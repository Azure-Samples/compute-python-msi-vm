---
services: virtual-machines
platforms: python
author: lmazuel
---

# Create a VM with MSI authentication enabled

This sample explains how to create a VM with Managed Service Identity enabled. This sample covers the two types of MSI scenarios:

- System Assigned Identity: the identity is created by ARM on VM creation
- User Assigned Identity: the identity is created and managed by the user, and assigned during VM creation

**On this page**

- [Run this sample](#run)
- [What is example.py doing?](#example)
    - [Preliminary operations](#preliminary-operations)
    - [Create a User Assigned Identity](#create-user-assigned)
    - [Create a VM with MSI creation](#create-vm)
    - [Role assignement to the MSI credentials](#role-assignment)
    - [Install MSI extension](#extension)
    - [Usage](#usage)
    - [Delete a resource group](#delete-group)

<a id="run"></a>
## Run this sample

1. If you don't already have it, [install Python](https://www.python.org/downloads/).

1. We recommend to use a [virtual environnement](https://docs.python.org/3/tutorial/venv.html) to run this example, but it's not mandatory. You can initialize a virtualenv this way:

    ```
    pip install virtualenv
    virtualenv mytestenv
    cd mytestenv
    source bin/activate
    ```

1. Clone the repository.

    ```
    git clone https://github.com/Azure-Samples/compute-python-msi-vm.git
    ```

1. Install the dependencies using pip.

    ```
    cd compute-python-msi-vm
    pip install -r requirements.txt
    ```

1. Create an Azure service principal either through
[Azure CLI](https://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/),
[PowerShell](https://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal/)
or [the portal](https://azure.microsoft.com/documentation/articles/resource-group-create-service-principal-portal/).

   Important note: to be able to run this sample, your Service Principal MUST have
   "Owner" role enabled, or at least the "Microsoft.Authorization/*/write" permission.
   Learn more about [Built-in Role for Azure](https://docs.microsoft.com/azure/active-directory/role-based-access-built-in-roles)

1. Export these environment variables into your current shell. 

    ```
    export AZURE_TENANT_ID={your tenant id}
    export AZURE_CLIENT_ID={your client id}
    export AZURE_CLIENT_SECRET={your client secret}
    export AZURE_SUBSCRIPTION_ID={your subscription id}
    ```

1. Run the sample.

    ```
    python example.py
    ```

<a id="example"></a>
## What is example.py doing?

The sample creates a VM with MSI creation. Then assign permission to that token. Finally
it installs the VM extension necessary to get this token from inside the VM.
It starts by setting up several clients using your subscription and credentials.

```python
import os
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

subscription_id = os.environ.get(
    'AZURE_SUBSCRIPTION_ID',
    '11111111-1111-1111-1111-111111111111') # your Azure Subscription Id
credentials = ServicePrincipalCredentials(
    client_id=os.environ['AZURE_CLIENT_ID'],
    secret=os.environ['AZURE_CLIENT_SECRET'],
    tenant=os.environ['AZURE_TENANT_ID']
)
resource_client = ResourceManagementClient(credentials, subscription_id)
compute_client = ComputeManagementClient(credentials, subscription_id)
network_client = NetworkManagementClient(credentials, subscription_id)
authorization_client = AuthorizationManagementClient(credentials, subscription_id)
```

There are a couple of supporting functions (`print_item` and `print_properties`) that print a resource group and it's properties.

<a id="preliminary-operations"></a>
### Preliminary operations

This example setup some preliminary components that are no the topic of this sample and do not differ
from regular scenarios:

- A Resource Group
- A Virtual Network
- A Subnet
- A Public IP
- A Network Interface

For details about creation of these components, you can refer to the generic samples:

- [Resource Group](https://github.com/Azure-Samples/resource-manager-python-resources-and-groups)
- [Network and VM](https://github.com/Azure-Samples/virtual-machines-python-manage)

<a id="create-user-assigned"></a>
### Create a User Assigned Identity

> You do NOT require this step if you just want to use System Assigned Identity.

Creating a User Assigned identity is simple:

```python
user_assigned_identity = msi_client.user_assigned_identities.create_or_update(
    GROUP_NAME,
    "myMsiIdentity", # Any name, just a human readable ID
    LOCATION
)
```

<a id="create-vm"></a>
### Create a VM with MSI creation

You can create a VM with both User Assigned and System Assigned at the same time, or only one of them.
In System Assigned, only one attribute is necessary to ask Azure to create a MSI id.
In User Assigned, you just need to provide the ID of the User Assigned identity you just created:

```python
params_identity = {}
if USER_ASSIGNED_IDENTITY and SYSTEM_ASSIGNED_IDENTITY:
    params_identity['type'] = ResourceIdentityType.system_assigned_user_assigned # Enum value for both
    params_identity['identity_ids'] = [
        user_assigned_identity.id
    ]
elif USER_ASSIGNED_IDENTITY: # User Assigned only
    params_identity['type'] = ResourceIdentityType.user_assigned
    params_identity['identity_ids'] = [
        user_assigned_identity.id
    ]
elif SYSTEM_ASSIGNED_IDENTITY: # System assigned only
    params_identity['type'] = ResourceIdentityType.system_assigned

params_create = {
    'location': LOCATION,
    'os_profile': get_os_profile(),
    'hardware_profile': get_hardware_profile(),
    'network_profile': get_network_profile(nic.id),
    'storage_profile': get_storage_profile(),
    # Activate MSI on that VM
    'identity': params_identity
}

vm_poller = compute_client.virtual_machines.create_or_update(
    GROUP_NAME,
    VM_NAME,
    params_create,
)
vm_result = vm_poller.result()
```

<a id="role-assignment"></a>
### Role assignement to the MSI credentials

By default, MSI identities does not have
any permissions and will be unable to do anything.

This section shows how to get the role id of the built-in role "Contributor"
and to assign it with the scope "Resource Group" to a MSI identity.

```python
msi_accounts_to_assign = []
if SYSTEM_ASSIGNED_IDENTITY:
    msi_accounts_to_assign.append(vm_result.identity.principal_id)
if USER_ASSIGNED_IDENTITY:
    msi_accounts_to_assign.append(user_assigned_identity.principal_id)

# Get "Contributor" built-in role as a RoleDefinition object
role_name = 'Contributor'
roles = list(authorization_client.role_definitions.list(
    resource_group.id,
    filter="roleName eq '{}'".format(role_name)
))
assert len(roles) == 1
contributor_role = roles[0]

# Add RG scope to the MSI token
for msi_identity in msi_accounts_to_assign:

    role_assignment = authorization_client.role_assignments.create(
        resource_group.id,
        uuid.uuid4(), # Role assignment random name
        {
            'role_definition_id': contributor_role.id,
            'principal_id': msi_identity
        }
    )
```

<a id="extension"></a>
### Install MSI extension

A VM extension is needed to be able to get the token from inside the VM.
This extension is just a simple localhost server on port 50342 that returns the token.

> For User Assigned, extension needs to be at least version 1.0.7

```python
ext_type_name = 'ManagedIdentityExtensionForLinux'
ext_name = vm_result.name + ext_type_name
params_create = {
    'location': LOCATION,
    'publisher': 'Microsoft.ManagedIdentity',
    'virtual_machine_extension_type': ext_type_name,
    'type_handler_version': '1.0',
    'auto_upgrade_minor_version': True,
    'settings': {'port': 50342}, # Default port. You should NOT change it.
}
ext_poller = compute_client.virtual_machine_extensions.create_or_update(
    GROUP_NAME,
    vm_result.name,
    ext_name,
    params_create,
)
ext = ext_poller.result()
```

<a id="usage"></a>
### Usage

You can now connect to the VM and use the MSI credentials directly, without
passing credentials to the VM.

More details on how to use MSI with SDK can be found in the 
[MSI usage sample](https://github.com/Azure-Samples/resource-manager-python-manage-resources-with-msi)

Once the Azure VM has been created, you can verify that MSI extension is running on this VM. Managed Service Identity extension will run on 
`localhost` and configured port, here `50342`.

```
notAdmin@msi-vm:~$ netstat -tlnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:50342         0.0.0.0:*               LISTEN      -               
...            

```

<a id="delete-group"></a>
### Delete a resource group

```python
delete_async_operation = client.resource_groups.delete('azure-msi-sample-group')
delete_async_operation.wait()
```
