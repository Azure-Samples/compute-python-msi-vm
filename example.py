import os
import uuid

from azure.common.credentials import ServicePrincipalCredentials

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

from azure.mgmt.compute.models import ResourceIdentityType

# Resource

LOCATION = 'westus'
GROUP_NAME = 'azure-msi-sample-group'

# Network

VNET_NAME = 'azure-sample-vnet'
SUBNET_NAME = 'azure-sample-subnet'
PUBLIC_IP_NAME = 'azure-sample-pip'
NIC_NAME = 'azure-sample-nic'
IP_CONFIG_NAME = 'azure-sample-ip-config'

# VM

VM_NAME = 'azuretestmsi'
ADMIN_LOGIN = 'Foo12'
ADMIN_PASSWORD = 'BaR@123' + GROUP_NAME


# Create a Linux VM with MSI enabled. The MSI token will have Contributor role within
# the Resource Group of the VM.
#
# Important: to execute this sample, your Service Principal credential needs the
# "Owner" role, or at least the "Microsoft.Authorization/*/write" permission.
#
# This script expects that the following environment vars are set:
#
# AZURE_TENANT_ID: with your Azure Active Directory tenant id or domain
# AZURE_CLIENT_ID: with your Azure Active Directory Application Client ID
# AZURE_CLIENT_SECRET: with your Azure Active Directory Application Secret
# AZURE_SUBSCRIPTION_ID: with your Azure Subscription Id
#
def run_example():
    """Resource Group management example."""
    #
    # Create the Resource Manager Client with an Application (service principal) token provider
    #
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

    # Create Resource group
    print('\nCreate Resource Group')
    resource_group = resource_client.resource_groups.create_or_update(
        GROUP_NAME,
        {'location': LOCATION}
    )
    print_item(resource_group)

    print("\nCreate Network")
    # Create Network components of the VM
    # This is not MSI related and is just required to create the VM
    subnet = create_virtual_network(network_client)
    public_ip = create_public_ip(network_client)
    nic = create_network_interface(network_client, subnet, public_ip)
    print_item(nic)

    # Create a VM MSI enabled
    params_create = {
        'location': LOCATION,
        'os_profile': get_os_profile(),
        'hardware_profile': get_hardware_profile(),
        'network_profile': get_network_profile(nic.id),
        'storage_profile': get_storage_profile(),
        # Activate MSI on that VM
        'identity': {
            'type': ResourceIdentityType.system_assigned
        }
    }

    print("\nCreate VM")
    vm_poller = compute_client.virtual_machines.create_or_update(
        GROUP_NAME,
        VM_NAME,
        params_create,
    )
    vm_result = vm_poller.result()
    print_item(vm_result)

    # Get the PublicIP after VM creation, since assignment is dynamic
    public_ip = network_client.public_ip_addresses.get(
        GROUP_NAME,
        PUBLIC_IP_NAME
    )

    # By default, the MSI account has no permissions
    # Next part is assignment of permissions to the account
    # Example is Resource Group access as Contributor, but
    # you can any permissions you need.

    print("\nAssign permissions to MSI account")
    # Get the Principal id of that VM
    msi_principal_id = vm_result.identity.principal_id

    # Get "Contributor" built-in role as a RoleDefinition object
    role_name = 'Contributor'
    roles = list(authorization_client.role_definitions.list(
        resource_group.id,
        filter="roleName eq '{}'".format(role_name)
    ))
    assert len(roles) == 1
    contributor_role = roles[0]

    # Add RG scope to the MSI token
    role_assignment = authorization_client.role_assignments.create(
        resource_group.id,
        uuid.uuid4(), # Role assignment random name
        {
            'role_definition_id': contributor_role.id,
            'principal_id': msi_principal_id
        }
    )
    print_item(role_assignment)

    # To be able to get the token from inside the VM, there is
    # a service on port 50342. This service is installed by an
    # extension

    print("\nInstall MSI extension on VM")

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
    print_item(ext)

    print("You can connect to the VM using:")
    print("ssh {}@{}".format(
        ADMIN_LOGIN,
        public_ip.ip_address,
    ))
    print("And password: {}\n".format(ADMIN_PASSWORD))

    input("Press enter to delete this Resource Group.")

    # Delete Resource group and everything in it
    print('Delete Resource Group')
    delete_async_operation = resource_client.resource_groups.delete(GROUP_NAME)
    delete_async_operation.wait()
    print("\nDeleted: {}".format(GROUP_NAME))

def print_item(group):
    """Print a ResourceGroup instance."""
    print("\tName: {}".format(group.name))
    print("\tId: {}".format(group.id))
    if hasattr(group, 'location'):
        print("\tLocation: {}".format(group.location))
    print_properties(getattr(group, 'properties', None))

def print_properties(props):
    """Print a ResourceGroup propertyies instance."""
    if props and hasattr(props, 'provisioning_state'):
        print("\tProperties:")
        print("\t\tProvisioning State: {}".format(props.provisioning_state))
    print("\n\n")

###### Network creation, not specific to MSI scenario ######

def create_virtual_network(network_client):
    params_create = {
        'location': LOCATION,
        'address_space': {
            'address_prefixes': ['10.0.0.0/16'],
        },
        'subnets': [{
            'name': SUBNET_NAME,
            'address_prefix': '10.0.0.0/24',
        }],
    }
    vnet_poller = network_client.virtual_networks.create_or_update(
        GROUP_NAME,
        VNET_NAME,
        params_create,
    )
    vnet_poller.wait()

    return network_client.subnets.get(
        GROUP_NAME,
        VNET_NAME,
        SUBNET_NAME,
    )

def create_public_ip(network_client):
    params_create = {
        'location': LOCATION,
        'public_ip_allocation_method': 'dynamic',
    }
    pip_poller = network_client.public_ip_addresses.create_or_update(
        GROUP_NAME,
        PUBLIC_IP_NAME,
        params_create,
    )
    return pip_poller.result()

def create_network_interface(network_client, subnet, public_ip):
    params_create = {
        'location': LOCATION,
        'ip_configurations': [{
            'name': IP_CONFIG_NAME,
            'private_ip_allocation_method': "Dynamic",
            'subnet': subnet,
            'public_ip_address': {
                'id': public_ip.id
            }
        }]
    }
    nic_poller = network_client.network_interfaces.create_or_update(
        GROUP_NAME,
        NIC_NAME,
        params_create,
    )
    return nic_poller.result()

###### VM creation, not specific to MSI scenario ######

def get_os_profile():
    return {
        'admin_username': ADMIN_LOGIN,
        'admin_password': ADMIN_PASSWORD,
        'computer_name': 'testmsi',
    }

def get_hardware_profile():
    return {
        'vm_size': 'standard_a0'
    }

def get_network_profile(network_interface_id):
    return {
        'network_interfaces': [{
            'id': network_interface_id,
        }],
    }

def get_storage_profile():
    return {
        'image_reference': {
            'publisher': 'Canonical',
            'offer': 'UbuntuServer',
            'sku': '16.04.0-LTS',
            'version': 'latest'
        }
    }

if __name__ == "__main__":
    run_example()
