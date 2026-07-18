"""Direct tests for AzureClient management-plane wrappers and failure states."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from scanner.azure_client import AzureClient


@pytest.fixture
def client():
    return AzureClient("sub-1", credential=MagicMock())


def test_parse_resource_id_handles_full_and_short_ids():
    full = "/subscriptions/s/resourceGroups/RG/providers/Microsoft.Web/sites/app"
    assert AzureClient.parse_resource_id(full) == {"resource_group": "RG", "name": "app"}
    assert AzureClient.parse_resource_id("app") == {"name": "app", "resource_group": ""}


@pytest.mark.parametrize(
    ("method", "patch_target", "operation"),
    [
        ("get_storage_accounts", "scanner.azure_client.StorageManagementClient", "storage_accounts.list"),
        (
            "get_network_security_groups",
            "scanner.azure_client.NetworkManagementClient",
            "network_security_groups.list_all",
        ),
        ("get_virtual_networks", "scanner.azure_client.NetworkManagementClient", "virtual_networks.list_all"),
        ("get_public_ip_addresses", "scanner.azure_client.NetworkManagementClient", "public_ip_addresses.list_all"),
        ("get_load_balancers", "scanner.azure_client.NetworkManagementClient", "load_balancers.list_all"),
        ("get_virtual_machines", "scanner.azure_client.ComputeManagementClient", "virtual_machines.list_all"),
        ("get_postgresql_servers", "scanner.azure_client.PostgreSQLManagementClient", "servers.list"),
        ("get_sql_servers", "scanner.azure_client.SqlManagementClient", "servers.list"),
        ("get_key_vaults", "scanner.azure_client.KeyVaultManagementClient", "vaults.list_by_subscription"),
    ],
)
def test_list_wrappers_return_results_and_fail_closed(client, method, patch_target, operation):
    with patch(patch_target) as constructor:
        sdk = constructor.return_value
        target = sdk
        parts = operation.split(".")
        for part in parts[:-1]:
            target = getattr(target, part)
        call = getattr(target, parts[-1])
        call.return_value = [SimpleNamespace(name="one")]
        assert [item.name for item in getattr(client, method)()] == ["one"]

        call.side_effect = RuntimeError("Azure unavailable")
        assert getattr(client, method)() == []


def test_single_resource_and_policy_wrappers(client):
    with patch("scanner.azure_client.NetworkManagementClient") as constructor:
        constructor.return_value.network_interfaces.get.return_value = SimpleNamespace(name="nic")
        assert client.get_network_interface("rg", "nic").name == "nic"
        constructor.return_value.network_interfaces.get.side_effect = RuntimeError("denied")
        assert client.get_network_interface("rg", "nic") is None

    with patch("scanner.azure_client.SqlManagementClient") as constructor:
        policy = SimpleNamespace(state="Enabled")
        constructor.return_value.server_blob_auditing_policies.get.return_value = policy
        assert client.get_sql_server_auditing_policy("rg", "sql") is policy
        constructor.return_value.server_blob_auditing_policies.get.side_effect = RuntimeError("denied")
        assert client.get_sql_server_auditing_policy("rg", "sql") is None


def test_firewall_and_peering_wrappers(client):
    with patch("scanner.azure_client.NetworkManagementClient") as constructor:
        sdk = constructor.return_value
        sdk.azure_firewalls.list.return_value = [SimpleNamespace(name="fw")]
        sdk.azure_firewalls.list_all.return_value = [SimpleNamespace(name="fw-all")]
        sdk.virtual_network_peerings.list.return_value = [SimpleNamespace(name="peer")]

        assert client.get_azure_firewalls("rg")[0].name == "fw"
        assert client.get_all_azure_firewalls()[0].name == "fw-all"
        assert client.get_vnet_peerings("rg", "vnet")[0].name == "peer"

        sdk.azure_firewalls.list.side_effect = RuntimeError("denied")
        sdk.azure_firewalls.list_all.side_effect = RuntimeError("denied")
        sdk.virtual_network_peerings.list.side_effect = RuntimeError("denied")
        assert client.get_azure_firewalls("rg") == []
        assert client.get_all_azure_firewalls() is None
        assert client.get_vnet_peerings("rg", "vnet") == []


def test_vm_extensions_normalize_sdk_page_and_failure(client):
    with patch("scanner.azure_client.ComputeManagementClient") as constructor:
        constructor.return_value.virtual_machine_extensions.list.return_value = SimpleNamespace(
            value=[SimpleNamespace(name="agent")]
        )
        assert client.get_vm_extensions("rg", "vm")[0].name == "agent"
        constructor.return_value.virtual_machine_extensions.list.side_effect = RuntimeError("denied")
        assert client.get_vm_extensions("rg", "vm") is None
