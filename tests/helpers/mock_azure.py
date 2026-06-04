"""Shared MockAzureClient for rule regression tests.

Provides a configurable in-memory replacement for the real AzureClient so that
scanner rule unit tests can run fully offline with no Azure credentials.

Usage:
    from tests.helpers.mock_azure import MockAzureClient, make_resource

    client = MockAzureClient()
    client.set_storage_accounts([
        make_resource(id="/sub/rg/sa", name="mystorage", allow_blob_public_access=True)
    ])
    findings = az_stor_001.scan(client, "sub-id")
"""

from types import SimpleNamespace
from typing import Any, Dict, List, Tuple


def make_resource(**kwargs: Any) -> SimpleNamespace:
    """Build a fake Azure resource object with arbitrary attributes."""
    return SimpleNamespace(**kwargs)


class MockAzureClient:
    """Drop-in replacement for AzureClient that returns configured fake data."""

    def __init__(self) -> None:
        self._storage_accounts: List[Any] = []
        self._network_security_groups: List[Any] = []
        self._virtual_machines: List[Any] = []
        self._key_vaults: List[Any] = []
        self._sql_servers: List[Any] = []
        self._service_principals: List[Any] = []
        self._sql_firewall_rules: Dict[Tuple[str, str], List[Any]] = {}

    def set_storage_accounts(self, accounts: List[Any]) -> "MockAzureClient":
        self._storage_accounts = accounts
        return self

    def set_network_security_groups(self, nsgs: List[Any]) -> "MockAzureClient":
        self._network_security_groups = nsgs
        return self

    def set_virtual_machines(self, vms: List[Any]) -> "MockAzureClient":
        self._virtual_machines = vms
        return self

    def set_key_vaults(self, vaults: List[Any]) -> "MockAzureClient":
        self._key_vaults = vaults
        return self

    def set_sql_servers(self, servers: List[Any]) -> "MockAzureClient":
        self._sql_servers = servers
        return self

    def set_service_principals(self, principals: List[Any]) -> "MockAzureClient":
        self._service_principals = principals
        return self

    def set_sql_server_firewall_rules(
        self, resource_group: str, server_name: str, rules: List[Any]
    ) -> "MockAzureClient":
        self._sql_firewall_rules[(resource_group, server_name)] = rules
        return self

    def get_storage_accounts(self) -> List[Any]:
        return self._storage_accounts

    def get_network_security_groups(self) -> List[Any]:
        return self._network_security_groups

    def get_virtual_machines(self) -> List[Any]:
        return self._virtual_machines

    def get_key_vaults(self) -> List[Any]:
        return self._key_vaults

    def get_sql_servers(self) -> List[Any]:
        return self._sql_servers

    def get_service_principals(self) -> List[Any]:
        return self._service_principals

    def get_sql_server_firewall_rules(
        self, resource_group: str, server_name: str
    ) -> List[Any]:
        return self._sql_firewall_rules.get((resource_group, server_name), [])

    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """Parse an Azure resource ID into a dict with name and resource_group."""
        parts = resource_id.split("/")
        result: Dict[str, str] = {"name": parts[-1] if parts else ""}
        for idx, segment in enumerate(parts):
            if segment.lower() == "resourcegroups" and idx + 1 < len(parts):
                result["resource_group"] = parts[idx + 1]
        return result
