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
from typing import Any, Dict, List, Optional, Tuple


def make_resource(**kwargs: Any) -> SimpleNamespace:
    """Build a fake Azure resource object with arbitrary attributes."""
    return SimpleNamespace(**kwargs)


class _StubToken:
    """Minimal stand-in for an Azure AccessToken (has a ``.token`` attribute)."""

    def __init__(self, token: str = "fake-graph-token") -> None:
        self.token = token


class _StubCredential:
    """Minimal stand-in for a TokenCredential used by Graph/SDK-based rules.

    Rules that talk to Microsoft Graph or instantiate an Azure management
    client read ``azure_client.credential`` and call ``get_token(scope)``.
    Tests monkeypatch ``requests.get`` / the SDK client class separately, so
    this stub only needs to hand back an object exposing ``.token``.
    """

    def get_token(self, *scopes: Any, **kwargs: Any) -> _StubToken:
        return _StubToken()


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
        # --- Additional state added for full rule-coverage tests ---------- #
        self._network_interfaces: Dict[Tuple[str, str], Any] = {}
        self._vm_extensions: Dict[Tuple[str, str], Optional[List[Any]]] = {}
        self._storage_lifecycle: Dict[Tuple[str, str], Optional[bool]] = {}
        self._storage_logging: Dict[Tuple[str, str, str], Optional[bool]] = {}
        self._virtual_networks: List[Any] = []
        self._public_ip_addresses: List[Any] = []
        self._load_balancers: List[Any] = []
        self._all_azure_firewalls: Optional[List[Any]] = []
        self._vnet_peerings: Dict[Tuple[str, str], List[Any]] = {}
        self._postgresql_servers: List[Any] = []
        self._postgresql_flexible_servers: List[Any] = []
        self._pg_flex_parameters: Dict[Tuple[str, str], List[Any]] = {}
        self._sql_auditing: Dict[Tuple[str, str], Any] = {}
        self._sql_auditing_default: Any = None
        self._kv_certificates: Dict[str, List[Any]] = {}
        self._kv_keys: Dict[str, List[Any]] = {}
        self._diagnostic_settings: Dict[str, Optional[bool]] = {}
        self._diagnostic_default: Optional[bool] = False
        self._conditional_access_policies: List[Any] = []
        # Credential stub for Graph/SDK-based rules (idn_003..009).
        self.credential = _StubCredential()
        self._regions_with_resources: List[str] = []
        self._network_watcher_regions: List[str] = []
        self._nsg_flow_logs: Dict[str, List[Any]] = {}
        self._dns_zones: List[Any] = []
        self._dns_record_sets: Dict[Tuple[str, str], List[Any]] = {}
        self._web_apps: List[Any] = []
        self._managed_clusters: Optional[List[Any]] = []
        # Some rules read azure_client.subscription_id when constructing an
        # SDK management client inside scan() (e.g. AZ-NET-007..010).
        self.subscription_id = "00000000-0000-0000-0000-000000000001"

    def set_storage_accounts(self, accounts: List[Any]) -> "MockAzureClient":
        self._storage_accounts = accounts
        return self

    def set_managed_clusters(self, clusters: Optional[List[Any]]) -> "MockAzureClient":
        """Configure AKS inventory; ``None`` represents an API failure."""
        self._managed_clusters = clusters
        return self

    def get_managed_clusters(self) -> Optional[List[Any]]:
        return self._managed_clusters

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

    def get_sql_server_firewall_rules(self, resource_group: str, server_name: str) -> List[Any]:
        return self._sql_firewall_rules.get((resource_group, server_name), [])

    # ------------------------------------------------------------------ #
    # Compute — network interfaces & VM extensions                          #
    # ------------------------------------------------------------------ #

    def set_network_interface(self, resource_group: str, nic_name: str, nic: Any) -> "MockAzureClient":
        self._network_interfaces[(resource_group, nic_name)] = nic
        return self

    def get_network_interface(self, resource_group: str, nic_name: str) -> Optional[Any]:
        return self._network_interfaces.get((resource_group, nic_name))

    def set_vm_extensions(
        self, resource_group: str, vm_name: str, extensions: Optional[List[Any]]
    ) -> "MockAzureClient":
        self._vm_extensions[(resource_group, vm_name)] = extensions
        return self

    def get_vm_extensions(self, resource_group: str, vm_name: str) -> Optional[List[Any]]:
        # Default to an empty list (compliant-by-default) unless configured.
        return self._vm_extensions.get((resource_group, vm_name), [])

    # ------------------------------------------------------------------ #
    # Storage — lifecycle & service logging (three-state: True/False/None) #
    # ------------------------------------------------------------------ #

    def set_storage_lifecycle_policy(
        self, resource_group: str, account_name: str, value: Optional[bool]
    ) -> "MockAzureClient":
        self._storage_lifecycle[(resource_group, account_name)] = value
        return self

    def get_storage_lifecycle_policy(self, resource_group: str, account_name: str) -> Optional[bool]:
        return self._storage_lifecycle.get((resource_group, account_name))

    def set_storage_service_logging(
        self, resource_group: str, account_name: str, service: str, value: Optional[bool]
    ) -> "MockAzureClient":
        self._storage_logging[(resource_group, account_name, service)] = value
        return self

    def get_storage_service_logging(self, resource_group: str, account_name: str, service: str) -> Optional[bool]:
        return self._storage_logging.get((resource_group, account_name, service))

    # ------------------------------------------------------------------ #
    # Network — VNets, public IPs, firewalls, peerings, flow logs           #
    # ------------------------------------------------------------------ #

    def set_virtual_networks(self, vnets: List[Any]) -> "MockAzureClient":
        self._virtual_networks = vnets
        return self

    def get_virtual_networks(self) -> List[Any]:
        return self._virtual_networks

    def set_public_ip_addresses(self, ips: List[Any]) -> "MockAzureClient":
        self._public_ip_addresses = ips
        return self

    def get_public_ip_addresses(self) -> List[Any]:
        return self._public_ip_addresses

    def set_load_balancers(self, load_balancers: List[Any]) -> "MockAzureClient":
        self._load_balancers = load_balancers
        return self

    def get_load_balancers(self) -> List[Any]:
        return self._load_balancers

    def set_all_azure_firewalls(self, firewalls: Optional[List[Any]]) -> "MockAzureClient":
        self._all_azure_firewalls = firewalls
        return self

    def get_all_azure_firewalls(self) -> Optional[List[Any]]:
        return self._all_azure_firewalls

    def set_vnet_peerings(self, resource_group: str, vnet_name: str, peerings: List[Any]) -> "MockAzureClient":
        self._vnet_peerings[(resource_group, vnet_name)] = peerings
        return self

    def get_vnet_peerings(self, resource_group: str, vnet_name: str) -> List[Any]:
        return self._vnet_peerings.get((resource_group, vnet_name), [])

    def set_nsg_flow_logs(self, resource_group: str, flow_logs: List[Any]) -> "MockAzureClient":
        # NOTE: az_net_012 calls get_nsg_flow_logs(resource_group) with a single
        # argument and iterates the result. This mock matches that *expected*
        # contract so the rule's detection logic can be exercised. The real
        # AzureClient does not implement get_nsg_flow_logs at all — see the
        # validation report (AZ-NET-012 always false-positives in production).
        self._nsg_flow_logs[resource_group] = flow_logs
        return self

    def get_nsg_flow_logs(self, resource_group: str) -> List[Any]:
        return self._nsg_flow_logs.get(resource_group, [])

    def set_regions_with_resources(self, regions: List[str]) -> "MockAzureClient":
        self._regions_with_resources = regions
        return self

    def get_regions_with_resources(self) -> List[str]:
        return self._regions_with_resources

    def set_network_watcher_regions(self, regions: List[str]) -> "MockAzureClient":
        self._network_watcher_regions = regions
        return self

    def get_network_watcher_regions(self) -> List[str]:
        return self._network_watcher_regions

    def set_dns_zones(self, zones: List[Any]) -> "MockAzureClient":
        self._dns_zones = zones
        return self

    def get_dns_zones(self) -> List[Any]:
        return self._dns_zones

    def set_dns_record_sets(self, resource_group: str, zone_name: str, record_sets: List[Any]) -> "MockAzureClient":
        self._dns_record_sets[(resource_group, zone_name)] = record_sets
        return self

    def get_dns_record_sets(self, resource_group: str, zone_name: str) -> List[Any]:
        return self._dns_record_sets.get((resource_group, zone_name), [])

    # ------------------------------------------------------------------ #
    # Databases — PostgreSQL (single + flexible), SQL auditing               #
    # ------------------------------------------------------------------ #

    def set_postgresql_servers(self, servers: List[Any]) -> "MockAzureClient":
        self._postgresql_servers = servers
        return self

    def get_postgresql_servers(self) -> List[Any]:
        return self._postgresql_servers

    def set_postgresql_flexible_servers(self, servers: List[Any]) -> "MockAzureClient":
        self._postgresql_flexible_servers = servers
        return self

    def get_postgresql_flexible_servers(self) -> List[Any]:
        return self._postgresql_flexible_servers

    def set_postgresql_flexible_server_parameters(
        self, resource_group: str, server_name: str, parameters: List[Any]
    ) -> "MockAzureClient":
        self._pg_flex_parameters[(resource_group, server_name)] = parameters
        return self

    def get_postgresql_flexible_server_parameters(self, resource_group: str, server_name: str) -> List[Any]:
        return self._pg_flex_parameters.get((resource_group, server_name), [])

    def set_sql_server_auditing_policy(self, resource_group: str, server_name: str, policy: Any) -> "MockAzureClient":
        self._sql_auditing[(resource_group, server_name)] = policy
        return self

    def get_sql_server_auditing_policy(self, resource_group: str, server_name: str) -> Optional[Any]:
        return self._sql_auditing.get((resource_group, server_name), self._sql_auditing_default)

    # ------------------------------------------------------------------ #
    # Key Vault — certificates & keys (data plane)                          #
    # ------------------------------------------------------------------ #

    def set_key_vault_certificates(self, vault_name: str, certificates: List[Any]) -> "MockAzureClient":
        self._kv_certificates[vault_name] = certificates
        return self

    def get_key_vault_certificates(self, vault_name: str) -> List[Any]:
        return self._kv_certificates.get(vault_name, [])

    def set_key_vault_keys(self, vault_name: str, keys: List[Any]) -> "MockAzureClient":
        self._kv_keys[vault_name] = keys
        return self

    def get_key_vault_keys(self, vault_name: str) -> List[Any]:
        return self._kv_keys.get(vault_name, [])

    # ------------------------------------------------------------------ #
    # Monitoring & Identity                                                 #
    # ------------------------------------------------------------------ #

    def set_diagnostic_settings(self, resource_id: str, value: Optional[bool]) -> "MockAzureClient":
        self._diagnostic_settings[resource_id] = value
        return self

    def get_diagnostic_settings(self, resource_id: str) -> Optional[bool]:
        return self._diagnostic_settings.get(resource_id, self._diagnostic_default)

    def set_conditional_access_policies(self, policies: List[Any]) -> "MockAzureClient":
        self._conditional_access_policies = policies
        return self

    def get_conditional_access_policies(self) -> List[Any]:
        return self._conditional_access_policies

    def set_web_apps(self, apps: List[Any]) -> "MockAzureClient":
        self._web_apps = apps
        return self

    def get_web_apps(self) -> List[Any]:
        return self._web_apps

    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """Parse an Azure resource ID into a dict with name and resource_group."""
        parts = resource_id.split("/")
        result: Dict[str, str] = {"name": parts[-1] if parts else ""}
        for idx, segment in enumerate(parts):
            if segment.lower() == "resourcegroups" and idx + 1 < len(parts):
                result["resource_group"] = parts[idx + 1]
        return result
