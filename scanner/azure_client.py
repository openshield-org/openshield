"""Azure SDK wrapper providing typed accessors for all CSPM scan operations."""

import logging
from typing import Any, Dict, List, Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.storage import StorageManagementClient


logger = logging.getLogger(__name__)

# Azure built-in role definition GUIDs (subscription-scoped)
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_UNSET = object()


def enum_str(value: Any, default: str = "") -> str:
    """Safely coerce an Azure SDK field to its plain string form.

    Azure SDK models often return fields typed as enums (e.g.
    SecurityRuleDirection, BlobAuditingPolicyState) rather than plain
    strings. ``str(enum_member)`` yields something like
    "SecurityRuleDirection.INBOUND", not the underlying value "Inbound",
    which breaks naive string comparisons. This prefers ``.value`` when
    present (covers real SDK enums and enum-like objects) and falls back
    to ``str()`` for plain strings, None, or anything else.
    """
    if value is None:
        return default
    return str(getattr(value, "value", value))


class AzureClient:
    """Wraps Azure SDK management clients for all CSPM scan operations.

    Instantiate once per scan and share across all rule modules. Every method
    logs on failure and returns an empty list so individual rule failures never
    crash the scan engine.
    """

    def __init__(self, subscription_id: str, credential: Optional[Any] = None) -> None:
        self.subscription_id = subscription_id
        self.credential = credential or DefaultAzureCredential()
        self._managed_clusters_cache: Any = _UNSET
        self._applications_cache: Any = _UNSET
        self._managed_identity_principals_cache: Any = _UNSET
        self._subscription_role_assignments_cache: Any = _UNSET
        self._container_registries_cache: Any = _UNSET
        self._disks_cache: Dict[str, Any] = {}
        self.devops_client = self._build_devops_client()

    def _build_devops_client(self) -> Optional[Any]:
        """Return a DevOpsClient if AZURE_DEVOPS_ORG_URL and AZURE_DEVOPS_PROJECT
        are configured, else None. Absence is a deliberate opt-out (not every
        subscription has an associated Azure DevOps organization), so rules
        that depend on this must treat None as "not configured, skip" rather
        than "unknown, indeterminate"."""
        import os

        org_url = os.environ.get("AZURE_DEVOPS_ORG_URL")
        project = os.environ.get("AZURE_DEVOPS_PROJECT")
        if not org_url or not project:
            return None

        from scanner.devops_client import DevOpsClient

        return DevOpsClient(org_url, project, credential=self.credential)

    # ------------------------------------------------------------------ #
    # Static helpers                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """Return resource_group and name parsed from an Azure resource ID.

        Always returns both keys, even for malformed or empty IDs, so
        callers can safely use parsed["resource_group"] without risking
        a KeyError.
        """
        parts = (resource_id or "").split("/")
        result: Dict[str, str] = {
            "name": parts[-1] if parts else "",
            "resource_group": "",
        }
        for idx, segment in enumerate(parts):
            if segment.lower() == "resourcegroups" and idx + 1 < len(parts):
                result["resource_group"] = parts[idx + 1]
        return result

    # ------------------------------------------------------------------ #
    # Storage                                                               #
    # ------------------------------------------------------------------ #

    def get_storage_accounts(self) -> List[Any]:
        """List all storage accounts in the subscription."""
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            return list(client.storage_accounts.list())
        except Exception as exc:
            logger.error("get_storage_accounts failed: %s", exc)
            return []

    def get_storage_lifecycle_policy(self, resource_group: str, account_name: str) -> Optional[bool]:
        """Check whether a storage account has a lifecycle management policy.

        Three-state return - the calling rule uses strict identity checks
        (is False / is None) to distinguish these states:

            True  - policy exists and contains at least one enabled rule.
            False - ResourceNotFoundError: no policy configured (non-compliant).
            None  - any other error (permissions, network, SDK bug).
                    Caller must NOT create a finding - skip with a warning
                    to avoid false positives.

        Args:
            resource_group: Resource group containing the storage account.
            account_name:   Name of the storage account.

        Returns:
            Optional[bool] - True, False, or None as described above.
        """
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            policy = client.management_policies.get(resource_group, account_name, "default")
            rules = getattr(getattr(policy, "policy", None), "rules", None)
            return bool(rules)

        except ResourceNotFoundError:
            logger.debug(
                "get_storage_lifecycle_policy(%s): ResourceNotFound - no policy",
                account_name,
            )
            return False

        except HttpResponseError as exc:
            logger.error(
                "get_storage_lifecycle_policy(%s) HTTP %s - check service principal permissions: %s",
                account_name,
                exc.status_code,
                exc,
            )
            return None

        except Exception as exc:
            logger.error(
                "get_storage_lifecycle_policy(%s) unexpected error: %s",
                account_name,
                exc,
            )
            return None

    def get_storage_service_logging(self, resource_group: str, account_name: str, service: str) -> Optional[bool]:
        """Check Azure Monitor diagnostic settings for a storage service sub-resource.

        Three-state return - the calling rule uses strict identity checks
        (is False / is None) to distinguish these states:

            True  - at least one diagnostic setting has StorageRead, StorageWrite,
                    and StorageDelete all enabled (compliant).
            False - no setting covers all three required categories (non-compliant).
            None  - permission error or unexpected SDK failure.
                    Caller must NOT create a finding - skip with a warning
                    to avoid false positives.

        Args:
            resource_group: Resource group containing the storage account.
            account_name:   Name of the storage account.
            service:        Sub-service to check: "blob", "queue", or "table".

        Returns:
            Optional[bool] - True, False, or None as described above.
        """
        _REQUIRED = {"StorageRead", "StorageWrite", "StorageDelete"}
        _SERVICE_MAP = {
            "blob": "blobServices",
            "queue": "queueServices",
            "table": "tableServices",
        }
        svc_path = _SERVICE_MAP.get(service)
        if not svc_path:
            logger.error(
                "get_storage_service_logging: unknown service %r - must be blob, queue, or table",
                service,
            )
            return None

        resource_uri = (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{resource_group}"
            f"/providers/Microsoft.Storage/storageAccounts/{account_name}"
            f"/{svc_path}/default"
        )
        try:
            client = MonitorManagementClient(self.credential, self.subscription_id)
            settings = list(client.diagnostic_settings.list(resource_uri))
            for setting in settings:
                enabled_categories = {
                    log.category for log in (getattr(setting, "logs", None) or []) if getattr(log, "enabled", False)
                }
                if _REQUIRED.issubset(enabled_categories):
                    return True
            return False

        except HttpResponseError as exc:
            logger.error(
                "get_storage_service_logging(%s/%s) HTTP %s - check service principal permissions: %s",
                account_name,
                service,
                exc.status_code,
                exc,
            )
            return None

        except Exception as exc:
            logger.error(
                "get_storage_service_logging(%s/%s) unexpected error: %s",
                account_name,
                service,
                exc,
            )
            return None

    # ------------------------------------------------------------------ #
    # Network                                                               #
    # ------------------------------------------------------------------ #

    def get_network_security_groups(self) -> List[Any]:
        """List all NSGs across all resource groups in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.network_security_groups.list_all())
        except Exception as exc:
            logger.error("get_network_security_groups failed: %s", exc)
            return []

    def get_network_interface(self, resource_group: str, nic_name: str) -> Optional[Any]:
        """Fetch a single NIC by resource group and name."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return client.network_interfaces.get(resource_group, nic_name)
        except Exception as exc:
            logger.error("get_network_interface(%s) failed: %s", nic_name, exc)
            return None

    def get_virtual_networks(self) -> List[Any]:
        """List all virtual networks in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_networks.list_all())
        except Exception as exc:
            logger.error("get_virtual_networks failed: %s", exc)
            return []

    def get_public_ip_addresses(self) -> List[Any]:
        """List all public IP addresses in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.public_ip_addresses.list_all())
        except Exception as exc:
            logger.error("get_public_ip_addresses failed: %s", exc)
            return []

    def get_azure_firewalls(self, resource_group: str) -> List[Any]:
        """List all Azure Firewalls in a resource group."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.azure_firewalls.list(resource_group))
        except Exception as exc:
            logger.error("get_azure_firewalls(%s) failed: %s", resource_group, exc)
            return []

    def get_all_azure_firewalls(self) -> Optional[List[Any]]:
        """List all Azure Firewalls in the subscription.

        Three-state return - the calling rule distinguishes these states:

            [...] - successful listing (may be empty: genuinely no firewalls).
            None  - listing failed (permissions, network, SDK error). The
                    caller must NOT flag VNets as non-compliant, since it
                    cannot tell which VNets are protected - skip to avoid
                    false positives.
        """
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.azure_firewalls.list_all())
        except Exception as exc:
            logger.error("get_all_azure_firewalls failed: %s", exc)
            return None

    def get_vnet_peerings(self, resource_group: str, vnet_name: str) -> List[Any]:
        """List all peering connections for a Virtual Network."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_network_peerings.list(resource_group, vnet_name))
        except Exception as exc:
            logger.error("get_vnet_peerings(%s) failed: %s", vnet_name, exc)
            return []

    def get_load_balancers(self) -> List[Any]:
        """List all load balancers in the subscription."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            return list(client.load_balancers.list_all())
        except Exception as exc:
            logger.error("get_load_balancers failed: %s", exc)
            return []

    def get_dns_zones(self) -> List[Any]:
        """List all DNS zones in the subscription."""
        try:
            from azure.mgmt.dns import DnsManagementClient

            client = DnsManagementClient(self.credential, self.subscription_id)
            return list(client.zones.list())
        except Exception as exc:
            logger.error("get_dns_zones failed: %s", exc)
            return []

    def get_dns_record_sets(self, resource_group: str, zone_name: str) -> List[Any]:
        """List all record sets in a DNS zone."""
        try:
            from azure.mgmt.dns import DnsManagementClient

            client = DnsManagementClient(self.credential, self.subscription_id)
            return list(client.record_sets.list_by_dns_zone(resource_group, zone_name))
        except Exception as exc:
            logger.error("get_dns_record_sets failed for zone %s: %s", zone_name, exc)
            return []

    # ------------------------------------------------------------------ #
    # Kubernetes / AKS                                                     #
    # ------------------------------------------------------------------ #

    def get_managed_clusters(self) -> Optional[List[Any]]:
        """List AKS managed clusters, preserving an indeterminate failure state.

        The result is cached for the lifetime of this client because every AKS
        rule evaluates the same subscription-level collection.

        Returns:
            A list (including an empty list) when Azure responds successfully,
            or ``None`` when permissions, networking, or the SDK prevent the
            collection from being evaluated. Callers must never interpret
            ``None`` as a compliant result.
        """
        if self._managed_clusters_cache is not _UNSET:
            return self._managed_clusters_cache

        try:
            client = ContainerServiceClient(self.credential, self.subscription_id)
            self._managed_clusters_cache = list(client.managed_clusters.list())
        except HttpResponseError as exc:
            logger.error(
                "get_managed_clusters HTTP %s - check Microsoft.ContainerService/managedClusters/read: %s",
                exc.status_code,
                exc,
            )
            self._managed_clusters_cache = None
        except Exception as exc:
            logger.error("get_managed_clusters failed: %s", exc)
            self._managed_clusters_cache = None

        return self._managed_clusters_cache

    # ------------------------------------------------------------------ #
    # Compute                                                               #
    # ------------------------------------------------------------------ #

    def get_virtual_machines(self) -> List[Any]:
        """List all VMs across all resource groups in the subscription."""
        try:
            client = ComputeManagementClient(self.credential, self.subscription_id)
            return list(client.virtual_machines.list_all())
        except Exception as exc:
            logger.error("get_virtual_machines failed: %s", exc)
            return []

    def get_web_apps(self) -> List[Any]:
        """List all App Services in the subscription."""
        try:
            from azure.mgmt.web import WebSiteManagementClient

            client = WebSiteManagementClient(self.credential, self.subscription_id)
            return list(client.web_apps.list())
        except Exception as exc:
            logger.error("get_web_apps failed: %s", exc)
            return []

    def get_vm_extensions(self, resource_group: str, vm_name: str) -> Optional[List[Any]]:
        """List all extensions installed on a virtual machine."""
        try:
            result = ComputeManagementClient(self.credential, self.subscription_id).virtual_machine_extensions.list(
                resource_group, vm_name
            )
            return list(getattr(result, "value", []) or [])
        except Exception as exc:
            logger.error("get_vm_extensions failed for %s/%s: %s", resource_group, vm_name, exc)
            return None

    def get_disk(self, disk_id: str) -> Optional[Any]:
        """Resolve the Disk resource referenced by a VM's ManagedDiskParameters.

        ManagedDiskParameters (the object embedded in a VM's storage_profile)
        only carries id, storage_account_type, disk_encryption_set and
        security_profile — the encryption state lives on the underlying Disk
        resource and must be fetched separately. Cached per subscription
        (this client instance already scopes one subscription) because the
        same disk may be evaluated more than once during a scan.

        Returns:
            The Disk resource, or ``None`` when the ID is missing/malformed
            or Azure cannot return it (permissions, deletion, SDK error).
            Callers must never interpret ``None`` as a compliant result.
        """
        if not disk_id:
            return None
        if disk_id in self._disks_cache:
            return self._disks_cache[disk_id]

        disk = None
        try:
            parsed = self.parse_resource_id(disk_id)
            resource_group = parsed.get("resource_group", "")
            disk_name = parsed.get("name", "")
            if resource_group and disk_name:
                client = ComputeManagementClient(self.credential, self.subscription_id)
                disk = client.disks.get(resource_group, disk_name)
            else:
                logger.error("get_disk failed: could not parse resource group/name from %s", disk_id)
        except Exception as exc:
            logger.error("get_disk failed for %s: %s", disk_id, exc)
            disk = None

        self._disks_cache[disk_id] = disk
        return disk

    # ------------------------------------------------------------------ #
    # Databases                                                             #
    # ------------------------------------------------------------------ #

    def get_postgresql_servers(self) -> List[Any]:
        """List all PostgreSQL single-server instances in the subscription."""
        try:
            client = PostgreSQLManagementClient(self.credential, self.subscription_id)
            return list(client.servers.list())
        except Exception as exc:
            logger.error("get_postgresql_servers failed: %s", exc)
            return []

    def get_sql_servers(self) -> List[Any]:
        """List all Azure SQL servers in the subscription."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return list(client.servers.list())
        except Exception as exc:
            logger.error("get_sql_servers failed: %s", exc)
            return []

    def get_sql_server_auditing_policy(self, resource_group: str, server_name: str) -> Optional[Any]:
        """Fetch the blob auditing policy for an Azure SQL server."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return client.server_blob_auditing_policies.get(resource_group, server_name)
        except Exception as exc:
            logger.error("get_sql_server_auditing_policy(%s) failed: %s", server_name, exc)
            return None

    def get_sql_server_firewall_rules(self, resource_group: str, server_name: str) -> List[Any]:
        """List all firewall rules for an Azure SQL server."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return list(client.firewall_rules.list_by_server(resource_group, server_name))
        except Exception as exc:
            logger.error("get_sql_server_firewall_rules(%s) failed: %s", server_name, exc)
            return []

    # ------------------------------------------------------------------ #
    # Key Vault                                                             #
    # ------------------------------------------------------------------ #

    def get_key_vaults(self) -> List[Any]:
        """List all Key Vaults in the subscription with full properties."""
        try:
            client = KeyVaultManagementClient(self.credential, self.subscription_id)
            return list(client.vaults.list_by_subscription())
        except Exception as exc:
            logger.error("get_key_vaults failed: %s", exc)
            return []

    def get_key_vault_certificates(self, vault_name: str) -> List[Any]:
        """List all certificates in a Key Vault using the Key Vault data plane API."""
        try:
            from azure.keyvault.certificates import CertificateClient

            vault_url = f"https://{vault_name}.vault.azure.net"
            client = CertificateClient(vault_url=vault_url, credential=self.credential)
            return list(client.list_properties_of_certificates())
        except Exception as exc:
            logger.error("get_key_vault_certificates(%s) failed: %s", vault_name, exc)
            return []

    def get_key_vault_keys(self, vault_name: str) -> List[Any]:
        """List all keys in a Key Vault using the Key Vault data plane API."""
        try:
            from azure.keyvault.keys import KeyClient

            vault_url = f"https://{vault_name}.vault.azure.net"
            client = KeyClient(vault_url=vault_url, credential=self.credential)
            return list(client.list_properties_of_keys())
        except Exception as exc:
            logger.error("get_key_vault_keys(%s) failed: %s", vault_name, exc)
            return []

    # ------------------------------------------------------------------ #
    # Monitoring                                                            #
    # ------------------------------------------------------------------ #

    def get_diagnostic_settings(self, resource_id: str) -> Optional[bool]:
        """Return diagnostic logging status for a resource.

        Three-state return:

            True  - at least one diagnostic log category is enabled.
            False - no diagnostic settings exist or all logs are disabled.
            None  - unable to determine status due to permissions/API failure.

        Returns:
            Optional[bool] - True, False, or None as described above.
        """
        try:
            client = MonitorManagementClient(
                self.credential,
                self.subscription_id,
            )
            settings = list(client.diagnostic_settings.list(resource_id))
            if not settings:
                return False
            for setting in settings:
                logs = getattr(setting, "logs", [])
                for log in logs:
                    category = getattr(log, "category", "")
                    enabled = getattr(log, "enabled", False)
                    if category == "AuditEvent" and enabled:
                        return True
            return False

        except HttpResponseError as exc:
            logger.error(
                "get_diagnostic_settings(%s) HTTP %s: %s",
                resource_id,
                exc.status_code,
                exc,
            )
            return None

        except Exception as exc:
            logger.error(
                "get_diagnostic_settings(%s) failed: %s",
                resource_id,
                exc,
            )
            return None

    # ------------------------------------------------------------------ #
    # Identity / Authorization                                              #
    # ------------------------------------------------------------------ #

    def _get_graph_collection(self, url: str, operation: str) -> Optional[List[Dict[str, Any]]]:
        """Fetch a paginated Microsoft Graph collection or return ``None`` on failure."""
        import requests

        items: List[Dict[str, Any]] = []
        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {
                "Authorization": f"Bearer {token.token}",
                "ConsistencyLevel": "eventual",
            }
            while url:
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink", "")
            return items
        except Exception as exc:
            logger.error("%s failed: %s", operation, exc)
            return None

    def get_applications(self) -> Optional[List[Dict[str, Any]]]:
        """Return cached App Registrations with security-relevant properties and owner IDs."""
        if self._applications_cache is _UNSET:
            select = (
                "id,displayName,appId,signInAudience,passwordCredentials,keyCredentials,"
                "web,spa,publicClient,servicePrincipalLockConfiguration"
            )
            url = f"https://graph.microsoft.com/v1.0/applications?$select={select}&$expand=owners($select=id)&$top=100"
            self._applications_cache = self._get_graph_collection(url, "get_applications")
        return self._applications_cache

    def get_managed_identity_service_principals(self) -> Optional[List[Dict[str, Any]]]:
        """Return cached Microsoft Entra service principals representing managed identities."""
        if self._managed_identity_principals_cache is _UNSET:
            url = (
                "https://graph.microsoft.com/v1.0/servicePrincipals"
                "?$filter=servicePrincipalType eq 'ManagedIdentity'"
                "&$select=id,displayName,servicePrincipalType&$count=true&$top=100"
            )
            self._managed_identity_principals_cache = self._get_graph_collection(
                url,
                "get_managed_identity_service_principals",
            )
        return self._managed_identity_principals_cache

    def get_subscription_role_assignments(self) -> Optional[List[Any]]:
        """Return cached subscription-scope RBAC assignments, preserving API failure as ``None``."""
        if self._subscription_role_assignments_cache is not _UNSET:
            return self._subscription_role_assignments_cache
        try:
            client = AuthorizationManagementClient(self.credential, self.subscription_id)
            scope = f"/subscriptions/{self.subscription_id}"
            self._subscription_role_assignments_cache = list(client.role_assignments.list_for_scope(scope))
        except Exception as exc:
            logger.error("get_subscription_role_assignments failed: %s", exc)
            self._subscription_role_assignments_cache = None
        return self._subscription_role_assignments_cache

    def get_service_principals(self) -> List[Any]:
        """Return role assignments whose principal type is ServicePrincipal."""
        assignments = self.get_subscription_role_assignments()
        if assignments is None:
            return []
        return [a for a in assignments if getattr(a, "principal_type", "") == "ServicePrincipal"]

    def get_postgresql_flexible_servers(self) -> List[Any]:
        """List all PostgreSQL Flexible Server instances in the subscription."""
        try:
            from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient as FlexClient

            client = FlexClient(self.credential, self.subscription_id)
            return list(client.servers.list())
        except Exception as exc:
            logger.error("get_postgresql_flexible_servers failed: %s", exc)
            return []

    def get_postgresql_flexible_server_parameters(self, resource_group: str, server_name: str) -> List[Any]:
        """List all configuration parameters for a PostgreSQL Flexible Server."""
        try:
            from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient as FlexClient

            client = FlexClient(self.credential, self.subscription_id)
            return list(client.configurations.list_by_server(resource_group, server_name))
        except Exception as exc:
            logger.error(
                "get_postgresql_flexible_server_parameters(%s) failed: %s",
                server_name,
                exc,
            )
            return []

    def get_conditional_access_policies(self) -> List[Any]:
        """Fetch Conditional Access policies from the Microsoft Graph API.

        Requires the credential to have 'Policy.Read.All' Graph permission.
        Follows '@odata.nextLink' until exhausted so tenants with enough
        policies to span multiple pages don't silently lose results from
        page 2 onward. Returns empty list if the permission is not granted
        or the call fails.
        """
        import requests  # imported here to keep azure-only paths dependency-free

        policies: List[Any] = []
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}

            while url:
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                data = response.json()
                policies.extend(data.get("value", []))
                url = data.get("@odata.nextLink")

            return policies
        except Exception as exc:
            logger.error("get_conditional_access_policies failed: %s", exc)
            return []

    def get_regions_with_resources(self) -> List[str]:
        """List all regions that have at least one resource deployed."""
        try:
            from azure.mgmt.resource import ResourceManagementClient

            client = ResourceManagementClient(self.credential, self.subscription_id)
            regions = {r.location.lower().replace(" ", "") for r in client.resources.list() if r.location}
            return list(regions)
        except Exception as exc:
            logger.error("get_regions_with_resources failed: %s", exc)
            return []

    def get_network_watcher_regions(self) -> List[str]:
        """List all regions that already have Network Watcher enabled."""
        try:
            client = NetworkManagementClient(self.credential, self.subscription_id)
            regions = {w.location.lower().replace(" ", "") for w in client.network_watchers.list_all() if w.location}
            return list(regions)
        except Exception as exc:
            logger.error("get_network_watcher_regions failed: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    # Supply chain: Container Registry, IaC state                          #
    # ------------------------------------------------------------------ #

    def get_container_registries(self) -> Optional[List[Any]]:
        """List Azure Container Registries, preserving an indeterminate failure state.

        Cached for the lifetime of this client because all AZ-SC container
        registry rules evaluate the same subscription-level collection.

        Returns:
            A list (including an empty list) when Azure responds successfully,
            or ``None`` when permissions, networking, or the SDK prevent the
            collection from being evaluated. Callers must never interpret
            ``None`` as a compliant result.
        """
        if self._container_registries_cache is not _UNSET:
            return self._container_registries_cache

        try:
            from azure.mgmt.containerregistry import ContainerRegistryManagementClient

            client = ContainerRegistryManagementClient(self.credential, self.subscription_id)
            self._container_registries_cache = list(client.registries.list())
        except Exception as exc:
            logger.error("get_container_registries failed: %s", exc)
            self._container_registries_cache = None
        return self._container_registries_cache

    def get_blob_containers(self, resource_group: str, account_name: str) -> Optional[List[Any]]:
        """List blob containers for a storage account, including per-container access level.

        Not cached: unlike the subscription-wide collections above, this is
        called once per storage account rather than once per scan.

        Returns:
            A list of container items, or ``None`` when the call fails
            (permissions, throttling, storage account not found).
        """
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            return list(client.blob_containers.list(resource_group, account_name))
        except Exception as exc:
            logger.error(
                "get_blob_containers(%s/%s) failed: %s",
                resource_group,
                account_name,
                exc,
            )
            return None

    def get_blob_service_properties(self, resource_group: str, account_name: str) -> Optional[Any]:
        """Return account-wide blob service properties (versioning, soft-delete retention).

        Not cached, for the same reason as get_blob_containers above.

        Returns:
            A BlobServiceProperties object, or ``None`` when the call fails.
        """
        try:
            client = StorageManagementClient(self.credential, self.subscription_id)
            return client.blob_services.get_service_properties(resource_group, account_name)
        except Exception as exc:
            logger.error(
                "get_blob_service_properties(%s/%s) failed: %s",
                resource_group,
                account_name,
                exc,
            )
            return None
