"""Azure SDK wrapper providing typed accessors for all CSPM scan operations."""

import logging
from typing import Any, Dict, List, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient

logger = logging.getLogger(__name__)

# Azure built-in role definition GUIDs (subscription-scoped)
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"


class AzureClient:
    """Wraps Azure SDK management clients for all CSPM scan operations.

    Instantiate once per scan and share across all rule modules. Every method
    logs on failure and returns an empty list so individual rule failures never
    crash the scan engine.
    """

    def __init__(
        self, subscription_id: str, credential: Optional[Any] = None
    ) -> None:
        self.subscription_id = subscription_id
        self.credential = credential or DefaultAzureCredential()

    # ------------------------------------------------------------------ #
    # Static helpers                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def parse_resource_id(resource_id: str) -> Dict[str, str]:
        """Return resource_group and name parsed from an Azure resource ID."""
        parts = resource_id.split("/")
        result: Dict[str, str] = {"name": parts[-1] if parts else ""}
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

    def get_network_interface(
        self, resource_group: str, nic_name: str
    ) -> Optional[Any]:
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

    def get_sql_server_auditing_policy(
        self, resource_group: str, server_name: str
    ) -> Optional[Any]:
        """Fetch the blob auditing policy for an Azure SQL server."""
        try:
            client = SqlManagementClient(self.credential, self.subscription_id)
            return client.server_blob_auditing_policies.get(resource_group, server_name)
        except Exception as exc:
            logger.error(
                "get_sql_server_auditing_policy(%s) failed: %s", server_name, exc
            )
            return None

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

    # ------------------------------------------------------------------ #
    # Identity / Authorization                                              #
    # ------------------------------------------------------------------ #

    def get_service_principals(self) -> List[Any]:
        """Return role assignments whose principal type is ServicePrincipal."""
        try:
            client = AuthorizationManagementClient(
                self.credential, self.subscription_id
            )
            scope = f"/subscriptions/{self.subscription_id}"
            assignments = list(client.role_assignments.list_for_scope(scope))
            return [
                a
                for a in assignments
                if getattr(a, "principal_type", "") == "ServicePrincipal"
            ]
        except Exception as exc:
            logger.error("get_service_principals failed: %s", exc)
            return []

    def get_conditional_access_policies(self) -> List[Any]:
        """Fetch Conditional Access policies from the Microsoft Graph API.

        Requires the credential to have 'Policy.Read.All' Graph permission.
        Returns empty list if the permission is not granted or the call fails.
        """
        import requests  # imported here to keep azure-only paths dependency-free

        try:
            token = self.credential.get_token("https://graph.microsoft.com/.default")
            headers = {"Authorization": f"Bearer {token.token}"}
            response = requests.get(
                "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            return response.json().get("value", [])
        except Exception as exc:
            logger.error("get_conditional_access_policies failed: %s", exc)
            return []
