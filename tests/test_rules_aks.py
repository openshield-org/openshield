"""Unit tests for the AZ-AKS-001 through AZ-AKS-006 rule pack."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from scanner.rules import az_aks_001, az_aks_002, az_aks_003, az_aks_004, az_aks_005, az_aks_006


def ns(**kwargs):
    return SimpleNamespace(**kwargs)


def cluster(**overrides):
    values = {
        "id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-1",
        "name": "aks-1",
        "api_server_access_profile": ns(enable_private_cluster=True),
        "disable_local_accounts": True,
        "identity": ns(type="SystemAssigned"),
        "oidc_issuer_profile": ns(enabled=True),
        "security_profile": ns(workload_identity=ns(enabled=True)),
        "addon_profiles": {"azurepolicy": ns(enabled=True)},
        "auto_upgrade_profile": ns(node_os_upgrade_channel="SecurityPatch"),
    }
    values.update(overrides)
    return ns(**values)


RULES = [az_aks_001, az_aks_002, az_aks_003, az_aks_004, az_aks_005, az_aks_006]


@pytest.mark.parametrize("rule", RULES)
def test_compliant_cluster_returns_no_findings(rule):
    client = MagicMock()
    client.get_managed_clusters.return_value = [cluster()]

    assert rule.scan(client, "sub-1") == []


@pytest.mark.parametrize(
    ("rule", "override", "metadata_key"),
    [
        (az_aks_001, {"api_server_access_profile": ns(enable_private_cluster=False)}, "private_cluster_enabled"),
        (az_aks_002, {"disable_local_accounts": False}, "local_accounts_disabled"),
        (az_aks_003, {"identity": None}, "identity_type"),
        (
            az_aks_004,
            {"oidc_issuer_profile": ns(enabled=False)},
            "oidc_issuer_enabled",
        ),
        (az_aks_005, {"addon_profiles": {}}, "azure_policy_enabled"),
        (az_aks_006, {"auto_upgrade_profile": ns(node_os_upgrade_channel="None")}, "node_os_upgrade_channel"),
    ],
)
def test_non_compliant_cluster_returns_standard_finding(rule, override, metadata_key):
    client = MagicMock()
    client.get_managed_clusters.return_value = [cluster(**override)]

    findings = rule.scan(client, "sub-1")

    assert len(findings) == 1
    result = findings[0]
    assert result["rule_id"] == rule.RULE_ID
    assert result["resource_name"] == "aks-1"
    assert result["resource_type"] == "Microsoft.ContainerService/managedClusters"
    assert result["playbook"] == rule.PLAYBOOK
    assert metadata_key in result["metadata"]


@pytest.mark.parametrize("rule", RULES)
def test_inventory_failure_never_creates_false_finding(rule):
    client = MagicMock()
    client.get_managed_clusters.return_value = None

    assert rule.scan(client, "sub-1") == []


@pytest.mark.parametrize("rule", RULES)
def test_invalid_resource_identity_is_skipped(rule):
    client = MagicMock()
    client.get_managed_clusters.return_value = [cluster(id="")]

    assert rule.scan(client, "sub-1") == []


def test_unknown_private_cluster_state_is_skipped():
    client = MagicMock()
    client.get_managed_clusters.return_value = [cluster(api_server_access_profile=None)]

    assert az_aks_001.scan(client, "sub-1") == []


def test_unknown_local_account_state_is_skipped():
    client = MagicMock()
    client.get_managed_clusters.return_value = [cluster(disable_local_accounts=None)]

    assert az_aks_002.scan(client, "sub-1") == []


def test_current_sdk_nested_properties_are_supported():
    current_model_cluster = ns(
        id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-2",
        name="aks-2",
        identity=ns(type="SystemAssigned"),
        properties=ns(
            api_server_access_profile=ns(enable_private_cluster=False),
            disable_local_accounts=False,
            oidc_issuer_profile=ns(enabled=False),
            security_profile=ns(workload_identity=ns(enabled=False)),
            addon_profiles={},
            auto_upgrade_profile=ns(node_os_upgrade_channel="None"),
        ),
    )
    client = MagicMock()
    client.get_managed_clusters.return_value = [current_model_cluster]

    assert [len(rule.scan(client, "sub-1")) for rule in RULES] == [1, 1, 0, 1, 1, 1]


def test_multiple_clusters_are_evaluated_independently():
    client = MagicMock()
    client.get_managed_clusters.return_value = [
        cluster(),
        cluster(
            id="/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks-2",
            name="aks-2",
            disable_local_accounts=False,
        ),
    ]

    findings = az_aks_002.scan(client, "sub-1")

    assert [item["resource_name"] for item in findings] == ["aks-2"]


@pytest.mark.parametrize("identity_type", ["SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"])
def test_supported_managed_identity_types_are_compliant(identity_type):
    client = MagicMock()
    client.get_managed_clusters.return_value = [cluster(identity=ns(type=identity_type))]

    assert az_aks_003.scan(client, "sub-1") == []


@pytest.mark.parametrize("channel", ["SecurityPatch", "NodeImage", "securitypatch", "nodeimage"])
def test_managed_node_os_channels_are_compliant(channel):
    client = MagicMock()
    client.get_managed_clusters.return_value = [cluster(auto_upgrade_profile=ns(node_os_upgrade_channel=channel))]

    assert az_aks_006.scan(client, "sub-1") == []
