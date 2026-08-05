"""Rule regression tests for the Supply Chain rules AZ-SC-001 .. AZ-SC-008."""

from types import SimpleNamespace

import scanner.rules.az_sc_001 as az_sc_001
import scanner.rules.az_sc_002 as az_sc_002
import scanner.rules.az_sc_003 as az_sc_003
import scanner.rules.az_sc_004 as az_sc_004
import scanner.rules.az_sc_005 as az_sc_005
import scanner.rules.az_sc_006 as az_sc_006
import scanner.rules.az_sc_007 as az_sc_007
import scanner.rules.az_sc_008 as az_sc_008
from tests.helpers.mock_azure import make_resource

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _acr_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.ContainerRegistry/registries/{name}"


def _sa_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Storage/storageAccounts/{name}"


def _make_registry(
    name, admin_enabled=False, public_access="Disabled", anonymous_pull=False, policies=None, sku_tier=None
):
    props = make_resource(
        admin_user_enabled=admin_enabled,
        public_network_access=public_access,
        anonymous_pull_enabled=anonymous_pull,
        policies=policies,
    )
    sku = make_resource(tier=sku_tier) if sku_tier is not None else None
    return make_resource(id=_acr_id(name), name=name, properties=props, sku=sku)


def _make_policies(retention_status="enabled", quarantine_status="enabled"):
    return make_resource(
        retention_policy=make_resource(status=retention_status),
        quarantine_policy=make_resource(status=quarantine_status),
    )


def _make_container(name, public_access="None"):
    return make_resource(name=name, container_properties=make_resource(public_access=public_access))


# ── AZ-SC-001: ACR admin user enabled ───────────────────────────────────────


def test_sc_001_admin_enabled_returns_finding(mock_azure, subscription_id):
    mock_azure.set_container_registries([_make_registry("acr1", admin_enabled=True)])
    findings = az_sc_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["category"] == "Supply Chain"


def test_sc_001_admin_disabled_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_container_registries([_make_registry("acr1", admin_enabled=False)])
    assert az_sc_001.scan(mock_azure, subscription_id) == []


def test_sc_001_inventory_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_container_registries(None)
    assert az_sc_001.scan(mock_azure, subscription_id) == []


# ── AZ-SC-002: ACR public network access ────────────────────────────────────


def test_sc_002_public_access_returns_finding(mock_azure, subscription_id):
    mock_azure.set_container_registries([_make_registry("acr1", public_access="Enabled")])
    findings = az_sc_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-002"


def test_sc_002_private_access_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_container_registries([_make_registry("acr1", public_access="Disabled")])
    assert az_sc_002.scan(mock_azure, subscription_id) == []


# ── AZ-SC-003: ACR anonymous pull ───────────────────────────────────────────


def test_sc_003_anonymous_pull_returns_finding(mock_azure, subscription_id):
    mock_azure.set_container_registries([_make_registry("acr1", anonymous_pull=True)])
    findings = az_sc_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-003"


def test_sc_003_anonymous_pull_disabled_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_container_registries([_make_registry("acr1", anonymous_pull=False)])
    assert az_sc_003.scan(mock_azure, subscription_id) == []


# ── AZ-SC-004: ACR missing retention/quarantine policy ──────────────────────


def test_sc_004_missing_retention_returns_finding(mock_azure, subscription_id):
    registry = _make_registry("acr1", policies=_make_policies(retention_status="disabled"))
    mock_azure.set_container_registries([registry])
    findings = az_sc_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-004"


def test_sc_004_basic_tier_missing_quarantine_is_compliant(mock_azure, subscription_id):
    """Quarantine is Premium-only; a Basic-tier registry must not be flagged for
    lacking a feature it cannot enable, as long as retention is configured."""
    registry = _make_registry(
        "acr1", sku_tier="Basic", policies=_make_policies(retention_status="enabled", quarantine_status="disabled")
    )
    mock_azure.set_container_registries([registry])
    assert az_sc_004.scan(mock_azure, subscription_id) == []


def test_sc_004_premium_tier_missing_quarantine_returns_finding(mock_azure, subscription_id):
    """On a Premium registry, quarantine is available, so lacking it must be flagged."""
    registry = _make_registry(
        "acr1",
        sku_tier="Premium",
        policies=_make_policies(retention_status="enabled", quarantine_status="disabled"),
    )
    mock_azure.set_container_registries([registry])
    findings = az_sc_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["quarantine_policy_enabled"] is False


def test_sc_004_premium_tier_both_policies_enabled_returns_no_findings(mock_azure, subscription_id):
    registry = _make_registry("acr1", sku_tier="Premium", policies=_make_policies())
    mock_azure.set_container_registries([registry])
    assert az_sc_004.scan(mock_azure, subscription_id) == []


def test_sc_004_missing_policies_object_returns_finding(mock_azure, subscription_id):
    """A registry with no `policies` block at all has no retention policy and must be flagged."""
    registry = _make_registry("acr1", policies=None)
    mock_azure.set_container_registries([registry])
    findings = az_sc_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1


# ── AZ-SC-005: Terraform state container publicly readable ─────────────────


def test_sc_005_public_tfstate_container_returns_finding(mock_azure, subscription_id):
    account = make_resource(id=_sa_id("sa1"), name="sa1")
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa1", [_make_container("tfstate-prod", public_access="Container")])
    findings = az_sc_005.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-005"
    assert findings[0]["severity"] == "CRITICAL"


def test_sc_005_private_tfstate_container_returns_no_findings(mock_azure, subscription_id):
    account = make_resource(id=_sa_id("sa1"), name="sa1")
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa1", [_make_container("tfstate-prod", public_access="None")])
    assert az_sc_005.scan(mock_azure, subscription_id) == []


def test_sc_005_non_tfstate_container_name_ignored(mock_azure, subscription_id):
    account = make_resource(id=_sa_id("sa1"), name="sa1")
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa1", [_make_container("app-uploads", public_access="Container")])
    assert az_sc_005.scan(mock_azure, subscription_id) == []


def test_sc_005_container_listing_failure_returns_no_findings(mock_azure, subscription_id):
    account = make_resource(id=_sa_id("sa1"), name="sa1")
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa1", None)
    assert az_sc_005.scan(mock_azure, subscription_id) == []


# ── AZ-SC-006: Terraform state account missing versioning/soft delete ──────


def test_sc_006_no_versioning_or_soft_delete_returns_finding(mock_azure, subscription_id):
    account = make_resource(id=_sa_id("sa1"), name="sa1")
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa1", [_make_container("terraform-state")])
    blob_service = make_resource(
        is_versioning_enabled=False,
        delete_retention_policy=make_resource(enabled=False),
    )
    mock_azure.set_blob_service_properties(_RG, "sa1", blob_service)
    findings = az_sc_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-006"


def test_sc_006_versioning_enabled_returns_no_findings(mock_azure, subscription_id):
    account = make_resource(id=_sa_id("sa1"), name="sa1")
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa1", [_make_container("terraform-state")])
    blob_service = make_resource(
        is_versioning_enabled=True,
        delete_retention_policy=make_resource(enabled=False),
    )
    mock_azure.set_blob_service_properties(_RG, "sa1", blob_service)
    assert az_sc_006.scan(mock_azure, subscription_id) == []


def test_sc_006_no_state_container_returns_no_findings(mock_azure, subscription_id):
    account = make_resource(id=_sa_id("sa1"), name="sa1")
    mock_azure.set_storage_accounts([account])
    mock_azure.set_blob_containers(_RG, "sa1", [_make_container("app-uploads")])
    assert az_sc_006.scan(mock_azure, subscription_id) == []


# ── AZ-SC-007 / AZ-SC-008: Azure DevOps service connections ────────────────


class _FakeDevOpsClient:
    def __init__(self, endpoints):
        self._endpoints = endpoints

    def get_service_endpoints(self):
        return self._endpoints


def _make_endpoint(name, scope_level="ResourceGroup", is_shared=False, scheme="WorkloadIdentityFederation"):
    return SimpleNamespace(
        id=f"endpoint-{name}",
        name=name,
        type="AzureRM",
        is_shared=is_shared,
        data={"scopeLevel": scope_level, "subscriptionId": _SUB},
        authorization=SimpleNamespace(scheme=scheme),
    )


def test_sc_007_subscription_scoped_returns_finding(mock_azure, subscription_id):
    mock_azure.devops_client = _FakeDevOpsClient([_make_endpoint("conn1", scope_level="Subscription")])
    findings = az_sc_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-007"


def test_sc_007_subscription_scoped_not_shared_still_returns_finding(mock_azure, subscription_id):
    """Scope is the risk, not cross-project sharing (is_shared) - a subscription-scoped
    connection is over-privileged whether or not it is shared with other projects."""
    mock_azure.devops_client = _FakeDevOpsClient([_make_endpoint("conn1", scope_level="Subscription", is_shared=False)])
    findings = az_sc_007.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_sc_007_resource_group_scoped_returns_no_findings(mock_azure, subscription_id):
    mock_azure.devops_client = _FakeDevOpsClient([_make_endpoint("conn1", scope_level="ResourceGroup")])
    assert az_sc_007.scan(mock_azure, subscription_id) == []


def test_sc_007_devops_not_configured_returns_no_findings(mock_azure, subscription_id):
    mock_azure.devops_client = None
    assert az_sc_007.scan(mock_azure, subscription_id) == []


def test_sc_007_endpoint_listing_failure_returns_no_findings(mock_azure, subscription_id):
    mock_azure.devops_client = _FakeDevOpsClient(None)
    assert az_sc_007.scan(mock_azure, subscription_id) == []


def test_sc_008_password_based_returns_finding(mock_azure, subscription_id):
    mock_azure.devops_client = _FakeDevOpsClient([_make_endpoint("conn1", scheme="ServicePrincipal")])
    findings = az_sc_008.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SC-008"


def test_sc_008_federated_returns_no_findings(mock_azure, subscription_id):
    mock_azure.devops_client = _FakeDevOpsClient([_make_endpoint("conn1", scheme="WorkloadIdentityFederation")])
    assert az_sc_008.scan(mock_azure, subscription_id) == []


def test_sc_008_managed_identity_returns_no_findings(mock_azure, subscription_id):
    """Managed identity is a second secretless scheme distinct from workload
    identity federation and must not be flagged as a stored-secret connection."""
    mock_azure.devops_client = _FakeDevOpsClient([_make_endpoint("conn1", scheme="ManagedServiceIdentity")])
    assert az_sc_008.scan(mock_azure, subscription_id) == []


def test_sc_008_devops_not_configured_returns_no_findings(mock_azure, subscription_id):
    mock_azure.devops_client = None
    assert az_sc_008.scan(mock_azure, subscription_id) == []
