"""Tests for enterprise identity rules AZ-IDN-010 through AZ-IDN-015."""

from types import SimpleNamespace

import pytest

from scanner.rules import az_idn_010, az_idn_011, az_idn_012, az_idn_013, az_idn_014, az_idn_015


def app(**overrides):
    values = {
        "id": "app-object-1",
        "displayName": "Enterprise App",
        "appId": "client-id-1",
        "owners": [{"id": "owner-1"}],
        "signInAudience": "AzureADMyOrg",
        "passwordCredentials": [],
        "keyCredentials": [],
        "web": {"redirectUris": ["https://app.example/callback"], "implicitGrantSettings": {}},
        "spa": {"redirectUris": []},
        "publicClient": {"redirectUris": []},
        "servicePrincipalLockConfiguration": None,
    }
    values.update(overrides)
    return values


APP_RULES = [az_idn_010, az_idn_011, az_idn_012, az_idn_013, az_idn_014]


@pytest.mark.parametrize("rule", APP_RULES)
def test_compliant_application_returns_no_findings(rule, mock_azure, subscription_id):
    mock_azure.set_applications([app()])
    assert rule.scan(mock_azure, subscription_id) == []


@pytest.mark.parametrize("rule", APP_RULES)
def test_application_inventory_failure_returns_no_findings(rule, mock_azure, subscription_id):
    mock_azure.set_applications(None)
    assert rule.scan(mock_azure, subscription_id) == []


@pytest.mark.parametrize("rule", APP_RULES)
def test_application_without_object_id_is_skipped(rule, mock_azure, subscription_id):
    mock_azure.set_applications([app(id="")])
    assert rule.scan(mock_azure, subscription_id) == []


def test_idn_010_unowned_application_returns_finding(mock_azure, subscription_id):
    mock_azure.set_applications([app(owners=[])])
    findings = az_idn_010.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"] == {"owner_count": 0}


def test_idn_010_missing_expanded_owner_state_is_unknown(mock_azure, subscription_id):
    application = app()
    application.pop("owners")
    mock_azure.set_applications([application])
    assert az_idn_010.scan(mock_azure, subscription_id) == []


@pytest.mark.parametrize(
    "uri",
    [
        "http://app.example/callback",
        "http://10.1.2.3/callback",
        "http://example.com/callback",
    ],
)
def test_idn_011_non_loopback_http_redirect_returns_finding(uri, mock_azure, subscription_id):
    mock_azure.set_applications([app(web={"redirectUris": [uri], "implicitGrantSettings": {}})])
    findings = az_idn_011.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["insecure_redirect_count"] == 1
    assert uri not in str(findings[0]["metadata"])


@pytest.mark.parametrize(
    "uri",
    [
        "http://localhost/callback",
        "http://127.0.0.1:8080/callback",
        "http://[::1]/callback",
        "https://app.example/callback",
        "msalclient-id://auth",
    ],
)
def test_idn_011_secure_or_native_redirect_is_allowed(uri, mock_azure, subscription_id):
    mock_azure.set_applications([app(web={"redirectUris": [uri], "implicitGrantSettings": {}})])
    assert az_idn_011.scan(mock_azure, subscription_id) == []


def test_idn_012_implicit_access_token_returns_finding(mock_azure, subscription_id):
    web = {"redirectUris": [], "implicitGrantSettings": {"enableAccessTokenIssuance": True}}
    mock_azure.set_applications([app(web=web)])
    findings = az_idn_012.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["access_token_issuance"] is True


def test_idn_013_password_credential_returns_finding_without_identifiers(mock_azure, subscription_id):
    credential = {"keyId": "must-not-leak", "hint": "xy", "displayName": "prod-secret"}
    mock_azure.set_applications([app(passwordCredentials=[credential])])
    findings = az_idn_013.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["password_credential_count"] == 1
    assert "must-not-leak" not in str(findings[0])


def test_idn_014_multitenant_without_lock_returns_finding(mock_azure, subscription_id):
    mock_azure.set_applications([app(signInAudience="AzureADMultipleOrgs")])
    findings = az_idn_014.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["metadata"]["lock_enabled"] is False


def test_idn_014_multitenant_full_lock_is_compliant(mock_azure, subscription_id):
    lock = {"isEnabled": True, "allProperties": True}
    mock_azure.set_applications([app(signInAudience="AzureADMultipleOrgs", servicePrincipalLockConfiguration=lock)])
    assert az_idn_014.scan(mock_azure, subscription_id) == []


def assignment(role_guid, principal_id="mi-1", scope="/subscriptions/sub-id"):
    return SimpleNamespace(
        id="/subscriptions/sub-id/providers/Microsoft.Authorization/roleAssignments/assignment-1",
        principal_id=principal_id,
        role_definition_id=f"/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/{role_guid}",
        scope=scope,
    )


@pytest.mark.parametrize("role_guid", [az_idn_015.OWNER_ROLE_GUID, az_idn_015.CONTRIBUTOR_ROLE_GUID])
def test_idn_015_privileged_managed_identity_returns_finding(role_guid, mock_azure, subscription_id):
    mock_azure.set_managed_identity_service_principals([{"id": "mi-1", "displayName": "payments-mi"}])
    mock_azure.set_subscription_role_assignments([assignment(role_guid, scope=f"/subscriptions/{subscription_id}")])
    findings = az_idn_015.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["resource_name"] == "payments-mi"


def test_idn_015_resource_group_scope_is_compliant(mock_azure, subscription_id):
    mock_azure.set_managed_identity_service_principals([{"id": "mi-1", "displayName": "payments-mi"}])
    mock_azure.set_subscription_role_assignments(
        [assignment(az_idn_015.CONTRIBUTOR_ROLE_GUID, scope=f"/subscriptions/{subscription_id}/resourceGroups/rg")]
    )
    assert az_idn_015.scan(mock_azure, subscription_id) == []


@pytest.mark.parametrize("failed_inventory", ["principals", "assignments"])
def test_idn_015_inventory_failure_returns_no_findings(failed_inventory, mock_azure, subscription_id):
    mock_azure.set_managed_identity_service_principals(None if failed_inventory == "principals" else [])
    mock_azure.set_subscription_role_assignments(None if failed_inventory == "assignments" else [])
    assert az_idn_015.scan(mock_azure, subscription_id) == []
