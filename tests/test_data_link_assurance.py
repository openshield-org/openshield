"""Completeness, API, and ExpressRoute MACsec regression tests."""

import copy
import json
from datetime import date
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from azure.mgmt.network.models import ExpressRouteLink, ExpressRouteLinkMacSecConfig, ExpressRoutePort

from api.services.data_link_assurance import (
    EXPECTED_DOMAIN_IDS,
    EXPECTED_SUBLAYER_IDS,
    build_report,
    load_catalog,
    validate_catalog,
)
from api.services.physical_assurance import CatalogValidationError
from scanner.rules import az_dl_001, az_dl_002
from scanner.rules._data_link_common import InventoryState, inventory_state


def _link(
    *,
    state: str = "Enabled",
    cipher: str | None = "GcmAesXpn256",
    cak: str = "cak-sensitive-value",
    ckn: str = "ckn-sensitive-value",
) -> SimpleNamespace:
    config = None
    if cipher is not None:
        config = SimpleNamespace(cipher=cipher, cak_secret_identifier=cak, ckn_secret_identifier=ckn)
    return SimpleNamespace(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/expressRoutePorts/erd1/links/link1",
        name="link1",
        admin_state=state,
        mac_sec_config=config,
    )


def _port(link: SimpleNamespace, bandwidth: int = 100) -> SimpleNamespace:
    return SimpleNamespace(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/expressRoutePorts/erd1",
        name="erd1",
        bandwidth_in_gbps=bandwidth,
        links=[link],
    )


def test_catalog_covers_both_sublayers_and_all_domains():
    catalog = load_catalog()
    assert {item["id"] for item in catalog["domains"]} == EXPECTED_DOMAIN_IDS
    assert {item["id"] for item in catalog["sublayers"]} == EXPECTED_SUBLAYER_IDS
    assert all(domain["responsibility_owner"] for domain in catalog["domains"])
    assert all(domain["azure_applicability"] for domain in catalog["domains"])
    assert all(domain["observability_method"] for domain in catalog["domains"])
    assert all(domain["evidence_source_ids"] for domain in catalog["domains"])


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        (lambda catalog: catalog["domains"].pop(), "complete DL-01 through DL-19"),
        (lambda catalog: catalog["sublayers"].pop(), "LLC and MAC"),
        (lambda catalog: catalog["domains"][0].pop("responsibility_owner"), "responsibility_owner"),
        (lambda catalog: catalog["domains"][0].pop("azure_applicability"), "azure_applicability"),
        (lambda catalog: catalog["domains"][0].pop("evidence_source_ids"), "evidence_source_ids"),
        (lambda catalog: catalog["domains"][14].pop("automated_control_ids"), "automated_control_ids"),
    ],
)
def test_catalog_fails_closed_on_missing_required_content(mutation, error_match):
    catalog = copy.deepcopy(load_catalog())
    mutation(catalog)
    with pytest.raises(CatalogValidationError, match=error_match):
        validate_catalog(catalog)


def test_report_separates_catalog_coverage_from_evidence_freshness():
    report = build_report(load_catalog(), as_of=date(2028, 1, 1))
    assert report["catalog_coverage"] == {
        "domains_covered": 19,
        "domains_total": 19,
        "percent": 100,
        "sublayers_covered": 2,
        "sublayers_total": 2,
    }
    assert report["evidence_freshness"]["percent"] == 0
    assert report["provider_assurance_state"] == "DOCUMENTED"
    assert report["platform_enforcement_state"] == "DOCUMENTED_NOT_LIVE_INSPECTED"


def test_data_link_endpoint_requires_authentication(client):
    assert client.get("/api/assurance/data-link-layer").status_code == 401


def test_data_link_endpoint_returns_complete_report(client, auth_headers):
    response = client.get("/api/assurance/data-link-layer", headers=auth_headers)
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["layer"]["number"] == 2
    assert payload["layer"]["name"] == "Data Link"
    assert payload["catalog_coverage"]["percent"] == 100
    assert len(payload["domains"]) == 19
    assert {item["id"] for item in payload["sublayers"]} == {"LLC", "MAC"}
    assert payload["automated_control_applicability"]["api_or_permission_failure"] == "INDETERMINATE"


def test_data_link_endpoint_hides_catalog_errors(client, auth_headers):
    with patch(
        "api.routes.assurance.get_data_link_assurance_report",
        side_effect=CatalogValidationError("sensitive path"),
    ):
        response = client.get("/api/assurance/data-link-layer", headers=auth_headers)
    assert response.status_code == 500
    assert response.get_json() == {"error": "Data Link assurance catalog is unavailable"}
    assert "sensitive path" not in response.get_data(as_text=True)


def test_empty_inventory_is_not_applicable_and_creates_no_findings(mock_azure, subscription_id):
    mock_azure.set_express_route_ports([])
    assert inventory_state(mock_azure.get_express_route_ports()) is InventoryState.NOT_APPLICABLE
    assert az_dl_001.scan(mock_azure, subscription_id) == []
    assert az_dl_002.scan(mock_azure, subscription_id) == []


def test_failed_inventory_is_indeterminate_and_creates_no_findings(mock_azure, subscription_id, caplog):
    mock_azure.set_express_route_ports(None)
    assert inventory_state(mock_azure.get_express_route_ports()) is InventoryState.INDETERMINATE
    assert az_dl_001.scan(mock_azure, subscription_id) == []
    assert az_dl_002.scan(mock_azure, subscription_id) == []
    assert caplog.text.count("result is indeterminate") == 2


def test_enabled_link_without_macsec_creates_only_absence_finding(mock_azure, subscription_id):
    mock_azure.set_express_route_ports([_port(_link(cipher=None))])
    findings = az_dl_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DL-001"
    assert findings[0]["category"] == "Data Link"
    assert findings[0]["playbook"] == "playbooks/cli/fix_az_dl_001.sh"
    assert findings[0]["resource_id"].endswith("/expressRoutePorts/erd1/links/link1")
    assert findings[0]["resource_name"] == "erd1/link1"
    assert az_dl_002.scan(mock_azure, subscription_id) == []


def test_high_speed_non_xpn_cipher_creates_finding(mock_azure, subscription_id):
    mock_azure.set_express_route_ports([_port(_link(cipher="GcmAes256"), bandwidth=100)])
    findings = az_dl_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-DL-002"
    assert findings[0]["category"] == "Data Link"
    assert findings[0]["playbook"] == "playbooks/cli/fix_az_dl_002.sh"
    assert findings[0]["resource_id"].endswith("/expressRoutePorts/erd1/links/link1")
    assert findings[0]["resource_name"] == "erd1/link1"
    assert findings[0]["metadata"]["cipher"] == "GcmAes256"


@pytest.mark.parametrize(
    ("bandwidth", "cipher"),
    [(10, "GcmAes256"), (40, "GcmAesXpn128"), (100, "GcmAesXpn256")],
)
def test_low_speed_or_xpn_links_do_not_create_cipher_findings(mock_azure, subscription_id, bandwidth, cipher):
    mock_azure.set_express_route_ports([_port(_link(cipher=cipher), bandwidth=bandwidth)])
    assert az_dl_002.scan(mock_azure, subscription_id) == []


def test_disabled_links_are_not_customer_actionable(mock_azure, subscription_id):
    mock_azure.set_express_route_ports([_port(_link(state="Disabled", cipher=None))])
    assert az_dl_001.scan(mock_azure, subscription_id) == []
    assert az_dl_002.scan(mock_azure, subscription_id) == []


def test_findings_never_expose_cak_or_ckn(mock_azure, subscription_id):
    mock_azure.set_express_route_ports([_port(_link(cipher="GcmAes256"))])
    serialized = json.dumps(az_dl_002.scan(mock_azure, subscription_id))
    assert "cak-sensitive-value" not in serialized
    assert "ckn-sensitive-value" not in serialized
    assert "secret_identifier" not in serialized


def test_rules_use_real_azure_sdk_link_structure(mock_azure, subscription_id):
    """Protect the exact Azure SDK field names and child-link resource identity."""
    config = ExpressRouteLinkMacSecConfig(
        cipher="GcmAes256",
        cak_secret_identifier="https://vault.example/secrets/cak",
        ckn_secret_identifier="https://vault.example/secrets/ckn",
    )
    link_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/expressRoutePorts/erd1/links/link2"
    link = ExpressRouteLink(
        id=link_id,
        name="link2",
        admin_state="Enabled",
        mac_sec_config=config,
    )
    port = ExpressRoutePort(
        id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/expressRoutePorts/erd1",
        bandwidth_in_gbps=100,
        links=[link],
    )
    port.name = "erd1"
    mock_azure.set_express_route_ports([port])

    assert az_dl_001.scan(mock_azure, subscription_id) == []
    findings = az_dl_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["resource_id"] == link_id
    assert findings[0]["resource_name"] == "erd1/link2"
    serialized = json.dumps(findings)
    assert "vault.example" not in serialized


def test_express_route_inventory_uses_azure_client_abstraction():
    from scanner.azure_client import AzureClient

    sdk_client = MagicMock()
    sdk_client.express_route_ports.list.return_value = [SimpleNamespace(name="erd1")]
    with patch("scanner.azure_client.NetworkManagementClient", return_value=sdk_client):
        client = AzureClient("sub-1", credential=MagicMock())
        assert [port.name for port in client.get_express_route_ports()] == ["erd1"]


def test_express_route_inventory_preserves_api_failure():
    from scanner.azure_client import AzureClient

    with patch("scanner.azure_client.NetworkManagementClient", side_effect=PermissionError("denied")):
        client = AzureClient("sub-1", credential=MagicMock())
        assert client.get_express_route_ports() is None
