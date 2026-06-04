"""Rule regression tests for AZ-NET-001 and AZ-NET-002."""

import scanner.rules.az_net_001 as az_net_001
import scanner.rules.az_net_002 as az_net_002
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id", "rule_name", "severity", "category",
    "resource_id", "resource_name", "resource_type",
    "description", "remediation", "playbook", "frameworks", "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _nsg_id(name):
    return (
        f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
        f"/providers/Microsoft.Network/networkSecurityGroups/{name}"
    )


def _allow_rule(name, port, source="10.0.0.0/24"):
    return make_resource(
        name=name,
        direction="Inbound",
        access="Allow",
        source_address_prefix=source,
        source_address_prefixes=[],
        destination_port_range=port,
        destination_port_ranges=[],
    )


def _open_allow_rule(name, port):
    return make_resource(
        name=name,
        direction="Inbound",
        access="Allow",
        source_address_prefix="0.0.0.0/0",
        source_address_prefixes=[],
        destination_port_range=port,
        destination_port_ranges=[],
    )


def test_net_001_compliant_returns_no_findings(mock_azure, subscription_id):
    """An NSG restricting SSH to a trusted IP range must produce no findings."""
    nsg = make_resource(
        id=_nsg_id("nsg-ssh-restricted"),
        name="nsg-ssh-restricted",
        security_rules=[_allow_rule("AllowSSHFromTrusted", "22", "10.0.0.0/24")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_001.scan(mock_azure, subscription_id)
    assert findings == []


def test_net_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """An NSG with Allow-inbound-SSH-from-any must produce exactly one finding."""
    nsg = make_resource(
        id=_nsg_id("nsg-ssh-open"),
        name="nsg-ssh-open",
        security_rules=[_open_allow_rule("AllowSSHFromInternet", "22")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-NET-001"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Network"
    assert finding["resource_name"] == "nsg-ssh-open"


def test_net_002_compliant_returns_no_findings(mock_azure, subscription_id):
    """An NSG restricting RDP to a trusted IP range must produce no findings."""
    nsg = make_resource(
        id=_nsg_id("nsg-rdp-restricted"),
        name="nsg-rdp-restricted",
        security_rules=[_allow_rule("AllowRDPFromTrusted", "3389", "192.168.1.0/24")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_net_002_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """An NSG with Allow-inbound-RDP-from-any must produce exactly one finding."""
    nsg = make_resource(
        id=_nsg_id("nsg-rdp-open"),
        name="nsg-rdp-open",
        security_rules=[_open_allow_rule("AllowRDPFromInternet", "3389")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-NET-002"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Network"
    assert finding["resource_name"] == "nsg-rdp-open"
