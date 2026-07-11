"""Rule regression tests for AZ-NET-001, AZ-NET-002, and AZ-NET-003."""

import scanner.rules.az_net_001 as az_net_001
import scanner.rules.az_net_002 as az_net_002
import scanner.rules.az_net_003 as az_net_003
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "category",
    "resource_id",
    "resource_name",
    "resource_type",
    "description",
    "remediation",
    "playbook",
    "frameworks",
    "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _nsg_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/networkSecurityGroups/{name}"


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


def _net_003_rule(name, direction="Inbound", access="Allow",
                   source="0.0.0.0/0", source_list=None, port="443"):
    return make_resource(
        name=name,
        direction=direction,
        access=access,
        source_address_prefix=source,
        source_address_prefixes=source_list or [],
        destination_port_range=port,
    )


def test_net_003_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """An NSG with Allow-inbound-443-from-any must produce exactly one finding."""
    nsg = make_resource(
        id=_nsg_id("nsg-443-open"),
        name="nsg-443-open",
        security_rules=[_net_003_rule("AllowHTTPSFromInternet")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-NET-003"


def test_net_003_compliant_returns_no_findings(mock_azure, subscription_id):
    """An NSG restricting 443 to a trusted IP range must produce no findings."""
    nsg = make_resource(
        id=_nsg_id("nsg-443-restricted"),
        name="nsg-443-restricted",
        security_rules=[_net_003_rule("AllowHTTPSFromTrusted", source="10.0.0.0/24")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert findings == []


def test_net_003_direction_is_case_insensitive(mock_azure, subscription_id):
    """COR-001: lowercase/mixed-case direction values must still be detected."""
    nsg = make_resource(
        id=_nsg_id("nsg-lowercase-direction"),
        name="nsg-lowercase-direction",
        security_rules=[_net_003_rule("AllowHTTPSLower", direction="inbound")],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1


def test_net_003_detects_plural_source_prefixes(mock_azure, subscription_id):
    """COR-002: an open source listed only in source_address_prefixes must be detected."""
    nsg = make_resource(
        id=_nsg_id("nsg-plural-prefix"),
        name="nsg-plural-prefix",
        security_rules=[
            _net_003_rule(
                "AllowHTTPSPluralOpen",
                source="",
                source_list=["0.0.0.0/0"],
            )
        ],
    )
    mock_azure.set_network_security_groups([nsg])
    findings = az_net_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
