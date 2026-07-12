"""Rule regression tests for the compute rules AZ-CMP-001 .. AZ-CMP-004.

Each test configures a MockAzureClient with fake VM/NIC/extension data and
calls the rule's scan() function directly. No network calls are made — the
mock_azure and subscription_id fixtures come from tests/conftest.py and the
helper accessors from tests/helpers/mock_azure.py.
"""

import scanner.rules.az_cmp_001 as az_cmp_001
import scanner.rules.az_cmp_002 as az_cmp_002
import scanner.rules.az_cmp_003 as az_cmp_003
import scanner.rules.az_cmp_004 as az_cmp_004
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
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _vm_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Compute/virtualMachines/{name}"


def _nic_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Network/networkInterfaces/{name}"


# ── AZ-CMP-001: VM public IP with no NSG ────────────────────────────────────


def test_cmp_001_compliant_nic_with_nsg_returns_no_findings(mock_azure, subscription_id):
    """A NIC with a public IP but a protecting NSG is compliant."""
    nic = make_resource(
        ip_configurations=[make_resource(public_ip_address=make_resource(id="pip1"))],
        network_security_group=make_resource(id="nsg1"),
    )
    vm = make_resource(
        id=_vm_id("vm-compliant"),
        name="vm-compliant",
        network_profile=make_resource(network_interfaces=[make_resource(id=_nic_id("nic1"))]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_network_interface(_RG, "nic1", nic)
    assert az_cmp_001.scan(mock_azure, subscription_id) == []


def test_cmp_001_noncompliant_public_ip_no_nsg_returns_one_finding(mock_azure, subscription_id):
    """A NIC with a public IP and no NSG must produce exactly one finding."""
    nic = make_resource(
        ip_configurations=[make_resource(public_ip_address=make_resource(id="pip1"))],
        network_security_group=None,
    )
    vm = make_resource(
        id=_vm_id("vm-exposed"),
        name="vm-exposed",
        network_profile=make_resource(network_interfaces=[make_resource(id=_nic_id("nic1"))]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_network_interface(_RG, "nic1", nic)
    findings = az_cmp_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-001"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-exposed"


# ── AZ-CMP-002: disk using platform-managed encryption only ─────────────────


def test_cmp_002_compliant_cmk_disk_returns_no_findings(mock_azure, subscription_id):
    """OS disk encrypted with a customer-managed key is compliant."""
    os_disk = make_resource(
        name="osdisk",
        managed_disk=make_resource(encryption=make_resource(type="EncryptionAtRestWithCustomerKey")),
    )
    vm = make_resource(
        id=_vm_id("vm-cmk"),
        name="vm-cmk",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    assert az_cmp_002.scan(mock_azure, subscription_id) == []


def test_cmp_002_noncompliant_platform_key_returns_one_finding(mock_azure, subscription_id):
    """OS disk using platform-managed encryption only must produce one finding."""
    os_disk = make_resource(
        name="osdisk",
        managed_disk=make_resource(encryption=make_resource(type="EncryptionAtRestWithPlatformKey")),
    )
    vm = make_resource(
        id=_vm_id("vm-pmk"),
        name="vm-pmk",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    findings = az_cmp_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-002"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-pmk"


# ── AZ-CMP-003: VM without endpoint protection ──────────────────────────────


def test_cmp_003_compliant_with_ep_extension_returns_no_findings(mock_azure, subscription_id):
    """A VM with a recognised endpoint-protection extension is compliant."""
    vm = make_resource(id=_vm_id("vm-protected"), name="vm-protected")
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_vm_extensions(
        _RG,
        "vm-protected",
        [make_resource(type_properties_type="IaaSAntimalware")],
    )
    assert az_cmp_003.scan(mock_azure, subscription_id) == []


def test_cmp_003_noncompliant_no_ep_extension_returns_one_finding(mock_azure, subscription_id):
    """A VM with no endpoint-protection extension must produce one finding."""
    vm = make_resource(id=_vm_id("vm-unprotected"), name="vm-unprotected")
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_vm_extensions(
        _RG,
        "vm-unprotected",
        [make_resource(type_properties_type="CustomScript")],
    )
    findings = az_cmp_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-003"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-unprotected"


def test_cmp_003_extensions_none_skips_without_finding(mock_azure, subscription_id):
    """When extensions cannot be determined (None) the rule must not flag."""
    vm = make_resource(id=_vm_id("vm-unknown"), name="vm-unknown")
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_vm_extensions(_RG, "vm-unknown", None)
    assert az_cmp_003.scan(mock_azure, subscription_id) == []


# ── AZ-CMP-004: VM without automatic OS patching ────────────────────────────


def test_cmp_004_compliant_auto_updates_returns_no_findings(mock_azure, subscription_id):
    """A Windows VM with automatic updates enabled is compliant."""
    vm = make_resource(
        id=_vm_id("vm-patched"),
        name="vm-patched",
        os_profile=make_resource(
            windows_configuration=make_resource(enable_automatic_updates=True, patch_settings=None),
            linux_configuration=None,
        ),
    )
    mock_azure.set_virtual_machines([vm])
    assert az_cmp_004.scan(mock_azure, subscription_id) == []


def test_cmp_004_noncompliant_no_patching_returns_one_finding(mock_azure, subscription_id):
    """A Windows VM with auto-updates off and no auto patch-mode must flag."""
    vm = make_resource(
        id=_vm_id("vm-stale"),
        name="vm-stale",
        os_profile=make_resource(
            windows_configuration=make_resource(enable_automatic_updates=False, patch_settings=None),
            linux_configuration=None,
        ),
    )
    mock_azure.set_virtual_machines([vm])
    findings = az_cmp_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-004"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-stale"
