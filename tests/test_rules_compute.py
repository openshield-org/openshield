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


def _disk_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Compute/disks/{name}"


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
#
# ManagedDiskParameters (the object actually embedded in a VM's
# storage_profile.os_disk/data_disks) only exposes id, storage_account_type,
# disk_encryption_set and security_profile -- it has no "encryption"
# attribute, and its security_profile (VMDiskSecurityProfile) carries
# security_encryption_type, not "type". The real encryption state lives on
# the underlying Disk resource, resolved via AzureClient.get_disk(id), whose
# Encryption.type and EncryptionSettingsCollection.enabled are the fields
# that actually distinguish compliant from non-compliant. These fixtures
# mirror that shape instead of inventing attributes the SDK does not define.


def _managed_disk(name):
    """A ManagedDiskParameters-shaped stub: only carries an id."""
    return make_resource(id=_disk_id(name))


def _disk(encryption_type=None, ade_enabled=False):
    """A Disk-shaped stub as returned by AzureClient.get_disk()."""
    return make_resource(
        encryption=make_resource(type=encryption_type) if encryption_type else None,
        encryption_settings_collection=make_resource(enabled=ade_enabled),
    )


def test_cmp_002_compliant_customer_key_returns_no_findings(mock_azure, subscription_id):
    """OS disk encrypted with a customer-managed key only is compliant."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-cmk"))
    vm = make_resource(
        id=_vm_id("vm-cmk"),
        name="vm-cmk",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(_disk_id("disk-cmk"), _disk(encryption_type="EncryptionAtRestWithCustomerKey"))
    assert az_cmp_002.scan(mock_azure, subscription_id) == []


def test_cmp_002_compliant_platform_and_customer_key_returns_no_findings(mock_azure, subscription_id):
    """OS disk encrypted with platform-and-customer keys is compliant."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-both"))
    vm = make_resource(
        id=_vm_id("vm-both"),
        name="vm-both",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(_disk_id("disk-both"), _disk(encryption_type="EncryptionAtRestWithPlatformAndCustomerKeys"))
    assert az_cmp_002.scan(mock_azure, subscription_id) == []


def test_cmp_002_compliant_ade_enabled_returns_no_findings(mock_azure, subscription_id):
    """A platform-key disk with Azure Disk Encryption enabled is compliant."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-ade"))
    vm = make_resource(
        id=_vm_id("vm-ade"),
        name="vm-ade",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(
        _disk_id("disk-ade"), _disk(encryption_type="EncryptionAtRestWithPlatformKey", ade_enabled=True)
    )
    assert az_cmp_002.scan(mock_azure, subscription_id) == []


def test_cmp_002_noncompliant_platform_key_returns_one_finding(mock_azure, subscription_id):
    """OS disk using platform-managed encryption only, with no ADE, must be flagged.

    This is a regression test: the previous implementation read
    managed_disk.security_profile / managed_disk.encryption, neither of
    which exist on ManagedDiskParameters, so every branch resolved to None
    and this case incorrectly returned no findings.
    """
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-pmk"))
    vm = make_resource(
        id=_vm_id("vm-pmk"),
        name="vm-pmk",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    mock_azure.set_disk(_disk_id("disk-pmk"), _disk(encryption_type="EncryptionAtRestWithPlatformKey"))
    findings = az_cmp_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert _REQUIRED_FIELDS.issubset(f.keys())
    assert f["rule_id"] == "AZ-CMP-002"
    assert f["severity"] == "HIGH"
    assert f["resource_name"] == "vm-pmk"
    assert f["metadata"]["unencrypted_disks"] == ["osdisk"]
    assert f["metadata"]["indeterminate_disks"] == []
    assert f["metadata"]["determination"] == "non_compliant"


def test_cmp_002_indeterminate_unreadable_disk_returns_one_finding(mock_azure, subscription_id):
    """A Disk resource that cannot be read must not be treated as compliant."""
    os_disk = make_resource(name="osdisk", managed_disk=_managed_disk("disk-unreadable"))
    vm = make_resource(
        id=_vm_id("vm-unreadable"),
        name="vm-unreadable",
        location="eastus",
        storage_profile=make_resource(os_disk=os_disk, data_disks=[]),
    )
    mock_azure.set_virtual_machines([vm])
    # No mock_azure.set_disk() call: get_disk() returns None, as it would if
    # Azure denied access or the disk had been deleted.
    findings = az_cmp_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    f = findings[0]
    assert f["metadata"]["unencrypted_disks"] == []
    assert f["metadata"]["indeterminate_disks"] == ["osdisk"]
    assert f["metadata"]["determination"] == "indeterminate"


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
