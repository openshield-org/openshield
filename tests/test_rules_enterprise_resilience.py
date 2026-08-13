"""Tests for Functions, Private Endpoint, and Backup enterprise resilience rules."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.rules import (
    az_bak_001,
    az_bak_002,
    az_bak_004,
    az_bak_006,
    az_func_001,
    az_func_002,
    az_func_003,
    az_func_004,
    az_func_005,
    az_pe_001,
    az_pe_002,
    az_pe_003,
    az_pe_004,
    az_pe_005,
    az_pe_006,
)


FUNCTION_RULES = [az_func_001, az_func_002, az_func_003, az_func_004, az_func_005]
PRIVATE_RULES = [az_pe_001, az_pe_002, az_pe_003, az_pe_004, az_pe_005]
BACKUP_RULES = [az_bak_001, az_bak_002, az_bak_004, az_bak_006]
FRAMEWORK_DIR = Path(__file__).parent.parent / "compliance" / "frameworks"


def test_principle_frameworks_keep_identity_and_enterprise_rule_mappings():
    """Adding this pack must not replace the identity mappings already on dev."""
    expected_ids = {
        *(f"AZ-IDN-{number:03d}" for number in range(10, 16)),
        *(rule.RULE_ID for rule in FUNCTION_RULES + PRIVATE_RULES + [az_pe_006] + BACKUP_RULES),
    }
    for filename in ("nist_csf.json", "iso27001.json", "soc2.json"):
        with (FRAMEWORK_DIR / filename).open(encoding="utf-8") as framework_file:
            controls = json.load(framework_file)["controls"]
        assert expected_ids <= controls.keys(), f"{filename} is missing {sorted(expected_ids - controls.keys())}"


def function_app(**changes):
    item = {
        "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/fn",
        "name": "fn",
        "https_only": True,
        "min_tls_version": "1.2",
        "ftps_state": "Disabled",
        "remote_debugging_enabled": False,
        "identity_type": "SystemAssigned",
    }
    item.update(changes)
    return item


@pytest.mark.parametrize("rule", FUNCTION_RULES)
def test_function_compliant_and_inventory_failure(rule):
    client = MagicMock()
    client.get_function_app_security_posture.return_value = [function_app()]
    assert rule.scan(client, "s") == []
    client.get_function_app_security_posture.return_value = None
    assert rule.scan(client, "s") == []


@pytest.mark.parametrize(
    ("rule", "change"),
    [
        (az_func_001, {"https_only": False}),
        (az_func_002, {"min_tls_version": "1.0"}),
        (az_func_003, {"ftps_state": "FtpsOnly"}),
        (az_func_004, {"remote_debugging_enabled": True}),
        (az_func_005, {"identity_type": "None"}),
    ],
)
def test_function_noncompliance(rule, change):
    client = MagicMock()
    client.get_function_app_security_posture.return_value = [function_app(**change)]
    finding = rule.scan(client, "s")[0]
    assert finding["rule_id"] == rule.RULE_ID
    assert finding["resource_type"] == "Microsoft.Web/sites"
    assert finding["frameworks"]["CIS"].startswith("N/A-FUNC-")


@pytest.mark.parametrize("rule", FUNCTION_RULES)
def test_function_unknown_property_is_not_false_positive(rule):
    client = MagicMock()
    app = function_app()
    fields = {
        az_func_001: "https_only",
        az_func_002: "min_tls_version",
        az_func_003: "ftps_state",
        az_func_004: "remote_debugging_enabled",
        az_func_005: "identity_type",
    }
    app[fields[rule]] = None
    client.get_function_app_security_posture.return_value = [app]
    assert rule.scan(client, "s") == []


@pytest.mark.parametrize(("rule", "service"), zip(PRIVATE_RULES, ["storage", "sql", "postgresql", "web", "recovery"]))
def test_private_endpoint_rules(rule, service):
    client = MagicMock()
    base = {
        "id": f"/subscriptions/s/{service}/one",
        "name": "one",
        "service": service,
        "public_network_access": "Enabled",
        "required_groups": ["target"],
        "approved_groups": [],
    }
    client.get_private_endpoint_posture.return_value = [base]
    assert len(rule.scan(client, "s")) == 1
    client.get_private_endpoint_posture.return_value = [{**base, "approved_groups": ["target"]}]
    finding = rule.scan(client, "s")[0]
    assert finding["metadata"]["missing_private_link_groups"] == []
    client.get_private_endpoint_posture.return_value = [{**base, "public_network_access": "Disabled"}]
    assert rule.scan(client, "s") == []


@pytest.mark.parametrize("rule", PRIVATE_RULES + [az_pe_006])
def test_private_inventory_failure_is_indeterminate(rule):
    client = MagicMock()
    client.get_private_endpoint_posture.return_value = None
    assert rule.scan(client, "s") == []


def test_unhealthy_private_endpoint_connection_is_reported():
    client = MagicMock()
    client.get_private_endpoint_posture.return_value = [
        {"id": "/pe/one", "name": "one", "service": "connection", "status": "Rejected"}
    ]
    finding = az_pe_006.scan(client, "s")[0]
    assert finding["metadata"]["connection_status"] == "Rejected"


def vault(**changes):
    item = {
        "id": "/subscriptions/s/providers/Microsoft.RecoveryServices/vaults/v",
        "name": "v",
        "soft_delete_state": "AlwaysON",
        "soft_delete_retention_days": 35,
        "immutability_state": "Locked",
        "multi_user_authorization": "Enabled",
        "resource_guard_operations": ["Microsoft.RecoveryServices/vaults/backupconfig/write"],
        "monitoring_alerts_for_job_failures": "Enabled",
    }
    item.update(changes)
    return item


@pytest.mark.parametrize("rule", BACKUP_RULES)
def test_backup_compliant_and_inventory_failure(rule):
    client = MagicMock()
    client.get_recovery_vault_security_posture.return_value = [vault()]
    assert rule.scan(client, "s") == []
    client.get_recovery_vault_security_posture.return_value = None
    assert rule.scan(client, "s") == []


@pytest.mark.parametrize(
    ("rule", "change"),
    [
        (az_bak_001, {"soft_delete_retention_days": 14}),
        (az_bak_002, {"immutability_state": "Disabled"}),
        (az_bak_004, {"multi_user_authorization": "Disabled", "resource_guard_operations": []}),
        (az_bak_006, {"monitoring_alerts_for_job_failures": "Disabled"}),
    ],
)
def test_backup_noncompliance(rule, change):
    client = MagicMock()
    client.get_recovery_vault_security_posture.return_value = [vault(**change)]
    finding = rule.scan(client, "s")[0]
    assert finding["rule_id"] == rule.RULE_ID
    assert finding["resource_type"] == "Microsoft.RecoveryServices/vaults"


@pytest.mark.parametrize(
    ("rule", "change"),
    [
        (az_bak_001, {"soft_delete_state": None}),
        (az_bak_002, {"immutability_state": None}),
        (az_bak_004, {"multi_user_authorization": None}),
        (az_bak_006, {"monitoring_alerts_for_job_failures": None}),
    ],
)
def test_backup_unknown_is_not_false_positive(rule, change):
    client = MagicMock()
    client.get_recovery_vault_security_posture.return_value = [vault(**change)]
    assert rule.scan(client, "s") == []
