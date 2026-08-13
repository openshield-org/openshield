"""Tests for AZ-SECOPS-006 (Defender plan coverage) and AZ-SECOPS-007 (recommendation SLA)."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import scanner.rules.az_secops_006 as az_secops_006
import scanner.rules.az_secops_007 as az_secops_007
from tests.helpers.mock_azure import MockAzureClient
from tests.helpers.security_operations import make_collector, set_policy_env, stub_collector

_SUB = "00000000-0000-0000-0000-000000000001"


def _client() -> MockAzureClient:
    return MockAzureClient()


def _pricing(name: str, tier: str) -> SimpleNamespace:
    return SimpleNamespace(name=name, pricing_tier=tier)


def _pricing_list(items):
    return SimpleNamespace(value=items)


# ── AZ-SECOPS-006: Defender plan coverage ───────────────────────────────────


def test_secops_006_all_required_plans_enabled_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_defender_plans=["VirtualMachines", "StorageAccounts"])
    security = SimpleNamespace(
        pricings=SimpleNamespace(
            list=lambda scope_id, **kw: _pricing_list(
                [_pricing("VirtualMachines", "Standard"), _pricing("StorageAccounts", "Standard")]
            )
        )
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_006, collector)
    assert az_secops_006.scan(_client(), _SUB) == []


def test_secops_006_missing_plan_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_defender_plans=["VirtualMachines", "StorageAccounts"])
    security = SimpleNamespace(
        pricings=SimpleNamespace(list=lambda scope_id, **kw: _pricing_list([_pricing("VirtualMachines", "Standard")]))
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_006, collector)
    findings = az_secops_006.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["resource_name"] == "storageaccounts"
    assert findings[0]["metadata"]["plan_found_in_subscription"] is False
    assert findings[0]["metadata"]["cis_control_reference"] == "2.1.7"


def test_secops_006_free_tier_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_defender_plans=["VirtualMachines"])
    security = SimpleNamespace(
        pricings=SimpleNamespace(list=lambda scope_id, **kw: _pricing_list([_pricing("VirtualMachines", "Free")]))
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_006, collector)
    findings = az_secops_006.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["plan_found_in_subscription"] is True


def test_secops_006_empty_required_plans_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_defender_plans=[])
    security = SimpleNamespace(pricings=SimpleNamespace(list=lambda scope_id, **kw: _pricing_list([])))
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_006, collector)
    assert az_secops_006.scan(_client(), _SUB) == []


def test_secops_006_pricing_api_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_defender_plans=["VirtualMachines"])

    def fail(scope_id, **kw):
        raise PermissionError("denied")

    security = SimpleNamespace(pricings=SimpleNamespace(list=fail))
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_006, collector)
    assert az_secops_006.scan(_client(), _SUB) == []


# ── AZ-SECOPS-007: Defender recommendation SLA ──────────────────────────────


def _assessment(*, severity: str, status_code: str, first_evaluation: str = None, name: str = "assess-1"):
    metadata = SimpleNamespace(display_name=f"Recommendation {name}", severity=severity)
    status = SimpleNamespace(code=status_code)
    additional_data = {"firstEvaluationDate": first_evaluation} if first_evaluation else {}
    return SimpleNamespace(
        id=f"/subscriptions/sub/providers/Microsoft.Security/assessments/{name}",
        name=name,
        metadata=metadata,
        status=status,
        additional_data=additional_data,
        resource_details=SimpleNamespace(id="/subscriptions/sub/resourceGroups/rg/providers/x/y"),
    )


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def test_secops_007_unresolved_beyond_sla_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, defender_recommendation_sla_days=30)
    security = SimpleNamespace(
        assessments=SimpleNamespace(
            list=lambda scope: [_assessment(severity="High", status_code="Unhealthy", first_evaluation=_iso(45))]
        )
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_007, collector)
    findings = az_secops_007.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["age_days"] >= 45


def test_secops_007_within_sla_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, defender_recommendation_sla_days=30)
    security = SimpleNamespace(
        assessments=SimpleNamespace(
            list=lambda scope: [_assessment(severity="High", status_code="Unhealthy", first_evaluation=_iso(10))]
        )
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_007, collector)
    assert az_secops_007.scan(_client(), _SUB) == []


def test_secops_007_healthy_status_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, defender_recommendation_sla_days=30)
    security = SimpleNamespace(
        assessments=SimpleNamespace(
            list=lambda scope: [_assessment(severity="High", status_code="Healthy", first_evaluation=_iso(400))]
        )
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_007, collector)
    assert az_secops_007.scan(_client(), _SUB) == []


def test_secops_007_low_severity_is_not_evaluated(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, defender_recommendation_sla_days=30)
    security = SimpleNamespace(
        assessments=SimpleNamespace(
            list=lambda scope: [_assessment(severity="Low", status_code="Unhealthy", first_evaluation=_iso(400))]
        )
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_007, collector)
    assert az_secops_007.scan(_client(), _SUB) == []


def test_secops_007_no_timestamp_is_skipped_not_fabricated(monkeypatch, tmp_path):
    """An assessment with no usable timestamp must never be silently marked compliant or overdue."""
    set_policy_env(monkeypatch, tmp_path, defender_recommendation_sla_days=30)
    security = SimpleNamespace(
        assessments=SimpleNamespace(
            list=lambda scope: [_assessment(severity="High", status_code="Unhealthy", first_evaluation=None)]
        )
    )
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_007, collector)
    assert az_secops_007.scan(_client(), _SUB) == []


def test_secops_007_assessments_api_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail(scope):
        raise RuntimeError("boom")

    security = SimpleNamespace(assessments=SimpleNamespace(list=fail))
    collector = make_collector(security_client=security)
    stub_collector(monkeypatch, az_secops_007, collector)
    assert az_secops_007.scan(_client(), _SUB) == []
