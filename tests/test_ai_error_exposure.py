"""Tests that /api/ai/{summary,prioritise,ask,threat-simulation} never leak
exception internals to the client (issue #177, CodeQL: information exposure
through an exception).

get_completion() in api/services/ai_provider.py wraps raw third-party
provider errors into RuntimeError messages (e.g. "Anthropic request failed:
{exc}"), which could carry response bodies or connection details from the
underlying HTTP client. These routes must never reflect that (or any other
exception's) message back to the caller.
"""

import secrets
from unittest.mock import patch

from ai.retriever import VectorStoreNotBuilt

_LEAK_MARKER = "provider-internal-secret-token-abc123"

_VALID_FINDINGS = [
    {
        "rule_id": "AZ-NET-001",
        "severity": "HIGH",
        "title": "Example finding",
        "description": "Example description.",
        "remediation": "Example remediation.",
    }
]


def _fake_api_key() -> str:
    return secrets.token_urlsafe(24)


def _assert_no_leak(resp, expected_status):
    assert resp.status_code == expected_status
    body = resp.get_json()
    assert _LEAK_MARKER not in str(body)


ENDPOINTS = {
    "/api/ai/summary": {"provider": "anthropic", "api_key": None, "findings": _VALID_FINDINGS},
    "/api/ai/prioritise": {"provider": "anthropic", "api_key": None, "findings": _VALID_FINDINGS},
    "/api/ai/ask": {"provider": "anthropic", "api_key": None, "question": "What is my risk?"},
    "/api/ai/threat-simulation": {"provider": "anthropic", "api_key": None, "findings": _VALID_FINDINGS},
}


def _payload(endpoint):
    body = dict(ENDPOINTS[endpoint])
    body["api_key"] = _fake_api_key()
    return body


@patch("api.routes.ai._context_for")
def test_vector_store_not_built_does_not_leak_exception(mock_context, client, auth_headers):
    mock_context.side_effect = VectorStoreNotBuilt(_LEAK_MARKER)
    for endpoint in ENDPOINTS:
        resp = client.post(endpoint, json=_payload(endpoint), headers=auth_headers)
        _assert_no_leak(resp, 503)


@patch("api.routes.ai.get_completion")
@patch("api.routes.ai._context_for")
def test_provider_value_error_does_not_leak_exception(mock_context, mock_gc, client, auth_headers):
    mock_context.return_value = ("grounded context", [])
    mock_gc.side_effect = ValueError(_LEAK_MARKER)
    for endpoint in ENDPOINTS:
        resp = client.post(endpoint, json=_payload(endpoint), headers=auth_headers)
        _assert_no_leak(resp, 400)


@patch("api.routes.ai.get_completion")
@patch("api.routes.ai._context_for")
def test_provider_runtime_error_does_not_leak_exception(mock_context, mock_gc, client, auth_headers):
    mock_context.return_value = ("grounded context", [])
    mock_gc.side_effect = RuntimeError(f"Anthropic request failed: {_LEAK_MARKER}")
    for endpoint in ENDPOINTS:
        resp = client.post(endpoint, json=_payload(endpoint), headers=auth_headers)
        _assert_no_leak(resp, 502)
