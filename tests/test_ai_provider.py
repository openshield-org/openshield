"""Tests for api.services.ai_provider (SEC-003: Gemini key must not leak via URL)."""

from unittest.mock import MagicMock, patch

from api.services import ai_provider


@patch("api.services.ai_provider.requests.post")
def test_gemini_api_key_sent_via_header_not_query_param(mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
    mock_post.return_value = mock_resp

    result = ai_provider.get_completion("gemini", "top-secret-key", "prompt")

    assert result == "ok"
    args, kwargs = mock_post.call_args
    url = args[0] if args else kwargs.get("url", "")
    assert "top-secret-key" not in url
    assert "params" not in kwargs or "key" not in (kwargs.get("params") or {})
    assert kwargs["headers"]["x-goog-api-key"] == "top-secret-key"
