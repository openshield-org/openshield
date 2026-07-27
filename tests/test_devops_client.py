"""Direct tests for DevOpsClient and its failure states."""

from unittest.mock import MagicMock, patch

import pytest

from scanner.devops_client import DevOpsClient


@pytest.fixture
def client():
    return DevOpsClient("https://dev.azure.com/test-org", "test-project", credential=MagicMock())


def test_get_service_endpoints_returns_results_and_caches(client):
    client.credential.get_token.return_value = MagicMock(token="fake-token")

    with patch("azure.devops.connection.Connection") as conn_ctor:
        fake_conn = MagicMock()
        conn_ctor.return_value = fake_conn
        fake_conn.clients_v7_1.get_service_endpoint_client.return_value.get_service_endpoints.return_value = [
            MagicMock(name="ep1")
        ]
        result = client.get_service_endpoints()
        assert result is not None
        assert len(result) == 1

        # cached: second call must not rebuild the connection
        conn_ctor.side_effect = RuntimeError("should not be called")
        assert client.get_service_endpoints() is result


def test_get_service_endpoints_auth_failure_returns_none():
    client = DevOpsClient("https://dev.azure.com/test-org", "test-project", credential=MagicMock())
    client.credential.get_token.side_effect = RuntimeError("auth failed")
    assert client.get_service_endpoints() is None


def test_get_service_endpoints_api_failure_returns_none(client):
    client.credential.get_token.return_value = MagicMock(token="fake-token")
    with patch("azure.devops.connection.Connection") as conn_ctor:
        fake_conn = MagicMock()
        conn_ctor.return_value = fake_conn
        fake_conn.clients_v7_1.get_service_endpoint_client.return_value.get_service_endpoints.side_effect = (
            RuntimeError("denied")
        )
        assert client.get_service_endpoints() is None


def test_default_credential_used_when_none_provided():
    with patch("azure.identity.DefaultAzureCredential") as cred_ctor:
        cred_ctor.return_value = MagicMock()
        client = DevOpsClient("https://dev.azure.com/test-org", "test-project")
        assert client.credential is cred_ctor.return_value
