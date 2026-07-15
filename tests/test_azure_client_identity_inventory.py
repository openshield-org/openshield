"""Tests for cached Microsoft Graph and RBAC identity inventory accessors."""

from unittest.mock import MagicMock, patch

from scanner.azure_client import AzureClient


class Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


@patch("requests.get")
def test_application_inventory_follows_pagination_and_caches(request_get):
    request_get.side_effect = [
        Response({"value": [{"id": "a1"}], "@odata.nextLink": "https://graph.microsoft.com/page2"}),
        Response({"value": [{"id": "a2"}]}),
    ]
    client = AzureClient("sub-1", credential=MagicMock())

    assert client.get_applications() == [{"id": "a1"}, {"id": "a2"}]
    assert client.get_applications() == [{"id": "a1"}, {"id": "a2"}]
    assert request_get.call_count == 2


@patch("requests.get")
def test_application_inventory_preserves_graph_failure(request_get):
    request_get.side_effect = RuntimeError("graph unavailable")
    client = AzureClient("sub-1", credential=MagicMock())
    assert client.get_applications() is None
    assert client.get_applications() is None
    request_get.assert_called_once()


@patch("requests.get")
def test_managed_identity_principal_inventory_uses_type_filter(request_get):
    request_get.return_value = Response({"value": [{"id": "mi-1"}]})
    client = AzureClient("sub-1", credential=MagicMock())
    assert client.get_managed_identity_service_principals() == [{"id": "mi-1"}]
    requested_url = request_get.call_args.args[0]
    assert "servicePrincipalType eq 'ManagedIdentity'" in requested_url


@patch("scanner.azure_client.AuthorizationManagementClient")
def test_subscription_role_assignments_cache_success(auth_client_type):
    auth_client_type.return_value.role_assignments.list_for_scope.return_value = ["assignment"]
    client = AzureClient("sub-1", credential=MagicMock())
    assert client.get_subscription_role_assignments() == ["assignment"]
    assert client.get_subscription_role_assignments() == ["assignment"]
    auth_client_type.return_value.role_assignments.list_for_scope.assert_called_once_with("/subscriptions/sub-1")


@patch("scanner.azure_client.AuthorizationManagementClient")
def test_subscription_role_assignments_preserves_failure(auth_client_type):
    auth_client_type.return_value.role_assignments.list_for_scope.side_effect = RuntimeError("denied")
    client = AzureClient("sub-1", credential=MagicMock())
    assert client.get_subscription_role_assignments() is None
