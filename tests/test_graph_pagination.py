"""Tests for AzureClient.get_conditional_access_policies pagination (COR-008)."""

from unittest.mock import MagicMock, patch

from scanner.azure_client import AzureClient


def _client():
    credential = MagicMock()
    credential.get_token.return_value = MagicMock(token="fake-token")
    return AzureClient(subscription_id="sub-1", credential=credential)


def _mock_response(value, next_link=None):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    body = {"value": value}
    if next_link:
        body["@odata.nextLink"] = next_link
    resp.json.return_value = body
    return resp


@patch("requests.get")
def test_single_page_returns_all_policies(mock_get):
    mock_get.return_value = _mock_response([{"id": "p1"}, {"id": "p2"}])

    result = _client().get_conditional_access_policies()

    assert result == [{"id": "p1"}, {"id": "p2"}]
    assert mock_get.call_count == 1


@patch("requests.get")
def test_follows_next_link_across_multiple_pages(mock_get):
    page1 = _mock_response([{"id": "p1"}], next_link="https://graph.microsoft.com/v1.0/...&$skiptoken=abc")
    page2 = _mock_response([{"id": "p2"}], next_link="https://graph.microsoft.com/v1.0/...&$skiptoken=def")
    page3 = _mock_response([{"id": "p3"}])
    mock_get.side_effect = [page1, page2, page3]

    result = _client().get_conditional_access_policies()

    assert result == [{"id": "p1"}, {"id": "p2"}, {"id": "p3"}]
    assert mock_get.call_count == 3
    # Second and third calls must hit the nextLink URLs, not the base URL again
    called_urls = [call.args[0] for call in mock_get.call_args_list]
    assert called_urls[1] == "https://graph.microsoft.com/v1.0/...&$skiptoken=abc"
    assert called_urls[2] == "https://graph.microsoft.com/v1.0/...&$skiptoken=def"


@patch("requests.get")
def test_no_next_link_stops_after_one_page(mock_get):
    mock_get.return_value = _mock_response([{"id": "only"}])

    result = _client().get_conditional_access_policies()

    assert result == [{"id": "only"}]
    assert mock_get.call_count == 1


@patch("requests.get")
def test_request_failure_returns_empty_list(mock_get):
    mock_get.side_effect = Exception("network error")

    result = _client().get_conditional_access_policies()

    assert result == []


@patch("requests.get")
def test_failure_on_second_page_does_not_raise(mock_get):
    page1 = _mock_response([{"id": "p1"}], next_link="https://graph.microsoft.com/v1.0/...&$skiptoken=abc")
    mock_get.side_effect = [page1, Exception("boom")]

    result = _client().get_conditional_access_policies()

    # Current behavior: a mid-pagination failure returns [] rather than partial results
    assert result == []
