"""Mocked request coverage for the SDK make request action."""

import json
from types import SimpleNamespace

import httpx
import pytest
from soar_sdk.exceptions import ActionFailure

from src import helper
from src.actions.make_request import MakeRequestParams, make_request


@pytest.fixture
def http_calls(monkeypatch):
    requests = []
    client_settings = []

    def respond(request):
        requests.append(request)
        return httpx.Response(200, text="mock response")

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)

    def mock_client(*, verify, timeout, **kwargs):
        client_settings.append((verify, timeout))
        return real_client(
            transport=transport, verify=verify, timeout=timeout, **kwargs
        )

    monkeypatch.setattr(helper.httpx, "Client", mock_client)
    return requests, client_settings


@pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
)
def test_make_request_accepts_sdk_methods(http_calls, method):
    requests, _ = http_calls
    params = MakeRequestParams(http_method=method, endpoint="/apks/")
    asset = SimpleNamespace(api_key="mock-key", verify_server_cert=True)

    output = make_request.__wrapped__(params, asset)

    assert [request.method for request in requests] == [method]
    assert output.model_dump(by_alias=True) == {
        "status_code": 200,
        "response": "mock response",
    }


def test_make_request_forwards_options_and_merges_query(http_calls):
    requests, client_settings = http_calls
    asset = SimpleNamespace(api_key="mock-key", verify_server_cert=True)
    params = MakeRequestParams(
        endpoint="/apks/?search=endpoint",
        http_method="post",
        query_parameters="search=input&blank=",
        headers='{"X-Request-ID": "test"}',
        body='{"comment": "test comment"}',
        timeout=7,
        verify_ssl=False,
    )

    make_request.__wrapped__(params, asset)

    [sent] = requests
    assert sent.method == "POST"
    assert sent.url.host == "developer.koodous.com"
    assert sent.url.params.get_list("search") == ["endpoint", "input"]
    assert sent.url.params["blank"] == ""
    assert sent.headers["Authorization"] == "Token mock-key"
    assert sent.headers["X-Request-ID"] == "test"
    assert sent.headers["Content-Type"] == "application/json"
    assert json.loads(sent.content) == {"comment": "test comment"}
    assert client_settings == [(False, 7)]


def test_make_request_defaults_to_get_and_asset_tls_setting(http_calls):
    requests, client_settings = http_calls
    asset = SimpleNamespace(api_key="mock-key", verify_server_cert=False)

    make_request.__wrapped__(MakeRequestParams(endpoint="/apks/"), asset)

    assert [request.method for request in requests] == ["GET"]
    assert client_settings == [(False, 30)]


@pytest.mark.parametrize(
    ("params", "message"),
    [
        ({"http_method": "TRACE"}, "http_method must be one of"),
        ({"headers": "{"}, "headers must contain a valid JSON object"),
        ({"headers": "[]"}, "headers must be a JSON object"),
        ({"headers": '{"X-Request-ID": 1}'}, "headers must contain only string values"),
        ({"headers": '{"authorization": "test"}'}, "Authorization header"),
        ({"body": "{"}, "body must contain a valid JSON object"),
        ({"body": "[]"}, "body must be a JSON object"),
        ({"timeout": 0}, "timeout must be a positive number"),
    ],
)
def test_make_request_rejects_invalid_options_without_sending(
    http_calls, params, message
):
    requests, _ = http_calls
    asset = SimpleNamespace(api_key="mock-key", verify_server_cert=True)

    with pytest.raises(ActionFailure, match=message):
        make_request.__wrapped__(MakeRequestParams(endpoint="/apks/", **params), asset)

    assert requests == []
