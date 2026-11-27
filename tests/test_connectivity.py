# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Response validation for the Koodous connectivity check."""

from unittest.mock import Mock

import httpx2
import pytest
from soar_sdk.exceptions import ActionFailure

from src.app import test_connectivity as check_connectivity
from src.asset import Asset


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (httpx2.Response(200, json={"results": []}), None),
        (httpx2.Response(302), "HTTP 302"),
        (httpx2.Response(405), "HTTP 405"),
        (httpx2.Response(401, json={"detail": "Invalid token"}), "Invalid token"),
        (httpx2.Response(200, html="<html>Sign in</html>"), "JSON APK listing"),
        (httpx2.Response(200, json={}), "JSON APK listing"),
        (httpx2.ConnectError("Connection refused"), "Could not connect to Koodous"),
    ],
)
def test_connectivity_requires_successful_apk_listing(monkeypatch, response, error):
    mock_request = Mock()
    if isinstance(response, httpx2.RequestError):
        mock_request.side_effect = response
    else:
        mock_request.return_value = response
    monkeypatch.setattr("src.app.request", mock_request)
    asset = Asset(api_key="mock-key")
    soar = Mock()

    if error is None:
        check_connectivity.__wrapped__(soar, asset)
        soar.set_message.assert_called_once_with("Test connectivity passed")
    else:
        with pytest.raises(ActionFailure, match=error):
            check_connectivity.__wrapped__(soar, asset)
        soar.set_message.assert_not_called()

    mock_request.assert_called_once_with(
        asset, "GET", "/apks", params={"search": "Whatsapp"}, return_response=True
    )
