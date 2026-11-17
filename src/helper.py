# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Shared Koodous API operations."""

import time
from typing import Any
from urllib.parse import urlsplit

import httpx
from soar_sdk.auth import StaticTokenAuth

BASE_URL = "https://developer.koodous.com"


def request(
    asset: Any,
    method: str,
    endpoint: str,
    *,
    return_response: bool = False,
    **kwargs: Any,
) -> Any:
    """Send an API request, authenticating only requests to Koodous."""
    parsed_endpoint = urlsplit(endpoint)
    is_absolute_url = bool(parsed_endpoint.scheme or parsed_endpoint.netloc)
    if is_absolute_url and (
        parsed_endpoint.scheme.lower() not in {"http", "https"}
        or not parsed_endpoint.netloc
    ):
        raise ValueError("Only absolute HTTP or HTTPS URLs are supported")
    url = endpoint if is_absolute_url else BASE_URL + endpoint
    auth = (
        None if is_absolute_url else StaticTokenAuth(asset.api_key, token_type="Token")  # noqa: S106
    )
    with httpx.Client(
        verify=asset.verify_server_cert,
        timeout=30,
        auth=auth,
        follow_redirects=True,
    ) as client:
        response = client.request(
            method,
            url,
            **kwargs,
        )
    if response.status_code == 405:
        return response if return_response else {}
    if response.status_code == 409:
        raise ValueError("This file has already been uploaded")
    if response.status_code == 415:
        raise ValueError("This is not an APK file")
    if response.status_code >= 399:
        raise ValueError(
            f"Koodous API returned HTTP {response.status_code}: {response.text}"
        )
    if return_response:
        return response
    return response.json() if response.content else {}


def report(
    asset: Any,
    soar: Any,
    sha256: str,
    attempts: int = 1,
    analysis_type: str = "all",
    last_yara_analysis_at: str | None = None,
) -> tuple[dict, dict, bool]:
    """Poll a file report and return overview and optional analysis."""
    overview: dict = {}
    analysis: dict = {}
    complete = False
    for index in range(attempts):
        overview = request(asset, "GET", f"/apks/{sha256}")
        if analysis_type == "yara":
            complete = overview.get("last_yara_analysis_at") != last_yara_analysis_at
        elif analysis_type in {"static", "dynamic"}:
            complete = bool(overview.get(f"is_{analysis_type}_analyzed"))
        else:
            complete = bool(
                overview.get("is_static_analyzed")
                or overview.get("is_dynamic_analyzed")
            )
        if complete:
            analysis = request(asset, "GET", f"/apks/{sha256}/analysis")
            break
        if index < attempts - 1:
            soar.set_message(
                f"Polling for report, on attempt {index + 1} of {attempts}"
            )
            time.sleep(30)
    return overview, analysis, complete
