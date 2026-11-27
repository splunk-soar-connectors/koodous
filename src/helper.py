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

import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx2
from soar_sdk.auth import StaticTokenAuth
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import progress

BASE_URL = "https://developer.koodous.com"
MAX_PROGRESS_SILENCE_SECONDS = 240
MAX_AUTOMATIC_RATE_LIMIT_WAIT_SECONDS = 240


def normalize_attempts(attempts: Any) -> Any:
    """Truncate numeric floats and accept only integer strings as in the legacy app."""
    if isinstance(attempts, float | str):
        try:
            return int(attempts)
        except (OverflowError, ValueError) as error:
            raise ValueError(
                "attempts must be a finite number or an integer string"
            ) from error
    return attempts


def _retry_after_seconds(response: httpx2.Response) -> float | None:
    """Read a numeric Retry-After value or Koodous' throttling detail."""
    retry_after = response.headers.get("Retry-After")
    if retry_after is not None:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass
    match = re.search(
        r"Expected available in\s+(\d+(?:\.\d+)?)\s+seconds?",
        response.text,
        re.IGNORECASE,
    )
    return float(match.group(1)) if match else None


def _sleep_with_progress(seconds: float, message: str) -> None:
    """Wait in bounded intervals and report progress to keep SOAR IPC active."""
    remaining = max(0.0, seconds)
    while remaining > 0:
        progress(f"{message}; waiting {remaining:.0f} seconds")
        sleep_interval = min(remaining, MAX_PROGRESS_SILENCE_SECONDS)
        time.sleep(sleep_interval)
        remaining -= sleep_interval


def response_data(response: httpx2.Response) -> Any:
    """Return a successful response body or raise the SDK's action failure."""
    if response.status_code == 405:
        return {}
    if response.status_code == 409:
        raise ActionFailure("This file has already been uploaded")
    if response.status_code == 415:
        raise ActionFailure("This is not an APK file")
    if response.status_code >= 399:
        raise ActionFailure(
            f"Koodous API returned HTTP {response.status_code}: {response.text}"
        )
    return response.json() if response.content else {}


def request(
    asset: Any,
    method: str,
    endpoint: str,
    *,
    return_response: bool = False,
    retry_rate_limited: bool = False,
    timeout: int | None = None,
    verify_ssl: bool | None = None,
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
    retries = 0
    while True:
        with httpx2.Client(
            verify=asset.verify_server_cert if verify_ssl is None else verify_ssl,
            timeout=30 if timeout is None else timeout,
            auth=auth,
            follow_redirects=True,
        ) as client:
            response = client.request(
                method,
                url,
                **kwargs,
            )
        if (
            retry_rate_limited
            and method.upper() == "GET"
            and response.status_code == 429
            and retries == 0
        ):
            delay = _retry_after_seconds(response)
            if delay is not None and delay <= MAX_AUTOMATIC_RATE_LIMIT_WAIT_SECONDS:
                _sleep_with_progress(delay, "Koodous rate limit; retrying the request")
                retries += 1
                continue
        break
    if return_response:
        return response
    return response_data(response)


def fetch_analysis(asset: Any, sha256: str) -> dict:
    response = request(
        asset,
        "GET",
        f"/apks/{sha256}/analysis",
        return_response=True,
        retry_rate_limited=True,
    )
    if response.status_code == 405:
        raise ActionFailure("Koodous rejected the analysis report fetch (HTTP 405)")
    return response_data(response)


def poll_overview(
    asset: Any,
    soar: Any,
    sha256: str,
    attempts: int = 1,
    analysis_type: str = "all",
    last_yara_analysis_at: str | None = None,
    *,
    on_overview: Callable[[dict], None] | None = None,
) -> tuple[dict, bool]:
    """Poll APK details until the requested analysis is ready."""
    overview: dict = {}
    complete = False
    for index in range(attempts):
        overview = request(asset, "GET", f"/apks/{sha256}", retry_rate_limited=True)
        if on_overview is not None and overview:
            on_overview(overview)
        if analysis_type == "yara":
            timestamp = overview.get("last_yara_analysis_at")
            if timestamp and timestamp != last_yara_analysis_at:
                return overview, True
        elif analysis_type in {"static", "dynamic"}:
            complete = bool(overview.get(f"is_{analysis_type}_analyzed"))
        else:
            complete = bool(
                overview.get("is_static_analyzed")
                or overview.get("is_dynamic_analyzed")
            )
        if complete:
            break
        if index < attempts - 1:
            message = f"Polling for report, on attempt {index + 1} of {attempts}"
            soar.set_message(message)
            _sleep_with_progress(30, message)
    return overview, complete
