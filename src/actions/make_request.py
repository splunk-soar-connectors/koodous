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
"""Make request action."""

import json
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from soar_sdk.action_results import (
    MakeRequestOutput as SDKMakeRequestOutput,
    OutputField,
)
from soar_sdk.exceptions import ActionFailure
from soar_sdk.field_utils import parse_json_schema_extra
from soar_sdk.params import MakeRequestParams as SDKMakeRequestParams, Param

from ..app import Asset, app
from ..helper import request


SUPPORTED_HTTP_METHODS = parse_json_schema_extra(
    SDKMakeRequestParams.model_fields["http_method"].json_schema_extra
)["value_list"]


class MakeRequestParams(SDKMakeRequestParams):
    http_method: str = Param(
        description=f"HTTP method. Choose from {', '.join(SUPPORTED_HTTP_METHODS)}.",
        required=False,
        default="GET",
        value_list=SUPPORTED_HTTP_METHODS,
    )
    endpoint: str = Param(
        description="Relative Koodous API path, for example /apks",
        required=True,
        primary=True,
    )
    headers: str = Param(
        description='HTTP headers as a JSON object with string values, for example {"Accept": "application/json"}. Authorization uses the asset API key.',
        required=False,
    )
    body: str = Param(
        description='Request body as a JSON object, for example {"key": "value"}.',
        required=False,
    )
    timeout: int = Param(
        description="Request timeout in seconds. Must be positive. Defaults to 30.",
        required=False,
    )
    verify_ssl: bool = Param(
        description="Verify the server certificate. Uses the asset setting when omitted.",
        required=False,
        default=True,
    )


class MakeRequestOutput(SDKMakeRequestOutput):
    response_body: str = OutputField(alias="response")


def _parse_json_object(value: str | None, field_name: str) -> dict[str, Any] | None:
    if not value or not value.strip():
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ActionFailure(f"{field_name} must contain a valid JSON object") from error
    if not isinstance(parsed, dict):
        raise ActionFailure(f"{field_name} must be a JSON object")
    return parsed


@app.make_request()
def make_request(params: MakeRequestParams, asset: Asset) -> MakeRequestOutput:
    """Send an authenticated request to a relative Koodous API path."""
    method = params.http_method.strip().upper()
    if method not in SUPPORTED_HTTP_METHODS:
        raise ActionFailure(
            f"http_method must be one of {', '.join(SUPPORTED_HTTP_METHODS)}"
        )

    endpoint = params.endpoint.strip()
    try:
        parsed_endpoint = urlsplit(endpoint)
    except ValueError as error:
        raise ActionFailure("endpoint must be a relative Koodous API path") from error
    if parsed_endpoint.scheme or parsed_endpoint.netloc:
        raise ActionFailure("endpoint must be a relative Koodous API path")
    path = parsed_endpoint.path
    if not path.startswith("/") or path.startswith("//"):
        raise ActionFailure("endpoint path must begin with a single '/'")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ActionFailure("endpoint must remain within the Koodous API")
    query_parameters = parse_qsl(parsed_endpoint.query, keep_blank_values=True)
    extra_query_parameters = params.query_parameters or ""
    if extra_query_parameters.lstrip().startswith(("{", "[")):
        try:
            extra_query = json.loads(extra_query_parameters)
        except json.JSONDecodeError as error:
            raise ActionFailure(
                "query_parameters must be a JSON object or query string"
            ) from error
        if not isinstance(extra_query, dict):
            raise ActionFailure("query_parameters must be a JSON object")
        for key, value in extra_query.items():
            values = value if isinstance(value, list) else [value]
            if any(isinstance(item, dict | list) for item in values):
                raise ActionFailure(
                    "query_parameters values must be scalars or arrays of scalars"
                )
            query_parameters.extend((key, item) for item in values)
    else:
        query_parameters.extend(
            parse_qsl(extra_query_parameters.lstrip("?"), keep_blank_values=True)
        )

    headers = _parse_json_object(params.headers, "headers")
    if headers is not None:
        if any(not isinstance(value, str) for value in headers.values()):
            raise ActionFailure("headers must contain only string values")
        if any(name.lower() == "authorization" for name in headers):
            raise ActionFailure(
                "The Authorization header is set from the asset API key"
            )

    body = _parse_json_object(params.body, "body")
    if params.timeout is not None and params.timeout <= 0:
        raise ActionFailure("timeout must be a positive number of seconds")
    verify_ssl = params.verify_ssl if "verify_ssl" in params.model_fields_set else None

    # Put both sources in `params` so repeated keys survive HTTPX's URL parameter merge.
    request_endpoint = urlunsplit(("", "", path, "", ""))
    response = request(
        asset,
        method,
        request_endpoint,
        headers=headers,
        json=body,
        params=query_parameters,
        timeout=params.timeout,
        verify_ssl=verify_ssl,
        return_response=True,
    )
    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )
