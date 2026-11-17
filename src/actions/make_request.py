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
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import request


class MakeRequestParams(Params):
    endpoint: str = Param(
        description="Relative Koodous API path, for example /apks",
        required=True,
        primary=True,
    )
    query_parameters: str | None = Param(
        description="Optional query parameters as a JSON object or query string"
    )


class MakeRequestOutput(ActionOutput):
    response: str = OutputField()


@app.action(
    description="Make a read-only GET request to the Koodous API",
    action_type="investigate",
    read_only=True,
)
def make_request(
    params: MakeRequestParams, soar: SOARClient, asset: Asset
) -> MakeRequestOutput:
    """Query a relative Koodous API path and return the response as JSON."""
    endpoint = params.endpoint.strip()
    parsed_endpoint = urlsplit(endpoint)
    if parsed_endpoint.scheme or parsed_endpoint.netloc:
        raise ValueError("endpoint must be a relative Koodous API path")
    path = parsed_endpoint.path
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("endpoint path must begin with a single '/'")
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("endpoint must remain within the Koodous API")
    query_parameters = parse_qsl(parsed_endpoint.query, keep_blank_values=True)
    extra_query_parameters = params.query_parameters or ""
    if extra_query_parameters.lstrip().startswith("{"):
        try:
            extra_query = json.loads(extra_query_parameters)
        except json.JSONDecodeError as error:
            raise ValueError(
                "query_parameters must be a JSON object or query string"
            ) from error
        if not isinstance(extra_query, dict):
            raise ValueError("query_parameters must be a JSON object")
        query_parameters.extend(extra_query.items())
    else:
        query_parameters.extend(
            parse_qsl(extra_query_parameters.lstrip("?"), keep_blank_values=True)
        )
    # Put both sources in `params` so repeated keys survive HTTPX's URL parameter merge.
    request_endpoint = urlunsplit(("", "", path, "", ""))
    result = request(asset, "GET", request_endpoint, params=query_parameters)
    soar.set_message("Koodous API request completed")
    return MakeRequestOutput(response=json.dumps(result, ensure_ascii=False))
