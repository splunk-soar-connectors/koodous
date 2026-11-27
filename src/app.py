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
from httpx2 import RequestError
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure

from .actions import register_actions
from .asset import Asset
from .helper import request


app = App(
    name="Koodous",
    app_type="sandbox",
    logo="logo_koodous.svg",
    logo_dark="logo_koodous_dark.svg",
    product_vendor="Koodous",
    product_name="Koodous",
    publisher="Splunk",
    appid="ff79d26f-590e-4158-ad33-1dd073ec10a5",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Verify connectivity by searching Koodous APKs."""
    try:
        response = request(
            asset, "GET", "/apks", params={"search": "Whatsapp"}, return_response=True
        )
    except RequestError as exc:
        raise ActionFailure(f"Could not connect to Koodous: {exc}") from exc

    if not response.is_success:
        raise ActionFailure(
            f"Koodous API returned HTTP {response.status_code}: {response.text}"
        )

    try:
        listing = response.json()
    except ValueError:
        listing = None
    if not isinstance(listing, dict) or not isinstance(listing.get("results"), list):
        raise ActionFailure("Koodous API did not return a JSON APK listing")

    soar.set_message("Test connectivity passed")


register_actions(app)

if __name__ == "__main__":
    app.cli()
