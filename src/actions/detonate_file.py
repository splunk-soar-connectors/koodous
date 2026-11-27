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
"""Detonate file action."""

from json import JSONDecodeError
from typing import Any

from httpx2 import RequestError
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import (
    ActionOutput,
    ActionResult,
    OutputField,
    PermissiveActionOutput,
)
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import (
    fetch_analysis,
    normalize_attempts,
    poll_overview,
    request,
    response_data,
)


class DetonateFileParams(Params):
    vault_id: str = Param(
        description="Vault ID of file to detonate",
        primary=True,
        cef_types=["vault id", "sha1"],
    )
    analysis_type: str = Param(
        description="Type of analysis",
        required=False,
        default="all",
        value_list=["static", "dynamic", "yara", "all"],
    )
    attempts: int = Param(
        description="Number of attempts to make while polling",
        required=False,
        default=10,
    )
    force_yara_analysis: bool | None = Param(
        description="Perform Yara analysis", default=False
    )

    def __init__(self, **data: Any) -> None:
        if "attempts" in data:
            data["attempts"] = normalize_attempts(data["attempts"])
        if data.get("force_yara_analysis") == "":
            data["force_yara_analysis"] = False
        super().__init__(**data)


class ApiKeyOutput(ActionOutput):
    com__startapp__sdk__APPLICATION_ID: str = OutputField(
        alias="com::startapp::sdk::APPLICATION_ID"
    )
    com__startapp__sdk__RETURN_ADS_ENABLED: str = OutputField(
        example_values=["true"], alias="com::startapp::sdk::RETURN_ADS_ENABLED"
    )
    metrica_api_level: str = OutputField(
        example_values=["62"], alias="metrica:api:level"
    )
    metrica_configuration_api_level: str = OutputField(
        example_values=["1"], alias="metrica:configuration:api:level"
    )
    required_amazon_package_com__amazon__application__compatibility__enforcer__sdk__library: str = OutputField(
        example_values=["19000"],
        alias="required_amazon_package:com::amazon::application::compatibility::enforcer::sdk::library",
    )
    required_amazon_package_com__amazon__device__messaging__sdk__library: str = OutputField(
        example_values=["2074700"],
        alias="required_amazon_package:com::amazon::device::messaging::sdk::library",
    )


class CertificateOutput(ActionOutput):
    issuerDN: str = OutputField(
        example_values=[
            "/C=NO/ST=Oslo/L=Oslo/O=Opera Software ASA/OU=Opera Mini/CN=Opera Android CA"
        ]
    )
    not_after: str = OutputField(example_values=["May 25 08:27:16 2114 GMT"])
    not_before: str = OutputField(example_values=["Jun 18 08:27:16 2014 GMT"])
    serial: str = OutputField(
        cef_types=["sha1"], example_values=["testtestE07403744EF8827071A939D3testtest"]
    )
    sha1: str = OutputField(
        cef_types=["sha1"], example_values=["testtestE07403744EF8827071A939D3testtest"]
    )
    subjectDN: str = OutputField(
        example_values=[
            "/C=NO/ST=Oslo/L=Oslo/O=Opera Software ASA/OU=Opera Mini/CN=Opera Android CA"
        ]
    )


class ClassesOutput(ActionOutput):
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "testtest45822f127329747ebc545fec8ca33301a1416a8e0e714e0ctesttest"
        ],
    )
    ssdeep: str = OutputField(
        example_values=[
            "98304:ncDdVScJfr4RBrv2yP+KdFi+mNUsQBbaju6hEeRxQ:ncp0wfr4RBrv2yP+KdY+iUsDtesttest"
        ]
    )


class Classes2Output(ActionOutput):
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "7f857344077ffc64899cf60bdf1dbef9776250d55f803e9a23831da7testtest"
        ],
    )
    ssdeep: str = OutputField(
        example_values=[
            "24576:Zmh4ZRdgplwdv4X5l5mE1RQ32WpQMzMAlgHz87OUsDvp8+UTVNFkxApmkwOvS:bRQlG4X8P2WpQ0MAlgTtesttest"
        ]
    )


class DexesOutput(ActionOutput):
    classes: ClassesOutput
    classes2: Classes2Output


class SmsOutput(ActionOutput):
    class_: str = OutputField(
        example_values=["Lcom/admarvel/android/ads/Utils;"], alias="class"
    )
    code: str = OutputField(example_values=["const-string v5, 'sms_body'"])
    method: str = OutputField(example_values=["a"])


class AdsOutput(ActionOutput):
    class_: str = OutputField(example_values=["Laje$3;"], alias="class")
    code: str = OutputField(example_values=["const-string v5, 'AdMob error code: '"])
    method: str = OutputField(example_values=["onAdFailedToLoad"])


class CameraOutput(ActionOutput):
    class_: str = OutputField(
        example_values=["Lcom/opera/android/custom_views/GenericCameraView;"],
        alias="class",
    )
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, v1, Landroid/hardware/Camera;->setPreviewDisplay(Landroid/view/SurfaceHolder;)V"
        ]
    )
    method: str = OutputField(example_values=["b"])


class CryptoOutput(ActionOutput):
    class_: str = OutputField(example_values=["Labe;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, v1, Ljava/security/MessageDigest;->digest([B)[B"
        ]
    )
    method: str = OutputField(example_values=["e"])


class DynamicbroadcastreceiverOutput(ActionOutput):
    class_: str = OutputField(example_values=["Labv;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-virtual v1, v2, v3, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver; Landroid/content/IntentFilter;)Landroid/content/Intent;"
        ]
    )
    method: str = OutputField(example_values=["g"])


class IccidOutput(ActionOutput):
    class_: str = OutputField(
        example_values=["Lcom/apprupt/sdk/CvAppInfo;"], alias="class"
    )
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, Landroid/telephony/TelephonyManager;->getSimSerialNumber()Ljava/lang/String;"
        ]
    )
    method: str = OutputField(example_values=["obtainTelephonyIds"])


class ImeiOutput(ActionOutput):
    class_: str = OutputField(example_values=["Lafo;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;"
        ]
    )
    method: str = OutputField(example_values=["e"])


class ImsiOutput(ActionOutput):
    class_: str = OutputField(example_values=["Lafo;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, Landroid/telephony/TelephonyManager;->getSubscriberId()Ljava/lang/String;"
        ]
    )
    method: str = OutputField(example_values=["f"])


class InstalledapplicationsOutput(ActionOutput):
    class_: str = OutputField(
        example_values=["Lcom/my/target/core/parsers/b;"], alias="class"
    )
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, v1, Landroid/content/pm/PackageManager;->getInstalledApplications(I)Ljava/util/List;"
        ]
    )
    method: str = OutputField(example_values=["a"])


class MccOutput(ActionOutput):
    class_: str = OutputField(example_values=["Ladp;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, Landroid/telephony/TelephonyManager;->getNetworkOperator()Ljava/lang/String;"
        ]
    )
    method: str = OutputField(example_values=["f"])


class PhonecallOutput(ActionOutput):
    class_: str = OutputField(example_values=["Lair;"], alias="class")
    code: str = OutputField(
        example_values=["const-string v1, 'android.intent.action.CALL'"]
    )
    method: str = OutputField(example_values=["a"])


class PhonenumberOutput(ActionOutput):
    class_: str = OutputField(example_values=["Lafo;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-virtual v0, Landroid/telephony/TelephonyManager;->getLine1Number()Ljava/lang/String;"
        ]
    )
    method: str = OutputField(example_values=["d"])


class RunbinaryOutput(ActionOutput):
    class_: str = OutputField(example_values=["Laay;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-static Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;"
        ]
    )
    method: str = OutputField(example_values=["a"])


class SerialnoOutput(ActionOutput):
    class_: str = OutputField(example_values=["Lafo;"], alias="class")
    code: str = OutputField(example_values=["const-string v3, 'ro.serialno'"])
    method: str = OutputField(example_values=["<clinit>"])


class SocketOutput(ActionOutput):
    class_: str = OutputField(example_values=["Labv;"], alias="class")
    code: str = OutputField(
        example_values=[
            "invoke-virtual v11, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;"
        ]
    )
    method: str = OutputField(example_values=["a"])


class SslOutput(ActionOutput):
    class_: str = OutputField(example_values=["La;"], alias="class")
    code: str = OutputField(example_values=["const-string v0, 'https://www.test.us/'"])
    method: str = OutputField(example_values=["b"])


class FunctionalitiesOutput(ActionOutput):
    SMS: list[SmsOutput]
    ads: list[AdsOutput]
    camera: list[CameraOutput]
    crypto: list[CryptoOutput]
    dynamicbroadcastreceiver: list[DynamicbroadcastreceiverOutput]
    iccid: list[IccidOutput]
    imei: list[ImeiOutput]
    imsi: list[ImsiOutput]
    installedapplications: list[InstalledapplicationsOutput]
    mcc: list[MccOutput]
    phonecall: list[PhonecallOutput]
    phonenumber: list[PhonenumberOutput]
    runbinary: list[RunbinaryOutput]
    serialno: list[SerialnoOutput]
    socket: list[SocketOutput]
    ssl: list[SslOutput]


class AndroguardOutput(ActionOutput):
    activities: str = OutputField(example_values=["com.test.msdk.shell.MVActivity"])
    androidtv: bool
    api_key: ApiKeyOutput
    app_name: str = OutputField(example_values=["Test app"])
    certificate: CertificateOutput
    cordova: str
    dexes: DexesOutput
    displayed_version: str = OutputField(example_values=["32.0.2254.123747"])
    filters: str = OutputField(example_values=["android.intent.action.PACKAGE_REMOVED"])
    functionalities: FunctionalitiesOutput
    main_activity: str = OutputField(example_values=["com.test.mini.abc.Browser"])
    max_sdk_version: str
    min_sdk_version: int = OutputField(example_values=[16])
    new_permissions: str = OutputField(
        example_values=["com.test.abc.native.permission.C2D_MESSAGE"]
    )
    package_name: str = OutputField(example_values=["com.test.abc.native"])
    permissions: str = OutputField(example_values=["android.permission.NFC"])
    providers: str = OutputField(
        example_values=[
            "com.test.android.news.newsfeed.internal.cache.NewsfeedContentProvider"
        ]
    )
    receivers: str = OutputField(
        example_values=["com.test.abc.gcm.GcmBroadcastReceiver"]
    )
    services: str = OutputField(
        example_values=["com.test.abc.ping.SyncAuthenticatorService"]
    )
    signature_name: str = OutputField(example_values=["META-INF/ANDROID.RSA"])
    target_sdk_version: int = OutputField(example_values=[25])
    urls: str = OutputField(cef_types=["url"], example_values=["https://www.test.us/"])
    version_code: str = OutputField(example_values=["321123747"])
    wearable: bool


class FileOutput(ActionOutput):
    name: str = OutputField(example_values=["application.apk"])
    path: str = OutputField(example_values=["/vault/application.apk"])
    type: str = OutputField(example_values=["APK"])
    crc32: str = OutputField(example_values=["5BCCD162"])
    md5: str = OutputField(
        cef_types=["md5"], example_values=["testf1954c84f386554b741f5737test"]
    )
    sha1: str = OutputField(
        cef_types=["sha1"], example_values=["test294cd5bac77e93e41493bd69b42705e2test"]
    )
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "testa95ec1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc28478aftest"
        ],
    )
    sha512: str = OutputField(
        example_values=[
            "test989f8d8a4726bbc8ef61bbc73a855461d4897c2c43cdacd847f3901069d8ac230e6c80da67525e0ed94e3f8449f56520a7a6e143f8314ca08671308ctest"
        ]
    )
    size: int = OutputField(example_values=[7544622])
    ssdeep: str = OutputField(
        example_values=[
            "196608:XX3GmbVoah5KRFtOHuPtEpT2q0XlfoJ82lCIOYb7hoI:2mbrh5M0HuPST2RVfQ8NIOGj"
        ]
    )


class TargetOutput(ActionOutput):
    category: str = OutputField(example_values=["file"])
    file: FileOutput


class CuckooOutput(ActionOutput):
    category: str = OutputField(example_values=["file"])
    file: FileOutput
    file_id: str
    target: TargetOutput


class CryptousageOutput(ActionOutput):
    algorithm: str = OutputField(example_values=["base64_decode"])
    data: str
    processname: str = OutputField(example_values=["eu.toralarm.toralarm_wm"])
    tid: int = OutputField(example_values=[5133])
    time: float = OutputField(example_values=[123.2289459705353])


class DexclassOutput(ActionOutput):
    path: str = OutputField(example_values=["/data/app/io.selendroid.testapp-1.apk"])
    pid: int = OutputField(example_values=[843])
    processname: str = OutputField(example_values=["io.selendroid.testapp"])
    tid: int = OutputField(example_values=[1073870640])
    time: float = OutputField(example_values=[0.212098])


class DnsOutput(ActionOutput):
    domain: str = OutputField(example_values=["rules.addapptr.com"])
    hostname: str = OutputField(example_values=["rules.addapptr.com"])
    ip: str = OutputField(example_values=["151.80.27.93"])


class FilesdeletedOutput(ActionOutput):
    name: str = OutputField(
        example_values=[
            "/data/app/com.test.app860056677872.rr-M42In0rnQNzdiDmPkpQy0A==/base.apk.x86_64.flock"
        ]
    )
    pid: int = OutputField(cef_types=["pid"], example_values=[4248])
    processname: str = OutputField(example_values=["com.test.app860056677872.rr"])
    tid: int = OutputField(example_values=[4248])
    time: float = OutputField(example_values=[121.2224400043488])


class FilesopenOutput(ActionOutput):
    name: str = OutputField(example_values=["/proc/self/cmdline"])
    pid: int = OutputField(cef_types=["pid"], example_values=[4248])
    processname: str = OutputField(example_values=["com.test.app860056677872.rr"])
    tid: int = OutputField(example_values=[4248])
    time: float = OutputField(example_values=[121.2202398777008])


class FilesreadOutput(ActionOutput):
    data: str
    name: str = OutputField(example_values=["/data/app/io.selendroid.testapp-1.apk"])
    pid: int = OutputField(cef_types=["pid"], example_values=[4248])
    processname: str = OutputField(example_values=["com.mobeasyapp.app860056677872.rr"])
    tid: int = OutputField(example_values=[4248])
    time: float = OutputField(example_values=[121.220575094223])


class FileswrittenOutput(ActionOutput):
    data: str
    name: str = OutputField(
        example_values=[
            "/data/user/0/com.test.app860056677872.rr/files/audience_network.dex"
        ]
    )
    pid: int = OutputField(cef_types=["pid"], example_values=[4248])
    processname: str = OutputField(example_values=["com.test.app860056677872.rr"])
    tid: int = OutputField(example_values=[5159])
    time: float = OutputField(example_values=[121.2951688766479])


class LibrariesOutput(ActionOutput):
    name: str = OutputField(example_values=["monochrome_base"])
    pid: int = OutputField(example_values=[5133])
    processname: str = OutputField(example_values=["eu.toralarm.toralarm_wm"])
    tid: int = OutputField(example_values=[5133])
    time: float = OutputField(example_values=[122.8014578819275])


class RecvnetOutput(ActionOutput):
    data: str = OutputField(example_values=["1603030058"])
    pid: int = OutputField(example_values=[5133])
    processname: str = OutputField(example_values=["eu.toralarm.toralarm_wm"])
    srchost: str = OutputField(example_values=["54.36.175.146"])
    srcport: int = OutputField(example_values=[443])
    tid: int = OutputField(example_values=[6224])
    time: float = OutputField(example_values=[124.5965847969055])


class SendnetOutput(ActionOutput):
    data: str
    desthost: str = OutputField(example_values=["185.86.138.16"])
    destport: int = OutputField(example_values=[80])
    pid: int = OutputField(example_values=[5133])
    processname: str = OutputField(example_values=["eu.toralarm.toralarm_wm"])
    tid: int = OutputField(example_values=[6239])
    time: float = OutputField(example_values=[125.5912230014801])


class DroidboxOutput(ActionOutput):
    cryptousage: list[CryptousageOutput]
    dexclass: list[DexclassOutput]
    dns: list[DnsOutput]
    filesdeleted: list[FilesdeletedOutput]
    filesopen: list[FilesopenOutput]
    filesread: list[FilesreadOutput]
    fileswritten: list[FileswrittenOutput]
    libraries: list[LibrariesOutput]
    recvnet: list[RecvnetOutput]
    sendnet: list[SendnetOutput]


class AnalysisOutput(PermissiveActionOutput):
    androguard: AndroguardOutput | None = None
    cuckoo: CuckooOutput | None = None
    # Koodous' current API calls this report section "dynamic". Retain "droidbox"
    # as an optional legacy key so older report payloads remain representable.
    dynamic: DroidboxOutput | None = None
    droidbox: DroidboxOutput | None = None
    scanning_date: str = OutputField(example_values=["2018-01-04T22:15:07.627000"])
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "testa95ec1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc28478aftest"
        ],
    )
    status: str = OutputField(example_values=["analyzed"])


class OverviewOutput(PermissiveActionOutput):
    analyzed: bool | None = None
    app: str | None = OutputField(example_values=["Test app"])
    comments_count: int = OutputField(example_values=[0])
    company: str = OutputField(example_values=["Test Software ASA"])
    corrupted: bool | None = None
    created_at: str = OutputField(example_values=["2022-06-13T10:32:12.772734+02:00"])
    created_on: int = OutputField(example_values=[1515099685])
    detected: bool | None = None
    displayed_version: str = OutputField(example_values=["32.0.2254.123747"])
    id: str = OutputField(example_values=["Lv8ydaXWQ4WOEQ3q"])
    image: str | None = OutputField(
        cef_types=["url"],
        example_values=[
            "https://test.abc.com/media/apk_images/2022/06/13/logo_o8aYRh9.png"
        ],
    )
    is_apk: bool | None = None
    is_corrupted: bool = OutputField(example_values=[False, True])
    is_detected: bool = OutputField(example_values=[False, True])
    is_dynamic_analyzed: bool | None = None
    is_installed: bool = OutputField(example_values=[False, True])
    is_static_analyzed: bool | None = None
    is_trusted: bool = OutputField(example_values=[False, True])
    last_yara_analysis_at: str | None = OutputField(
        example_values=["2022-06-13T10:52:46.967913+02:00"]
    )
    matches_count: int = OutputField(example_values=[1])
    md5: str = OutputField(
        cef_types=["md5"], example_values=["9b57f1954c84f386554b741ftesttest"]
    )
    on_devices: bool | None = None
    package_name: str | None = OutputField(example_values=["com.test.mini.native"])
    rating: int = OutputField(example_values=[0])
    repo: str | None = None
    sha1: str = OutputField(
        cef_types=["sha1"], example_values=["testtestd5bac77e93e41493bd69b427testtest"]
    )
    sha256: str = OutputField(
        cef_types=["sha256"],
        example_values=[
            "testtest1d9ee65ad14654fd4c4095e3c71fe5b4064fe8b9f6dc284testtest"
        ],
    )
    size: int = OutputField(example_values=[7544622])
    stored: bool | None = None
    tags: list[str] | None = OutputField(example_values=["bad-signed"])
    trusted: bool | None = None
    updated_at: str = OutputField(example_values=["2022-06-13T10:32:12.772757+02:00"])
    url: str = OutputField(
        cef_types=["url"],
        example_values=[
            "https://test.abc.com/apks/test46ada7896b0c93a7a8741f3dbe3135e39b4b07100328b3a4c23b9bb3test/"
        ],
    )
    version: str = OutputField(example_values=["2"])
    votes_count: int = OutputField(example_values=[0])


class DetonateFileOutput(PermissiveActionOutput):
    # Preserve the raw report while declaring its nested SOAR datapaths.
    analysis: AnalysisOutput | None = None
    overview: OverviewOutput


class DetonateFileSummary(ActionOutput):
    sha256: str = OutputField(cef_types=["sha256"])
    analysis_complete: bool


@app.action(
    description="Run the file in the sandbox and retrieve the analysis results",
    action_type="generic",
    read_only=False,
    summary_type=DetonateFileSummary,
    verbose="File detonation may take a while. If the polling in this action doesn't succeed in getting the file analysis (which will be indicated through the <b>analysis_complete</b> key in the summary), then you should continue polling with the <b>get report</b> action. If the <b>analysis_type</b> is 'yara' and <b>force_yara_analysis</b> is false, then the 'yara' analysis will only be performed if it has not been performed before. To perform yara analysis repeatedly, keep <b>force_yara_analysis</b> as true.",
)
def detonate_file(
    params: DetonateFileParams, soar: SOARClient, asset: Asset
) -> DetonateFileOutput:
    attempts = max(1, params.attempts)
    analysis_type = params.analysis_type
    if analysis_type not in {"all", "static", "dynamic", "yara"}:
        raise ActionFailure(
            "Please provide a valid analysis_type: static, dynamic, yara, or all"
        )
    attachments = soar.vault.get_attachment(vault_id=params.vault_id)
    if not attachments:
        raise ValueError("Vault file could not be found with supplied Vault ID")
    attachment = attachments[0]
    if not attachment.name.endswith(".apk"):
        raise ValueError("Please provide a valid apk file")
    sha256 = (attachment.metadata or {}).get("sha256")
    if not sha256:
        raise ActionFailure("Vault attachment is missing its SHA-256 hash")
    overview_response = request(
        asset,
        "GET",
        f"/apks/{sha256}",
        return_response=True,
        retry_rate_limited=True,
    )
    progress = []
    result_data = {}
    fetching_analysis = False
    try:
        if overview_response.status_code == 404:
            upload = request(asset, "GET", f"/apks/{sha256}/get_upload_url")
            with attachment.open("rb") as apk:
                upload_response = request(
                    asset,
                    "POST",
                    upload["upload_url"],
                    files={"file": (attachment.name, apk)},
                    return_response=True,
                )
            response_data(upload_response)
            if upload_response.is_success:
                progress.append("APK upload accepted")
            overview = request(asset, "GET", f"/apks/{sha256}", retry_rate_limited=True)
        else:
            overview = response_data(overview_response)
        result_data["overview"] = overview
        last_yara = overview.get("last_yara_analysis_at")
        requested = {
            "dynamic": analysis_type in {"dynamic", "all"}
            and not overview.get("is_dynamic_analyzed"),
            "static": analysis_type in {"static", "all"}
            and not overview.get("is_static_analyzed"),
            "yara": analysis_type in {"yara", "all"}
            and (params.force_yara_analysis or not last_yara),
        }
        for kind, should_run in requested.items():
            if not should_run:
                continue
            submission_response = request(
                asset,
                "GET",
                f"/apks/{sha256}/analyze_{kind}/",
                return_response=True,
            )
            if submission_response.status_code == 405:
                raise ActionFailure(
                    f"Koodous rejected the {kind} analysis submission (HTTP 405)"
                )
            response_data(submission_response)
            if submission_response.is_success:
                progress.append(f"{kind} analysis submission accepted")
        overview, analysis_complete = poll_overview(
            asset,
            soar,
            sha256,
            attempts,
            analysis_type,
            last_yara_analysis_at=last_yara if requested["yara"] else None,
            on_overview=lambda value: result_data.update(overview=value),
        )
        result_data["overview"] = overview
        fetching_analysis = analysis_complete and analysis_type != "yara"
        if fetching_analysis:
            analysis = fetch_analysis(asset, sha256)
            if analysis:
                result_data["analysis"] = analysis
    except (ActionFailure, RequestError, JSONDecodeError, UnicodeDecodeError) as exc:
        if not progress and not fetching_analysis:
            raise
        message = exc.message if isinstance(exc, ActionFailure) else str(exc)
        if progress:
            message = f"{message.rstrip('.')}. Detonation progress includes {', '.join(progress)}."
    else:
        if analysis_complete:
            soar.set_summary(DetonateFileSummary(sha256=sha256, analysis_complete=True))
            soar.set_message("Successfully retrieved overview and analysis")
            return DetonateFileOutput(**result_data)

        analysis_name = (
            "analysis" if analysis_type == "all" else f"{analysis_type} analysis"
        )
        message = (
            f"Polling attempts were exhausted before the {analysis_name} completed"
        )

    result = ActionResult(
        status=False,
        message=message,
        param=params.model_dump(exclude_unset=True, exclude_none=True),
    )
    if result_data:
        result.add_data(result_data)
    result.set_summary(
        DetonateFileSummary(sha256=sha256, analysis_complete=False).model_dump()
    )
    return result
