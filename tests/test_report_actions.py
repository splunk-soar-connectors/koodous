"""Mocked API coverage for Koodous report output serialization."""

from __future__ import annotations

import io
from types import SimpleNamespace

import httpx
import pytest
from soar_sdk.action_results import PermissiveActionOutput
from soar_sdk.app import App
from soar_sdk.exceptions import ActionFailure

from src import helper
from src.actions.detonate_file import DetonateFileParams, detonate_file
from src.actions.get_report import GetReportParams, get_report

SHA256 = "a" * 64


def _api_payloads() -> tuple[dict, dict]:
    overview = {
        "sha256": SHA256,
        "is_static_analyzed": True,
        "is_dynamic_analyzed": True,
        "last_yara_analysis_at": "2026-11-18T10:00:00Z",
        "app": "Mock APK",
        "extra_overview_field": {"preserved": True},
    }
    # Deliberately sparse and irregular nested values emulate variable report
    # sections from Koodous while checking that the SDK output path keeps them.
    analysis = {
        "sha256": SHA256,
        "status": "analyzed",
        "androguard": {
            "app_name": {"unexpected": "object instead of string"},
            "api_key": "unexpected scalar instead of object",
            "unmodeled_section": {"preserved": True},
        },
        "dynamic": {
            "recvnet": [
                {"time": "not-a-float", "unmodeled_field": [1, 2, 3]},
            ],
            "unmodeled_section": "preserved",
        },
        "unmodeled_analysis_field": {"preserved": True},
    }
    return overview, analysis


def _install_mock_api(
    monkeypatch, overview: dict, analysis: dict
) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    transport = httpx.MockTransport(
        lambda request: _mock_response(request, overview, analysis, calls)
    )
    real_client = httpx.Client

    def client_with_mock_transport(**kwargs):
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(helper.httpx, "Client", client_with_mock_transport)
    return calls


def _install_case_api(
    monkeypatch,
    overview_responses: dict[str, list[dict]],
    analyses: dict[str, dict],
) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    response_indexes: dict[str, int] = {}
    transport = httpx.MockTransport(
        lambda request: _case_response(
            request, overview_responses, analyses, response_indexes, calls
        )
    )
    real_client = httpx.Client

    def client_with_mock_transport(**kwargs):
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(helper.httpx, "Client", client_with_mock_transport)
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    return calls


def _case_response(
    request: httpx.Request,
    overview_responses: dict[str, list[dict]],
    analyses: dict[str, dict],
    response_indexes: dict[str, int],
    calls: list[tuple[str, str]],
) -> httpx.Response:
    calls.append((request.method, request.url.path))
    path_parts = request.url.path.strip("/").split("/")
    match request.method, path_parts:
        case "POST", ["apks", sha256, "analyze_yara"] if sha256 in overview_responses:
            return httpx.Response(204)
        case "GET", ["apks", sha256, "analysis"] if sha256 in analyses:
            return httpx.Response(200, json=analyses[sha256])
        case "GET", ["apks", sha256] if sha256 in overview_responses:
            responses = overview_responses[sha256]
            index = response_indexes.get(sha256, 0)
            response_indexes[sha256] = index + 1
            return httpx.Response(200, json=responses[min(index, len(responses) - 1)])
    return httpx.Response(404, json={"detail": "Unexpected mocked endpoint"})


def _mock_response(
    request: httpx.Request,
    overview: dict,
    analysis: dict,
    calls: list[tuple[str, str]],
) -> httpx.Response:
    calls.append((request.method, request.url.path))
    if request.url.path == f"/apks/{SHA256}":
        return httpx.Response(200, json=overview)
    if request.url.path == f"/apks/{SHA256}/analysis":
        return httpx.Response(200, json=analysis)
    return httpx.Response(404, json={"detail": "Unexpected mocked endpoint"})


def _asset() -> SimpleNamespace:
    return SimpleNamespace(api_key="mock-token", verify_server_cert=True)


def _soar() -> SimpleNamespace:
    soar = SimpleNamespace(message="", summary=None)
    soar.set_message = lambda message: setattr(soar, "message", message)
    soar.set_summary = lambda summary: setattr(soar, "summary", summary)
    return soar


def _attachment(sha256: str) -> SimpleNamespace:
    return SimpleNamespace(
        name="mock.apk",
        metadata={"sha256": sha256},
        hash=sha256,
        open=lambda _mode: io.BytesIO(b"mock apk bytes"),
    )


def _run_action(action, params, soar, *, success=True) -> object:
    output = action.__wrapped__(params, soar, _asset())
    if success:
        assert isinstance(output, PermissiveActionOutput)
    added_results = []
    status = App._adapt_action_result(
        output,
        SimpleNamespace(add_result=added_results.append),
        params,
        message=soar.message,
        summary=soar.summary,
    )
    assert status is success
    assert len(added_results) == 1
    return added_results[0]


def test_get_report_preserves_irregular_mocked_analysis(monkeypatch) -> None:
    overview, analysis = _api_payloads()
    calls = _install_mock_api(monkeypatch, overview, analysis)

    output = _run_action(
        get_report, GetReportParams(sha256=SHA256, attempts=1), _soar()
    )

    assert output.get_status() is True
    assert output.get_data() == [{"overview": overview, "analysis": analysis}]
    assert output.get_summary() == {"sha256": SHA256, "analysis_complete": True}
    assert output.get_message() == "Successfully retrieved overview and analysis"
    assert calls == [
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}/analysis"),
    ]


def test_detonate_file_preserves_irregular_mocked_analysis(monkeypatch) -> None:
    overview, analysis = _api_payloads()
    calls = _install_mock_api(monkeypatch, overview, analysis)
    attachment = SimpleNamespace(
        name="mock.apk",
        metadata={"sha256": SHA256},
        hash=SHA256,
        open=lambda _mode: io.BytesIO(b"mock apk bytes"),
    )
    soar = _soar()
    soar.vault = SimpleNamespace(get_attachment=lambda vault_id: [attachment])

    output = _run_action(
        detonate_file, DetonateFileParams(vault_id="mock-vault-id", attempts=1), soar
    )

    assert output.get_status() is True
    assert output.get_data() == [{"overview": overview, "analysis": analysis}]
    assert output.get_summary() == {"sha256": SHA256, "analysis_complete": True}
    assert output.get_message() == "Successfully retrieved overview and analysis"
    assert calls == [
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}/analysis"),
    ]


@pytest.mark.parametrize("params_cls", [DetonateFileParams, GetReportParams])
@pytest.mark.parametrize(
    ("attempts", "expected"), [(10.56, 10), (-5.9, -5), (10.0, 10), ("10", 10)]
)
def test_report_params_convert_legacy_attempts(params_cls, attempts, expected):
    params = params_cls.model_validate(
        {"vault_id": "mock-vault-id", "attempts": attempts}
    )
    assert params.attempts == expected
    assert type(params.attempts) is int


@pytest.mark.parametrize("params_cls", [DetonateFileParams, GetReportParams])
@pytest.mark.parametrize("attempts", ["10.56", "10.0", "-12.345"])
def test_report_params_reject_decimal_attempt_strings(params_cls, attempts):
    with pytest.raises(ValueError, match="attempts must be a finite number"):
        params_cls.model_validate({"vault_id": "mock-vault-id", "attempts": attempts})


@pytest.mark.parametrize(
    ("params_cls", "expected"), [(DetonateFileParams, 10), (GetReportParams, 1)]
)
def test_report_params_keep_legacy_attempt_defaults(params_cls, expected):
    params = params_cls.model_validate({"vault_id": "mock-vault-id"})
    assert params.attempts == expected


@pytest.mark.parametrize(
    ("has_yara_result", "force_yara_analysis", "starts_yara"),
    [(True, False, False), (True, "", False), (False, False, True), (True, True, True)],
    ids=["existing-result", "legacy-empty-force", "first-scan", "forced-rescan"],
)
def test_yara_detonation_returns_overview_when_ready(
    monkeypatch,
    has_yara_result: bool,
    force_yara_analysis: bool | str,
    starts_yara: bool,
) -> None:
    overview, _ = _api_payloads()
    overview.update(is_static_analyzed=False, is_dynamic_analyzed=False)
    if not has_yara_result:
        overview["last_yara_analysis_at"] = None
    completed = (
        {**overview, "last_yara_analysis_at": "2026-11-19T10:00:00Z"}
        if starts_yara
        else overview
    )
    overviews = [overview, overview, completed] if starts_yara else [overview]
    calls = _install_case_api(monkeypatch, {SHA256: overviews}, {})
    soar = _soar()
    soar.vault = SimpleNamespace(get_attachment=lambda **_: [_attachment(SHA256)])
    params = DetonateFileParams.model_validate(
        {
            "vault_id": "mock-vault-id",
            "attempts": 2,
            "analysis_type": "yara",
            "force_yara_analysis": force_yara_analysis,
        }
    )

    result = _run_action(detonate_file, params, soar)

    assert result.get_data() == [{"overview": completed}]
    assert result.get_summary() == {"sha256": SHA256, "analysis_complete": True}
    lookup = ("GET", f"/apks/{SHA256}")
    if starts_yara:
        assert calls == [
            lookup,
            ("POST", f"/apks/{SHA256}/analyze_yara/"),
            lookup,
            lookup,
        ]
    else:
        assert calls == [lookup, lookup]


@pytest.mark.parametrize("action", [get_report, detonate_file])
def test_polling_timeout_preserves_partial_result(monkeypatch, action) -> None:
    overview, _ = _api_payloads()
    overview.update(is_static_analyzed=False, is_dynamic_analyzed=False)
    _install_case_api(monkeypatch, {SHA256: [overview]}, {})
    soar = _soar()
    if action is detonate_file:
        soar.vault = SimpleNamespace(get_attachment=lambda **_: [_attachment(SHA256)])
        params = DetonateFileParams(
            vault_id="mock-vault-id",
            attempts=1,
            analysis_type="yara",
            force_yara_analysis=True,
        )
    else:
        params = GetReportParams(sha256=SHA256, attempts=1)

    result = _run_action(action, params, soar, success=False)

    assert result.get_data() == [{"overview": overview}]
    assert result.get_summary() == {"sha256": SHA256, "analysis_complete": False}
    assert result.get_message().startswith("Polling attempts were exhausted")


@pytest.mark.parametrize(
    ("case_id", "attempts"),
    [
        ("detonate_file_0_retry_000", 0),
        ("detonate_file_negative_retry_000", -5),
    ],
    ids=["detonate_file_0_retry_000", "detonate_file_negative_retry_000"],
)
def test_detonate_file_nonpositive_attempts_use_one_mocked_poll(
    monkeypatch, case_id: str, attempts: int
) -> None:
    overview, analysis = _api_payloads()
    calls = _install_case_api(monkeypatch, {SHA256: [overview]}, {SHA256: analysis})
    soar = _soar()
    soar.vault = SimpleNamespace(get_attachment=lambda vault_id: [_attachment(SHA256)])

    result = _run_action(
        detonate_file,
        DetonateFileParams(vault_id="mock-vault-id", attempts=attempts),
        soar,
    )

    assert result.get_status() is True, case_id
    assert result.get_summary() == {"sha256": SHA256, "analysis_complete": True}
    assert calls == [
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}/analysis"),
    ]


def test_detonate_file_retries_rate_limit_without_upload(monkeypatch) -> None:
    overview, analysis = _api_payloads()
    calls: list[tuple[str, str]] = []
    sleep_delays: list[float] = []
    progress_messages: list[str] = []
    overview_requests = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal overview_requests
        calls.append((request.method, request.url.path))
        if request.url.path == f"/apks/{SHA256}":
            overview_requests += 1
            if overview_requests == 1:
                return httpx.Response(
                    429,
                    json={
                        "detail": "Request was throttled. Expected available in 44 seconds."
                    },
                )
            return httpx.Response(200, json=overview)
        if request.url.path == f"/apks/{SHA256}/analysis":
            return httpx.Response(200, json=analysis)
        if request.url.path == f"/apks/{SHA256}/get_upload_url":
            return httpx.Response(
                409, json={"detail": "This file has already been uploaded"}
            )
        return httpx.Response(404, json={"detail": "Unexpected mocked endpoint"})

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)

    def client_with_mock_transport(**kwargs):
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(helper.httpx, "Client", client_with_mock_transport)
    monkeypatch.setattr(helper.time, "sleep", sleep_delays.append)
    monkeypatch.setattr(helper, "progress", progress_messages.append)
    soar = _soar()
    soar.vault = SimpleNamespace(get_attachment=lambda **_kwargs: [_attachment(SHA256)])

    result = _run_action(
        detonate_file, DetonateFileParams(vault_id="mock-vault-id", attempts=1), soar
    )

    assert result.get_status() is True
    assert result.get_summary() == {"sha256": SHA256, "analysis_complete": True}
    assert sleep_delays == [44.0]
    assert progress_messages == [
        "Koodous rate limit; retrying the request; waiting 44 seconds"
    ]
    assert calls == [
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}/analysis"),
    ]


def test_long_rate_limit_wait_sends_repeated_progress(monkeypatch) -> None:
    sleep_intervals: list[float] = []
    progress_messages: list[str] = []
    monkeypatch.setattr(helper.time, "sleep", sleep_intervals.append)
    monkeypatch.setattr(helper, "progress", progress_messages.append)

    helper._sleep_with_progress(500, "Waiting for Koodous rate limit")

    assert sleep_intervals == [240, 240, 20]
    assert len(progress_messages) == 3


def test_24_hour_rate_limit_fails_without_waiting(monkeypatch) -> None:
    calls: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            429,
            headers={"Retry-After": "86400"},
            json={"detail": "Expected available in 86400 seconds"},
        )

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)

    def client_with_mock_transport(**kwargs):
        return real_client(transport=transport, **kwargs)

    sleep_intervals: list[float] = []
    monkeypatch.setattr(helper.httpx, "Client", client_with_mock_transport)
    monkeypatch.setattr(helper.time, "sleep", sleep_intervals.append)

    with pytest.raises(ActionFailure, match="HTTP 429"):
        helper.request(_asset(), "GET", f"/apks/{SHA256}", retry_rate_limited=True)

    assert len(calls) == 1
    assert sleep_intervals == []


def test_detonate_file_uploads_only_when_overview_is_not_found(monkeypatch) -> None:
    overview, analysis = _api_payloads()
    calls: list[tuple[str, str]] = []
    overview_requests = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal overview_requests
        calls.append((request.method, request.url.path))
        if request.url.path == f"/apks/{SHA256}":
            overview_requests += 1
            if overview_requests == 1:
                return httpx.Response(404, json={"detail": "Not found"})
            return httpx.Response(200, json=overview)
        if request.url.path == f"/apks/{SHA256}/get_upload_url":
            return httpx.Response(
                200, json={"upload_url": "https://uploads.example/upload"}
            )
        if request.url.path == "/upload" and request.method == "POST":
            return httpx.Response(200, json={"uploaded": True})
        if request.url.path == f"/apks/{SHA256}/analysis":
            return httpx.Response(200, json=analysis)
        return httpx.Response(404, json={"detail": "Unexpected mocked endpoint"})

    real_client = httpx.Client
    transport = httpx.MockTransport(respond)

    def client_with_mock_transport(**kwargs):
        return real_client(transport=transport, **kwargs)

    monkeypatch.setattr(helper.httpx, "Client", client_with_mock_transport)
    soar = _soar()
    soar.vault = SimpleNamespace(get_attachment=lambda **_kwargs: [_attachment(SHA256)])

    result = _run_action(
        detonate_file, DetonateFileParams(vault_id="mock-vault-id", attempts=1), soar
    )

    assert result.get_status() is True
    assert calls == [
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}/get_upload_url"),
        ("POST", "/upload"),
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}"),
        ("GET", f"/apks/{SHA256}/analysis"),
    ]


@pytest.mark.parametrize(
    (
        "case_id",
        "sha256",
        "attempts",
        "vault_id",
        "attachment_sha256",
        "expected_sha256",
        "overview_sequence",
    ),
    [
        ("get_report_2_000", "", 1, "vault", SHA256, SHA256, None),
        ("get_report_12_000", SHA256, 1, "", None, SHA256, None),
        (
            "get_report_16_000",
            SHA256,
            1,
            "vault",
            "b" * 64,
            "b" * 64,
            None,
        ),
        (
            "get_report_17_000",
            "c" * 64,
            1,
            "vault",
            "b" * 64,
            "b" * 64,
            None,
        ),
        (
            "get_report_20_000",
            "d" * 64,
            6,
            "",
            None,
            "d" * 64,
            "complete_on_second_poll",
        ),
        ("get_report_22_000", "", -6, "vault", SHA256, SHA256, None),
        ("get_report_23_000", "", 0, "vault", SHA256, SHA256, None),
    ],
    ids=[
        "get_report_2_000",
        "get_report_12_000",
        "get_report_16_000",
        "get_report_17_000",
        "get_report_20_000",
        "get_report_22_000",
        "get_report_23_000",
    ],
)
def test_get_report_mocked_app_test_cases(
    monkeypatch,
    case_id: str,
    sha256: str,
    attempts: int,
    vault_id: str,
    attachment_sha256: str | None,
    expected_sha256: str,
    overview_sequence: str | None,
) -> None:
    progress_messages: list[str] = []
    monkeypatch.setattr(helper, "progress", progress_messages.append)
    overview, analysis = _api_payloads()
    ready_overview = {**overview, "sha256": expected_sha256}
    if overview_sequence == "complete_on_second_poll":
        pending_overview = {
            **ready_overview,
            "is_static_analyzed": False,
            "is_dynamic_analyzed": False,
        }
        overviews = [pending_overview, ready_overview]
    else:
        overviews = [ready_overview]
    calls = _install_case_api(
        monkeypatch,
        {expected_sha256: overviews},
        {expected_sha256: {**analysis, "sha256": expected_sha256}},
    )
    soar = _soar()
    if attachment_sha256:
        soar.vault = SimpleNamespace(
            get_attachment=lambda **kwargs: (
                [_attachment(attachment_sha256)]
                if kwargs["vault_id"] == vault_id
                else []
            )
        )

    result = _run_action(
        get_report,
        GetReportParams(
            sha256=sha256 or None,
            attempts=attempts,
            vault_id=vault_id or None,
        ),
        soar,
    )

    assert result.get_status() is True, case_id
    assert result.get_summary() == {
        "sha256": expected_sha256,
        "analysis_complete": True,
    }
    expected_poll_count = 2 if overview_sequence == "complete_on_second_poll" else 1
    assert calls == [
        *[("GET", f"/apks/{expected_sha256}")] * expected_poll_count,
        ("GET", f"/apks/{expected_sha256}/analysis"),
    ]
    if case_id == "get_report_20_000":
        assert progress_messages == [
            "Polling for report, on attempt 1 of 6; waiting 30 seconds"
        ]
