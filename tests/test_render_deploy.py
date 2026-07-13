import io
import json
import sys
import urllib.error

import pytest

from scripts import render_deploy


class Clock:
    def __init__(self):
        self.now = 0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def http_error(code):
    return urllib.error.HTTPError("https://api.render.com", code, "error", {}, io.BytesIO(b"detail"))


def test_open_rejects_untrusted_endpoint():
    request = render_deploy.urllib.request.Request("file:///etc/passwd")
    with pytest.raises(SystemExit):
        render_deploy._open(request)


def sequence(monkeypatch, values):
    calls = []
    iterator = iter(values)

    def fake_open(request):
        calls.append(request)
        value = next(iterator)
        if isinstance(value, BaseException):
            raise value
        return json.dumps(value) if not isinstance(value, str) else value

    monkeypatch.setattr(render_deploy, "_open", fake_open)
    return calls


def test_successful_deployment_creation(monkeypatch):
    calls = sequence(monkeypatch, [{"id": "dep-api", "status": "created"}])
    assert render_deploy.trigger_deploy("srv-api", "secret", "abc123", "API") == "dep-api"
    assert len(calls) == 1
    assert calls[0].method == "POST"
    assert json.loads(calls[0].data) == {"commitId": "abc123"}


def test_missing_deployment_id_fails(monkeypatch):
    sequence(monkeypatch, [{"status": "created"}])
    with pytest.raises(SystemExit):
        render_deploy.trigger_deploy("srv-api", "secret", "abc123")


@pytest.mark.parametrize("body", ["not-json", []])
def test_malformed_post_response_fails(monkeypatch, body):
    sequence(monkeypatch, [body])
    with pytest.raises(SystemExit):
        render_deploy.trigger_deploy("srv-api", "secret", "abc123")


def test_post_network_failure_is_not_retried(monkeypatch):
    calls = sequence(monkeypatch, [urllib.error.URLError("offline")])
    with pytest.raises(SystemExit):
        render_deploy.trigger_deploy("srv-api", "secret", "abc123")
    assert len(calls) == 1


def _set_cli_environment(monkeypatch, **overrides):
    environment = {
        "RENDER_API_KEY": "secret",
        "RENDER_SERVICE_ID": "srv-api",
        "RENDER_SERVICE_NAME": "API",
        "GITHUB_SHA": "abc123",
    }
    environment.update(overrides)
    for name in ("GITHUB_OUTPUT", "RENDER_DEPLOY_ID", "RENDER_DEPLOY_TIMEOUT_SECONDS", "RENDER_DEPLOY_POLL_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)


def test_create_mode_succeeds_locally_and_prints_deployment_id(monkeypatch, capsys):
    calls = sequence(monkeypatch, [{"id": "dep-local"}])
    _set_cli_environment(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["render_deploy.py", "create"])

    render_deploy.main()

    assert len(calls) == 1
    assert capsys.readouterr().out.splitlines()[-1] == "deploy_id=dep-local"


def test_create_mode_writes_github_output_when_available(monkeypatch, tmp_path, capsys):
    calls = sequence(monkeypatch, [{"id": "dep-actions"}])
    output_file = tmp_path / "github-output"
    _set_cli_environment(monkeypatch, GITHUB_OUTPUT=str(output_file))
    monkeypatch.setattr(sys, "argv", ["render_deploy.py", "create"])

    render_deploy.main()

    assert len(calls) == 1
    assert capsys.readouterr().out.splitlines()[-1] == "deploy_id=dep-actions"
    assert output_file.read_text(encoding="utf-8") == "deploy_id=dep-actions\n"


def test_failed_create_writes_no_github_output_and_is_not_retried(monkeypatch, tmp_path):
    calls = sequence(monkeypatch, [urllib.error.URLError("offline")])
    output_file = tmp_path / "github-output"
    _set_cli_environment(monkeypatch, GITHUB_OUTPUT=str(output_file))
    monkeypatch.setattr(sys, "argv", ["render_deploy.py", "create"])

    with pytest.raises(SystemExit):
        render_deploy.main()

    assert len(calls) == 1
    assert not output_file.exists()


def test_wait_mode_requires_deployment_id(monkeypatch):
    _set_cli_environment(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["render_deploy.py", "wait"])

    with pytest.raises(SystemExit):
        render_deploy.main()


def test_default_deploy_creates_once_and_waits_for_the_same_id(monkeypatch):
    calls = sequence(monkeypatch, [{"id": "dep-default"}, {"status": "live"}])
    _set_cli_environment(monkeypatch, RENDER_DEPLOY_TIMEOUT_SECONDS="30", RENDER_DEPLOY_POLL_SECONDS="1")
    monkeypatch.setattr(sys, "argv", ["render_deploy.py"])

    render_deploy.main()

    assert len(calls) == 2
    assert calls[0].method == "POST"
    assert calls[1].full_url.endswith("/srv-api/deploys/dep-default")


def test_successful_polling_uses_exact_deployment_id(monkeypatch):
    calls = sequence(monkeypatch, [{"status": "build_in_progress"}, {"deploy": {"status": "live"}}])
    clock = Clock()
    render_deploy.poll_deploy(
        "srv-api", "secret", "dep-exact", "abc123", 30, 1, sleep=clock.sleep, monotonic=clock.monotonic
    )
    assert all(request.full_url.endswith("/srv-api/deploys/dep-exact") for request in calls)


def test_terminal_render_failure_is_immediate(monkeypatch):
    calls = sequence(monkeypatch, [{"status": "build_failed"}])
    with pytest.raises(SystemExit):
        render_deploy.poll_deploy("srv", "secret", "dep", "sha", 30, 1)
    assert len(calls) == 1


def test_overall_timeout_reports_last_status(monkeypatch, capsys):
    sequence(monkeypatch, [{"status": "queued"}])
    clock = Clock()
    with pytest.raises(SystemExit):
        render_deploy.poll_deploy("srv", "secret", "dep", "sha", 1, 2, sleep=clock.sleep, monotonic=clock.monotonic)
    assert "last status: queued" in capsys.readouterr().err


@pytest.mark.parametrize("payload", [[], {"deploy": []}])
def test_malformed_polling_payload_fails(monkeypatch, payload):
    sequence(monkeypatch, [payload])
    with pytest.raises(SystemExit):
        render_deploy.poll_deploy("srv", "secret", "dep", "sha", 30, 1)


def test_missing_polling_status_fails(monkeypatch):
    sequence(monkeypatch, [{"id": "dep"}])
    with pytest.raises(SystemExit):
        render_deploy.poll_deploy("srv", "secret", "dep", "sha", 30, 1)


@pytest.mark.parametrize(
    "transient",
    [
        urllib.error.URLError("offline"),
        http_error(429),
        http_error(500),
        http_error(502),
        http_error(503),
        http_error(504),
    ],
)
def test_transient_polling_failure_recovers(monkeypatch, transient):
    sequence(monkeypatch, [transient, {"status": "live"}])
    clock = Clock()
    render_deploy.poll_deploy("srv", "secret", "dep", "sha", 30, 1, sleep=clock.sleep, monotonic=clock.monotonic)
    assert clock.sleeps == [1]


def test_exhausted_transient_retries_use_bounded_backoff(monkeypatch, capsys):
    calls = sequence(monkeypatch, [urllib.error.URLError("offline")] * 4)
    clock = Clock()
    with pytest.raises(SystemExit):
        render_deploy.poll_deploy("srv", "secret", "dep", "sha", 30, 1, sleep=clock.sleep, monotonic=clock.monotonic)
    assert len(calls) == 4
    assert clock.sleeps == [1, 2, 4]
    assert "exhausted 4 attempts" in capsys.readouterr().err


@pytest.mark.parametrize("code", [400, 401, 403, 404])
def test_permanent_http_failure_is_not_retried(monkeypatch, code):
    calls = sequence(monkeypatch, [http_error(code)])
    with pytest.raises(SystemExit):
        render_deploy.poll_deploy("srv", "secret", "dep", "sha", 30, 1)
    assert len(calls) == 1


def test_retry_delay_cannot_exceed_overall_timeout(monkeypatch, capsys):
    sequence(monkeypatch, [urllib.error.URLError("offline")])
    clock = Clock()
    clock.now = 9.5
    with pytest.raises(SystemExit):
        render_deploy._request(
            "GET", "https://example.test", "secret", deadline=10, sleep=clock.sleep, monotonic=clock.monotonic
        )
    assert clock.sleeps == []
    assert "overall deployment timeout" in capsys.readouterr().err


def test_unknown_status_is_not_retried(monkeypatch):
    calls = sequence(monkeypatch, [{"status": "mystery"}])
    with pytest.raises(SystemExit):
        render_deploy.poll_deploy("srv", "secret", "dep", "sha", 30, 1)
    assert len(calls) == 1
