#!/usr/bin/env python3
"""Create or monitor an immutable Render deployment.

The deployment-creation POST is deliberately single-attempt. Polling GETs retry
transient failures within the deployment's overall timeout budget.
"""

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NoReturn

API_ROOT = "https://api.render.com/v1"
LIVE_STATUS = "live"
IN_PROGRESS_STATUSES = {
    "created",
    "queued",
    "build_in_progress",
    "update_in_progress",
    "pre_deploy_in_progress",
}
FAILED_STATUSES = {
    "build_failed",
    "update_failed",
    "pre_deploy_failed",
    "canceled",
    "deactivated",
}
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
RETRY_DELAYS_SECONDS = (1, 2, 4)


def _fail(message: str) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def _env(name: str, required: bool = True, default: str = "") -> str:
    value = os.environ.get(name, default)
    if required and not value:
        _fail(f"{name} environment variable is not set")
    return value


def _error_detail(exc: urllib.error.HTTPError) -> str:
    try:
        return exc.read().decode("utf-8")[:500]
    except Exception:
        return ""


def _decode_json(body: str, context: str) -> dict:
    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        _fail(f"{context} returned malformed JSON")
    if not isinstance(result, dict):
        _fail(f"{context} returned an invalid payload shape")
    return result


def _open(request: urllib.request.Request) -> str:
    parsed = urllib.parse.urlsplit(request.full_url)
    if parsed.scheme != "https" or parsed.hostname != "api.render.com" or parsed.port not in (None, 443):
        _fail("refusing request to an untrusted Render API endpoint")
    with (
        urllib.request.urlopen(  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected  # noqa: E501
            request, timeout=30
        ) as response
    ):
        return response.read().decode("utf-8")


def _request(
    method: str,
    url: str,
    api_key: str,
    payload: dict | None = None,
    *,
    deadline: float | None = None,
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> dict:
    """Make one POST, or retry a polling GET on transient failures."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {api_key}")
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")

    attempts = 1 if method != "GET" else 1 + len(RETRY_DELAYS_SECONDS)
    for attempt in range(attempts):
        try:
            return _decode_json(_open(request), f"{method} {url}")
        except urllib.error.HTTPError as exc:
            retryable = method == "GET" and exc.code in RETRYABLE_HTTP_CODES
            detail = _error_detail(exc)
            error = f"HTTP {exc.code}{f': {detail}' if detail else ''}"
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, socket.timeout) as exc:
            retryable = method == "GET"
            reason = getattr(exc, "reason", exc)
            error = f"network error: {reason}"

        if not retryable:
            _fail(f"{method} {url} failed: {error}")
        if attempt == attempts - 1:
            _fail(f"{method} {url} exhausted {attempts} attempts after transient {error}")

        delay = RETRY_DELAYS_SECONDS[attempt]
        if deadline is not None and monotonic() + delay > deadline:
            _fail(f"{method} {url} cannot retry within the overall deployment timeout after transient {error}")
        print(f"Transient {error}; retrying GET in {delay}s (attempt {attempt + 2}/{attempts})")
        sleep(delay)

    raise AssertionError("unreachable")


def trigger_deploy(service_id: str, api_key: str, commit_sha: str, service_name: str = "service") -> str:
    """Create one deploy and return its exact deployment ID; never retry POST."""
    url = f"{API_ROOT}/services/{service_id}/deploys"
    print(f"Creating {service_name} deploy for service {service_id} at SHA {commit_sha}")
    result = _request("POST", url, api_key, payload={"commitId": commit_sha})
    deploy_id = result.get("id")
    if not isinstance(deploy_id, str) or not deploy_id.strip():
        _fail(f"{service_name} deploy creation for service {service_id} at SHA {commit_sha} returned no deployment ID")
    return deploy_id


def poll_deploy(
    service_id: str,
    api_key: str,
    deploy_id: str,
    commit_sha: str,
    timeout_s: int,
    poll_s: int,
    service_name: str = "service",
    *,
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> None:
    """Poll the exact deployment ID until live, terminal failure, or timeout."""
    url = f"{API_ROOT}/services/{service_id}/deploys/{deploy_id}"
    deadline = monotonic() + timeout_s
    last_status = "not observed"

    while True:
        if monotonic() >= deadline:
            _fail(
                f"{service_name} service {service_id} deployment {deploy_id} at SHA {commit_sha} timed out "
                f"after {timeout_s}s; last status: {last_status}"
            )
        result = _request("GET", url, api_key, deadline=deadline, sleep=sleep, monotonic=monotonic)
        if "deploy" in result:
            result = result["deploy"]
            if not isinstance(result, dict):
                _fail(f"{service_name} deployment {deploy_id} returned an invalid deploy payload")
        status = result.get("status")
        if not isinstance(status, str) or not status:
            _fail(f"{service_name} service {service_id} deployment {deploy_id} response contained no status")
        last_status = status
        print(f"{service_name} deployment {deploy_id} at SHA {commit_sha}: {status}")

        if status == LIVE_STATUS:
            return
        if status in FAILED_STATUSES:
            _fail(
                f"{service_name} service {service_id} deployment {deploy_id} at SHA {commit_sha} "
                f"failed with terminal status {status}"
            )
        if status not in IN_PROGRESS_STATUSES:
            _fail(f"{service_name} deployment {deploy_id} returned unknown status {status!r}")

        if monotonic() + poll_s > deadline:
            _fail(
                f"{service_name} service {service_id} deployment {deploy_id} at SHA {commit_sha} timed out; "
                f"last status: {last_status}"
            )
        sleep(poll_s)


def _write_github_output_if_available(name: str, value: str) -> None:
    """Expose an output to GitHub Actions when the workflow output file exists."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as output:
        output.write(f"{name}={value}\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("create", "wait", "deploy"), nargs="?", default="deploy")
    args = parser.parse_args()

    api_key = _env("RENDER_API_KEY")
    service_id = _env("RENDER_SERVICE_ID")
    commit_sha = _env("GITHUB_SHA")
    service_name = _env("RENDER_SERVICE_NAME", required=False, default="service")

    if args.command in {"create", "deploy"}:
        deploy_id = trigger_deploy(service_id, api_key, commit_sha, service_name)
        if args.command == "create":
            print(f"deploy_id={deploy_id}")
            _write_github_output_if_available("deploy_id", deploy_id)
            return
    else:
        deploy_id = _env("RENDER_DEPLOY_ID")

    try:
        timeout_s = int(_env("RENDER_DEPLOY_TIMEOUT_SECONDS", required=False, default="1800"))
        poll_s = int(_env("RENDER_DEPLOY_POLL_SECONDS", required=False, default="15"))
    except ValueError:
        _fail("RENDER_DEPLOY_TIMEOUT_SECONDS and RENDER_DEPLOY_POLL_SECONDS must be integers")
    if timeout_s <= 0 or poll_s <= 0:
        _fail("Render deploy timeout and poll interval must be positive integers")
    poll_deploy(service_id, api_key, deploy_id, commit_sha, timeout_s, poll_s, service_name)


if __name__ == "__main__":
    main()
