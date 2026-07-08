"""Shared observability layer: structured logging, request IDs, Prometheus
metrics and optional Sentry error tracking.

This module is intentionally free of any project imports so that it can be
used from both the API (``api.app``) and the background worker
(``scanner.worker``) without creating an import cycle.

Metric cardinality note: no metric is ever labelled with a request ID,
scan ID, subscription ID, resource ID, error message or free-form user
input. Only low-cardinality, bounded values (HTTP method, view name,
status code, scan status, rule ID and provider name) are used as labels.
"""

import logging
import os
import time
import uuid

from flask import Flask, Response, g, request
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# python-json-logger moved ``JsonFormatter`` from ``pythonjsonlogger.jsonlogger``
# to ``pythonjsonlogger.json`` in 3.1. Prefer the new path, fall back for <3.1.
try:  # pragma: no cover - trivial import shim
    from pythonjsonlogger.json import JsonFormatter
except ImportError:  # pragma: no cover
    from pythonjsonlogger.jsonlogger import JsonFormatter

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

# --------------------------------------------------------------------------- #
# Prometheus metrics                                                           #
# --------------------------------------------------------------------------- #
# Defined at module import so they are process-wide singletons. Re-importing
# this module (e.g. across repeated create_app() calls in tests) reuses the
# same collectors and never double-registers.

HTTP_REQUESTS_TOTAL = Counter(
    "openshield_http_requests_total",
    "Total HTTP requests processed by the API.",
    ["method", "endpoint", "status"],
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "openshield_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ["method", "endpoint"],
)
SCANS_TOTAL = Counter(
    "openshield_scans_total",
    "Total scans processed by the worker, by terminal status.",
    ["status"],
)
SCAN_DURATION_SECONDS = Histogram(
    "openshield_scan_duration_seconds",
    "Wall-clock duration of a single scan execution in seconds.",
)
PENDING_SCANS = Gauge(
    "openshield_pending_scans",
    "Number of scans currently waiting in the pending queue.",
)
RULE_ERRORS_TOTAL = Counter(
    "openshield_rule_errors_total",
    "Total number of times a scanner rule raised an exception.",
    ["rule_id"],
)
NVD_REQUEST_LATENCY_SECONDS = Histogram(
    "openshield_nvd_request_latency_seconds",
    "Latency of outbound NVD HTTP requests in seconds.",
)
LLM_PROVIDER_LATENCY_SECONDS = Histogram(
    "openshield_llm_provider_latency_seconds",
    "Latency of outbound LLM provider requests in seconds.",
    ["provider"],
)


# --------------------------------------------------------------------------- #
# Structured logging                                                           #
# --------------------------------------------------------------------------- #
def configure_logging(level: int = logging.INFO) -> None:
    """Configure the root logger to emit structured JSON to stderr.

    Safe to call multiple times — it replaces the root handlers each call so
    repeated invocations (API import, worker start, tests) do not stack
    duplicate handlers. Any ``extra={...}`` fields passed to log calls are
    included as top-level JSON keys.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)


# --------------------------------------------------------------------------- #
# Sentry (optional)                                                            #
# --------------------------------------------------------------------------- #
def init_sentry() -> bool:
    """Initialise Sentry error tracking only when ``SENTRY_DSN`` is set.

    Returns ``True`` when Sentry was initialised, ``False`` otherwise (DSN
    unset, or ``sentry-sdk`` not installed). Never raises.
    """
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        return False
    try:
        import sentry_sdk
    except ImportError:
        logger.warning("SENTRY_DSN is set but sentry-sdk is not installed; skipping.")
        return False

    try:
        sentry_sdk.init(
            dsn=dsn,
            environment=os.environ.get("OPENSHIELD_ENV", "development"),
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.0")),
        )
    except Exception as exc:
        # A malformed DSN must never take down the API or the worker.
        logger.warning("Failed to initialise Sentry: %s", exc)
        return False
    logger.info("Sentry error tracking initialised.")
    return True


# --------------------------------------------------------------------------- #
# Request IDs                                                                  #
# --------------------------------------------------------------------------- #
def get_request_id() -> str:
    """Return the request ID bound to the current request context.

    Falls back to a freshly generated UUID if the middleware has not run
    (e.g. outside a request), so callers always receive a usable value.
    """
    rid = getattr(g, "request_id", None)
    if not rid:
        rid = str(uuid.uuid4())
        g.request_id = rid
    return rid


# --------------------------------------------------------------------------- #
# Flask wiring                                                                 #
# --------------------------------------------------------------------------- #
def init_app(app: Flask) -> None:
    """Register request-ID and Prometheus middleware and the /metrics route.

    Must be called before any other ``before_request`` handlers (such as JWT
    auth) so that ``g.request_id`` is available to them and to error handlers.
    """

    @app.before_request
    def _start_observability() -> None:
        g.request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        g.request_start_time = time.perf_counter()

    @app.after_request
    def _record_observability(response: Response) -> Response:
        response.headers[REQUEST_ID_HEADER] = get_request_id()

        endpoint = request.endpoint or "unknown"
        method = request.method
        HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status=response.status_code).inc()
        start = getattr(g, "request_start_time", None)
        if start is not None:
            HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=endpoint).observe(time.perf_counter() - start)
        return response

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), content_type=CONTENT_TYPE_LATEST)
