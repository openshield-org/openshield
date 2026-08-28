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
import re
import threading
import time
import uuid
from collections import deque
from functools import wraps
from typing import Callable, Deque, Dict, Optional, Tuple

from flask import Flask, Response, current_app, g, jsonify, request
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
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

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
DB_POOL_CONNECTIONS_IN_USE = Gauge(
    "openshield_db_pool_connections_in_use",
    "Connections currently checked out from the shared database pool.",
)
DB_POOL_CONNECTIONS_IDLE = Gauge(
    "openshield_db_pool_connections_idle",
    "Connections currently idle in the shared database pool.",
)
DB_POOL_CONNECTIONS_MAX = Gauge(
    "openshield_db_pool_connections_max",
    "Configured maximum size of the shared database pool.",
)

# Set by api.app at startup (see set_pool_stats_provider). Kept as a plain
# module-level callable rather than importing api.models.finding directly -
# this module stays free of project imports (see module docstring) so it
# can be reused from the worker without pulling in the API's DB layer.
_pool_stats_provider: Optional[Callable[[], Dict[str, int]]] = None


def set_pool_stats_provider(fn: Callable[[], Dict[str, int]]) -> None:
    """Register the callable /metrics uses to refresh the DB pool gauges.

    Called lazily on every scrape (see ``metrics()`` below) rather than on a
    timer, so the numbers are exact at scrape time instead of aging between
    scrapes.
    """
    global _pool_stats_provider
    _pool_stats_provider = fn


def _refresh_pool_metrics() -> None:
    if _pool_stats_provider is None:
        return
    try:
        stats = _pool_stats_provider()
        DB_POOL_CONNECTIONS_IN_USE.set(stats["in_use"])
        DB_POOL_CONNECTIONS_IDLE.set(stats["idle"])
        DB_POOL_CONNECTIONS_MAX.set(stats["max_connections"])
    except Exception:
        # A stats lookup must never take /metrics down - the rest of the
        # scrape (HTTP/scan counters etc.) is still valid without it.
        logger.exception("Failed to refresh database pool metrics")


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
# Probe/scrape rate limiting                                                   #
# --------------------------------------------------------------------------- #
# /health, /ready, and /metrics are exempt from JWT auth by design (see
# api.app._ALWAYS_PUBLIC) so uptime checkers and Prometheus scrapers can
# reach them without a token. That also makes /ready and /metrics the one
# place an unauthenticated caller can trigger repeated backend work - a
# pooled database checkout for /ready - without ever presenting a token.
#
# api.rate_limit.rate_limit (used elsewhere in the API) is the wrong tool
# here: it does its own Postgres round trip per check, which would add
# database load to /ready - the exact endpoint whose job is to protect the
# database pool from overload - and risks checking out a second, separate
# pooled connection under its own `g.db` alongside the one /ready's handler
# already manages, only one of which the teardown handler would return.
#
# This limiter is pure in-memory and per-process instead. The connection
# pool it protects (api.models.finding._POOLS) is itself process-local under
# Gunicorn's multi-worker model, so a per-process budget is the matching
# granularity, not a weaker substitute for a shared one: it bounds exactly
# the pool a single worker process can exhaust. It is a defense-in-depth
# backstop, not a replacement for restricting these paths at whatever
# reverse proxy/CDN/WAF fronts the deployment - see the "Restricting
# probe/scrape endpoints at the edge" section of docs/deployment/render.md.
_PROBE_WINDOW_SECONDS = 10.0
# Prometheus scrapes on a fixed interval (typically 15-30s) from a small,
# stable set of scraper IPs, so this stays generous; it exists to blunt a
# single caller hammering the endpoint, not to constrain normal scraping.
_METRICS_MAX_REQUESTS_PER_WINDOW = 20
_probe_lock = threading.Lock()
_probe_hits: Dict[Tuple[str, str], Deque[float]] = {}


def probe_rate_limit(max_requests: int, window_seconds: float = _PROBE_WINDOW_SECONDS):
    """Limit a probe/scrape view to ``max_requests`` per ``window_seconds`` per client IP.

    The check runs before the wrapped view body, so a request rejected here
    never reaches the database work it would otherwise trigger. Disabled in
    testing mode, matching the convention in api.rate_limit.rate_limit.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if current_app.testing:
                return fn(*args, **kwargs)

            key = (request.remote_addr or "unknown", request.path)
            now = time.monotonic()
            with _probe_lock:
                hits = _probe_hits.get(key)
                if hits is not None:
                    cutoff = now - window_seconds
                    while hits and hits[0] < cutoff:
                        hits.popleft()
                    if not hits:
                        # Prune empty entries immediately rather than letting
                        # every distinct caller's key accumulate forever -
                        # a key only exists while it has a hit in-window.
                        del _probe_hits[key]
                        hits = None
                if hits is None:
                    hits = deque()
                allowed = len(hits) < max_requests
                if allowed:
                    hits.append(now)
                    _probe_hits[key] = hits

            if not allowed:
                return jsonify({"status": "rate_limited"}), 429

            return fn(*args, **kwargs)

        return wrapped

    return decorator


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
        supplied_request_id = request.headers.get(REQUEST_ID_HEADER, "")
        g.request_id = supplied_request_id if _REQUEST_ID_RE.fullmatch(supplied_request_id) else str(uuid.uuid4())
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
    @probe_rate_limit(_METRICS_MAX_REQUESTS_PER_WINDOW)
    def metrics() -> Response:
        _refresh_pool_metrics()
        return Response(generate_latest(), content_type=CONTENT_TYPE_LATEST)
