"""Postgres-backed sliding-window rate limiter for Flask routes.

Deployments run gunicorn with multiple worker processes (see startup.sh),
so a plain in-memory counter would give each worker its own independent
budget instead of enforcing one shared limit per client. State is kept in
the `rate_limit_hits` table instead, with the count-then-insert made atomic
across all workers via a Postgres advisory transaction lock keyed on the
same rate-limit key.
"""

import logging
import os
from functools import wraps
from typing import Any

from flask import current_app, g, jsonify, request

from api.models.finding import DatabaseManager

logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    """Reuse the same `g.db` connection every other route module populates,
    so it's cleaned up by api.app's existing close_db teardown instead of
    leaking a second, unmanaged connection per request."""
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


def _check_and_record(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if this request is within the limit, recording it if so.

    The advisory lock is scoped to the current transaction (released on the
    commit/rollback below), which serializes concurrent requests for the
    same key across every worker process sharing this database — not just
    threads within one process.
    """
    db = _get_db()
    conn: Any = db._get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (key,))
            cur.execute(
                "DELETE FROM rate_limit_hits WHERE limit_key = %s AND hit_at < now() - make_interval(secs => %s)",
                (key, window_seconds),
            )
            cur.execute("SELECT COUNT(*) FROM rate_limit_hits WHERE limit_key = %s", (key,))
            (count,) = cur.fetchone()
            allowed = count < max_requests
            if allowed:
                cur.execute("INSERT INTO rate_limit_hits (limit_key, hit_at) VALUES (%s, now())", (key,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return allowed


def rate_limit(max_requests: int, window_seconds: int = 60):
    """Limit a view to ``max_requests`` per ``window_seconds`` per client IP.

    Disabled automatically when the Flask app is in testing mode. Fails
    open (allows the request) if the rate-limit check itself errors, since
    a database hiccup here shouldn't take down an otherwise-healthy AI
    endpoint — this limiter blunts abuse, it isn't the primary safeguard.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if current_app.testing:
                return fn(*args, **kwargs)

            if "DATABASE_URL" not in os.environ:
                # Distinct from the generic fail-open below: a transient DB
                # hiccup is fine to wave through, but a deployment that's
                # simply missing its DB config would otherwise silently and
                # permanently run this metered endpoint with no rate
                # limiting at all, which should be loud, not silent.
                logger.error(
                    "DATABASE_URL is not set; refusing %s without rate limiting",
                    request.path,
                )
                return jsonify({"error": "Service temporarily unavailable"}), 503

            key = f"{request.remote_addr}:{request.path}"
            try:
                allowed = _check_and_record(key, max_requests, window_seconds)
            except Exception:
                logger.exception("Rate limit check failed for %s; failing open", key)
                allowed = True

            if not allowed:
                return jsonify({"error": "Rate limit exceeded, try again later"}), 429

            return fn(*args, **kwargs)

        return wrapped

    return decorator
