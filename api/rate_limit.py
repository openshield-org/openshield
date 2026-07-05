"""Minimal in-memory sliding-window rate limiter for Flask routes.

Not a substitute for a distributed limiter (e.g. Redis-backed) behind a
load balancer with multiple worker processes, but sufficient to blunt basic
abuse of endpoints that proxy to metered third-party APIs.
"""

import threading
import time
from functools import wraps

from flask import current_app, jsonify, request

_lock = threading.Lock()
_hits: dict[str, list[float]] = {}


def rate_limit(max_requests: int, window_seconds: int = 60):
    """Limit a view to ``max_requests`` per ``window_seconds`` per client IP.

    Disabled automatically when the Flask app is in testing mode.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if current_app.testing:
                return fn(*args, **kwargs)

            key = f"{request.remote_addr}:{request.path}"
            now = time.monotonic()
            with _lock:
                recent = [t for t in _hits.get(key, ()) if now - t < window_seconds]
                if len(recent) >= max_requests:
                    return jsonify({"error": "Rate limit exceeded, try again later"}), 429
                recent.append(now)
                _hits[key] = recent

            return fn(*args, **kwargs)

        return wrapped

    return decorator
