#!/usr/bin/env python3
"""A static file server for the Playwright suite that actually applies
vercel.json's header rules - including the real Content-Security-Policy -
instead of `python3 -m http.server`'s no-headers-at-all behavior.

Without this, the entire browser suite could pass while the deployed CSP
header was absent or broken: nothing in the suite would ever see it. See
the "CSP is exercised" tests in security.spec.js, and issue #297.

Usage: python3 tests/csp_server.py [port]   (run from website/)
"""

import http.server
import json
import re
import sys
from pathlib import Path

_WEBSITE_ROOT = Path(__file__).resolve().parent.parent


def _load_header_rules():
    with open(_WEBSITE_ROOT / "vercel.json") as f:
        config = json.load(f)
    # Compile each rule's Vercel "source" glob once. These two source
    # patterns are already valid Python regexes (parenthesised wildcards),
    # which is all this test harness needs to support - it is not a
    # general-purpose Vercel routing engine.
    return [(re.compile(f"^{rule['source']}$"), rule["headers"]) for rule in config["headers"]]


_HEADER_RULES = _load_header_rules()


class CSPAwareHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(_WEBSITE_ROOT), **kwargs)

    def end_headers(self):
        # Vercel applies every matching rule's headers, not just the first
        # match - a request to /assets/foo.js gets both the assets-only
        # Cache-Control rule and the site-wide security headers rule.
        path = self.path.split("?", 1)[0]
        for pattern, headers in _HEADER_RULES:
            if pattern.match(path):
                for header in headers:
                    self.send_header(header["key"], header["value"])
        super().end_headers()

    def log_message(self, format, *args):  # noqa: A002 - matches base class signature
        pass  # Keep Playwright's webServer output quiet, matching http.server's prior silence.


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4173
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), CSPAwareHandler)
    server.serve_forever()
