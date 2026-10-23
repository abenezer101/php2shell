#!/usr/bin/env python3
"""Tiny fake PHP host used to exercise the scanner locally.

It imitates a WordPress box on PHP 8.1.2: X-Powered-By, PHPSESSID cookies and
wp-content paths. It serves nothing real and executes nothing.

    python3 examples/fake_php_host.py --port 8089 --version 8.1.2
"""

from __future__ import annotations

import argparse
import random
import string
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"""<!DOCTYPE html>
<html><head><title>Demo site</title>
<meta name="generator" content="WordPress 6.4.2"></head>
<body>
<h1>It works</h1>
<div class="entry"><p>Hello from a PHP page.</p></div>
<a href="/index.php">home</a>
<script src="/wp-includes/js/jquery.js"></script>
</body></html>
"""


def make_handler(version: str, expose: bool):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Apache/2.4.56 (Debian)"
        sys_version = ""

        def log_message(self, *a):  # keep the console clean
            pass

        def _send(self, status: int, body: bytes, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if expose:
                self.send_header("X-Powered-By", f"PHP/{version}")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.php", "/wp-login.php"):
                sid = "".join(random.choices(string.ascii_lowercase + string.digits, k=26))
                self._send(200, BODY, {"Set-Cookie": f"PHPSESSID={sid}; path=/"})
            elif path == "/info.php":
                self._send(200, f"<html><body>PHP Version {version}</body></html>".encode())
            else:
                self._send(404, b"<html><body>Not found</body></html>")

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            sid = "".join(random.choices(string.ascii_lowercase + string.digits, k=26))
            self._send(200, BODY, {"Set-Cookie": f"PHPSESSID={sid}; path=/"})

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--version", default="8.1.2")
    ap.add_argument("--no-expose", action="store_true",
                    help="hide X-Powered-By (simulates expose_php=Off)")
    args = ap.parse_args()

    handler = make_handler(args.version, not args.no_expose)
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), handler)
    print(f"fake PHP {args.version} on http://127.0.0.1:{args.port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
