"""Minimal HTTP client built on the standard library.

No third-party dependencies, no redirect-following into other hosts by default,
and no automatic decompression (we ask for identity so response bodies stay
comparable when we hunt for fingerprints).
"""

from __future__ import annotations

import gzip
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

DEFAULT_UA = (
    "Mozilla/5.0 (compatible; php2shell-scanner/1.0; "
    "+https://www.wiz.io/blog/php2shell-php-rce)"
)


@dataclass
class Response:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed: float = 0.0
    error: Optional[str] = None
    redirect_to: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status < 500

    @property
    def text(self) -> str:
        for enc in ("utf-8", "latin-1"):
            try:
                return self.body.decode(enc, errors="replace")
            except Exception:
                continue
        return ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def header_list(self, name: str) -> List[str]:
        val = self.header(name)
        if not val:
            return []
        # Dict merging below joins with "\n" so multiple Set-Cookie survive.
        return [v.strip() for v in val.split("\n") if v.strip()]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Record redirects instead of silently chasing them off-host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class HttpClient:
    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_UA,
        verify_tls: bool = True,
        proxy: Optional[str] = None,
        delay: float = 0.35,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.delay = delay
        self._last = 0.0
        self.cookies: Dict[str, str] = {}

        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        handlers: List[urllib.request.BaseHandler] = [
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ctx),
        ]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        self.opener = urllib.request.build_opener(*handlers)

    # -- low level --------------------------------------------------------
    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        read_limit: int = 512 * 1024,
    ) -> Response:
        # Politeness: never hammer a target.
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)

        hdrs = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if headers:
            hdrs.update(headers)

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        started = time.time()
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(read_limit)
                out = Response(
                    url=url,
                    status=resp.status,
                    headers=_merge_headers(resp.headers),
                    body=_maybe_decompress(raw, resp.headers),
                    elapsed=time.time() - started,
                )
                self._absorb_cookies(resp.headers)
                return out
        except urllib.error.HTTPError as exc:
            raw = b""
            try:
                raw = exc.read(read_limit)
            except Exception:
                pass
            out = Response(
                url=url,
                status=exc.code,
                headers=_merge_headers(exc.headers),
                body=_maybe_decompress(raw, exc.headers),
                elapsed=time.time() - started,
                redirect_to=(exc.headers.get("Location") if exc.headers else None),
            )
            if exc.headers:
                self._absorb_cookies(exc.headers)
            return out
        except urllib.error.URLError as exc:
            return Response(url=url, elapsed=time.time() - started,
                            error=_describe_network_error(exc.reason))
        except (socket.timeout, TimeoutError):
            return Response(url=url, elapsed=time.time() - started,
                            error=f"timeout after {self.timeout}s")
        except ssl.SSLError as exc:
            return Response(url=url, elapsed=time.time() - started,
                            error=f"TLS error: {exc}")
        except Exception as exc:  # pragma: no cover - defensive
            return Response(url=url, elapsed=time.time() - started,
                            error=f"{type(exc).__name__}: {exc}")
        finally:
            self._last = time.time()

    def get(self, url: str, **kw) -> Response:
        return self.request(url, "GET", **kw)

    def post(self, url: str, body: bytes = b"", headers=None, **kw) -> Response:
        return self.request(url, "POST", headers=headers, body=body, **kw)

    # -- helpers ----------------------------------------------------------
    def _absorb_cookies(self, headers) -> None:
        if not headers:
            return
        try:
            items = headers.get_all("Set-Cookie") or []
        except Exception:
            items = []
        for item in items:
            pair = item.split(";", 1)[0]
            if "=" in pair:
                k, v = pair.split("=", 1)
                self.cookies[k.strip()] = v.strip()


def _merge_headers(headers) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not headers:
        return out
    for key, value in headers.items():
        k = key.lower()
        out[k] = f"{out[k]}\n{value}" if k in out else value
    return out


def _maybe_decompress(raw: bytes, headers) -> bytes:
    enc = (headers.get("Content-Encoding") or "").lower() if headers else ""
    try:
        if "gzip" in enc:
            return gzip.decompress(raw)
        if "deflate" in enc:
            return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        return raw
    return raw


def _describe_network_error(reason) -> str:
    text = str(reason)
    if "Name or service not known" in text or "nodename nor servname" in text:
        return "DNS resolution failed"
    if "Connection refused" in text:
        return "connection refused"
    if "certificate" in text.lower():
        return f"TLS certificate problem ({text})"
    return text


def normalize_target(target: str) -> str:
    """Turn 'example.com' or 'example.com/app' into an https URL, then fall
    back to http if https fails to connect (checked by the caller)."""
    target = target.strip()
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return "https://" + target.rstrip("/")


def host_of(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def join(base: str, path: str) -> str:
    return urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
