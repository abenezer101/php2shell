"""Fingerprint a remote web target: is it PHP, which version, which stack."""

from __future__ import annotations

import re
import socket
from typing import List, Optional, Tuple

from . import vulndb
from .http import HttpClient, Response, host_of, join, normalize_target
from .model import EvidenceItem, Finding, ScanResult
from .version import format_version, parse_version

# Percent-encoded binary in a Set-Cookie is the memory-disclosure signature.
PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")

PHP_BODY_MARKERS = [
    (r"\.php(?:\?|\"|'|\s|$)", 2, "links or form actions ending in .php"),
    (r"(?:Fatal error|Parse error|Warning|Notice):\s+.{0,200}? in\s+/[\w./-]+\.php", 4,
     "PHP error message leaked in the response"),
    (r"PHP Version\s*[:=]?\s*\d", 4, "explicit 'PHP Version' string"),
    (r"X-Powered-By:\s*PHP", 3, "X-Powered-By echoed in body"),
    (r"<meta[^>]+generator[^>]+WordPress", 2, "WordPress generator meta tag"),
    (r"wp-content/|wp-includes/", 2, "WordPress asset paths"),
    (r"sites/default/files|/core/misc/drupal", 2, "Drupal asset paths"),
    (r"/media/system/js/|/administrator/", 2, "Joomla asset paths"),
    (r"PHPSESSID", 3, "PHPSESSID referenced in the response body"),
]

# Well-known paths that only exist on a given stack, used to confirm PHP.
PHP_CONFIRM_PATHS = [
    ("index.php", "typical PHP front controller"),
    ("index.php?=PHPE9568F36-D428-11d2-A769-00AA001ACF42", "PHP logo easter egg (expose_php)"),
    ("wp-login.php", "WordPress login"),
    ("administrator/index.php", "Joomla administrator"),
    ("core/install.php", "Drupal installer"),
    ("info.php", "phpinfo page"),
    ("phpinfo.php", "phpinfo page"),
    ("server-status", "mod_status (also reveals SAPI)"),
]

CMS_PATHS = {
    "WordPress": [
        ("wp-login.php", r"user_login|wp-submit"),
        ("wp-includes/version.php", r"\$wp_version"),
        ("feed/", r"<generator>https://wordpress.org/\?v=([\d.]+)"),
    ],
    "Drupal": [
        ("core/CHANGELOG.txt", r"Drupal ([\d.]+)"),
        ("CHANGELOG.txt", r"Drupal ([\d.]+)"),
        ("core/lib/Drupal.php", r"VERSION = '([\d.]+)'"),
    ],
    "Joomla": [
        ("administrator/manifests/files/joomla.xml", r"<version>([\d.]+)</version>"),
        ("language/en-GB/en-GB.xml", r"<version>([\d.]+)</version>"),
    ],
}

VERSION_PATTERNS = [
    # (regex, source label)
    (re.compile(r"PHP/(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)", re.I), "X-Powered-By / Server header"),
    (re.compile(r"X-Powered-By:\s*PHP/([\d.]+)", re.I), "X-Powered-By header"),
    (re.compile(r"PHP Version\s*([\d.]+)", re.I), "page output"),
    (re.compile(r'"php"\s*:\s*"[\^~>=< ]*(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)"', re.I), "composer.json"),
    (re.compile(r"php_fpm_version[^0-9]{0,20}(\d{1,2}\.\d{1,2}\.\d{1,3})", re.I), "status page"),
]


class Detector:
    """Runs a bounded, polite reconnaissance pass against one target."""

    MAX_PATHS = 12

    def __init__(self, client: HttpClient, verbose: bool = False) -> None:
        self.client = client
        self.verbose = verbose
        self.result = ScanResult(target="")
        self._path_hits = 0

    # -- entry point ------------------------------------------------------
    def run(self, target: str) -> ScanResult:
        url = normalize_target(target)
        self.result.target = url

        root = self.client.get(url)
        if root.error and url.startswith("https://"):
            # Common for dev/staging boxes without TLS; retry plainly.
            alt = "http://" + url[len("https://"):]
            retry = self.client.get(alt)
            if not retry.error:
                self.result.notes.append(
                    "HTTPS failed, target answered over plain HTTP. Traffic is unencrypted."
                )
                url = alt
                self.result.target = url
                root = retry
        if root.error:
            self.result.notes.append(f"Target unreachable: {root.error}")
            self._add_network_finding(root.error)
            return self.result

        self._resolve_ip(url)
        self._record("root request", url, root)

        score, reasons = self._score_php(root)
        state: List = [score, reasons]
        self._score_paths(url, state)
        score, reasons = state[0], state[1]

        self.result.php_confidence = score
        self.result.is_php = score >= 3

        self._extract_version([root])
        self._detect_cms(url, root)
        self._detect_server(root)
        self._assess()

        if not self.result.is_php:
            self.result.notes.append(
                "No reliable PHP indicators. The php2shell CVEs live in the PHP engine; "
                "if this host runs PHP behind a reverse proxy, re-scan the origin directly."
            )
        return self.result

    # -- detection stages -------------------------------------------------
    def _score_php(self, root: Response) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        xpb = root.header("x-powered-by")
        if "php" in xpb.lower():
            score += 4
            reasons.append(f"X-Powered-By header: {xpb}")
        if "php" in root.header("server").lower():
            score += 3
            reasons.append(f"Server header mentions PHP: {root.header('server')}")
        for cookie in root.header_list("set-cookie"):
            if cookie.lower().startswith("phpsessid"):
                score += 4
                reasons.append("PHPSESSID cookie issued")

        body = root.text
        for pattern, weight, label in PHP_BODY_MARKERS:
            if re.search(pattern, body, re.I):
                score += weight
                reasons.append(f"Body indicator: {label}")

        if root.header("x-pingback") or root.header("link", ).find("wp-json") >= 0:
            score += 2
            reasons.append("WordPress REST/pingback headers")

        self.result.evidence.append(
            EvidenceItem(label="php indicators", url=root.url, status=root.status,
                         headers=_interesting_headers(root),
                         note="; ".join(reasons[:6]) or "none")
        )
        return score, reasons

    def _score_paths(self, url: str, state: List) -> None:
        """Follow up with a small, fixed set of paths to confirm the stack."""
        root_score = state[0] if state else 0
        reasons = state[1] if len(state) > 1 else []
        for path, label in PHP_CONFIRM_PATHS[: self.MAX_PATHS]:
            target = join(url, path)
            resp = self.client.get(target)
            if resp.error or resp.status >= 500:
                continue
            if resp.status == 404:
                continue
            # A 200/403/302 on a PHP-specific path is meaningful only if the
            # body or headers corroborate it.
            hay = (resp.text[:20000] + "\n" + "\n".join(resp.headers.values())).lower()
            if path.startswith("index.php?=PHPE9568"):
                if resp.status == 200 and resp.body[:4] == b"\x89PNG":
                    root_score += 4
                    reasons.append("PHP logo returned by the expose_php easter-egg path")
            elif path in ("info.php", "phpinfo.php") and "php version" in hay:
                root_score += 5
                reasons.append(f"phpinfo exposed at /{path}")
                self._extract_version([resp])
            elif "phpsessid" in hay:
                root_score += 3
                reasons.append(f"/{path} issues PHPSESSID ({label})")
            elif path in ("wp-login.php", "administrator/index.php", "core/install.php") and (
                resp.status in (200, 302, 403)
            ):
                root_score += 2
                reasons.append(f"/{path} reachable ({label})")
            elif path == "server-status" and re.search(r"php|fpm", hay):
                root_score += 2
                reasons.append("mod_status page exposes SAPI info")
                self._extract_version([resp])

            self._record(f"path probe /{path}", target, resp)
            if root_score >= 8:
                break

        state[:] = [root_score, reasons]

    def _extract_version(self, responses: List[Response]) -> None:
        if self.result.php_version:
            return
        for resp in responses:
            haystacks = [
                resp.header("x-powered-by"),
                resp.header("server"),
                resp.text[:60000],
            ]
            for hay in haystacks:
                if not hay:
                    continue
                for pattern, source in VERSION_PATTERNS:
                    m = pattern.search(hay)
                    if not m:
                        continue
                    v = parse_version(m.group(1))
                    if v and 5 <= v[0] <= 9:
                        self.result.php_version = v
                        self.result.version_source = source
                        return

    def _detect_cms(self, url: str, root: Response) -> None:
        body = root.text
        quick = {
            "WordPress": r"wp-content|wp-includes|wp-json",
            "Drupal": r"Drupal|sites/default/files|drupal",
            "Joomla": r"/media/system/js/|Joomla",
            "MediaWiki": r"MediaWiki|mw-",
        }
        for name, pat in quick.items():
            if re.search(pat, body, re.I):
                self.result.cms = name
                break

        # Generator meta tags are the cheapest reliable version source.
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if m:
            gen = m.group(1)
            vm = re.search(r"([\d]+\.[\d.]+)", gen)
            if vm:
                self.result.cms_version = vm.group(1)
            if "wordpress" in gen.lower():
                self.result.cms = "WordPress"

        if self.result.cms and not self.result.cms_version:
            for path, pattern in CMS_PATHS.get(self.result.cms, [])[:3]:
                resp = self.client.get(join(url, path))
                if resp.error:
                    continue
                m = re.search(pattern, resp.text[:40000], re.I)
                if m and m.groups():
                    self.result.cms_version = m.group(1)
                    self._record(f"cms version /{path}", resp.url, resp)
                    break

    def _detect_server(self, root: Response) -> None:
        self.result.server_software = root.header("server")
        xpb = root.header("x-powered-by")
        hints = []
        if "fpm" in xpb.lower() or "fpm" in root.header("server").lower():
            hints.append("php-fpm")
        if any(name in self.result.server_software.lower() for name in ("apache", "httpd")):
            hints.append("mod_php (likely)")
        if "x-accel" in " ".join(root.headers.keys()):
            hints.append("litespeed/nginx front")
        self.result.sapi = ", ".join(hints)

    # -- verdict ----------------------------------------------------------
    def _assess(self) -> None:
        res = self.result
        if not res.is_php:
            res.status = "UNKNOWN"
            res.status_reason = "PHP not confirmed on this target."
            return

        status, reason = vulndb.assess(res.php_version)
        res.status = status
        res.status_reason = reason

        if status == "VULNERABLE":
            for vuln in vulndb.VULNERABILITIES:
                res.add(
                    Finding(
                        id=f"PHP2SHELL-{vuln.cve}",
                        title=f"{vuln.cve}: {vuln.title}",
                        severity=vuln.severity,
                        category="vulnerable-php-runtime",
                        detail=f"{vuln.summary}\n\nImpact: {vuln.impact}",
                        evidence=(
                            f"Detected PHP {format_version(res.php_version)} via "
                            f"{res.version_source or 'passive fingerprint'}; fixed in "
                            f"{vuln.fixed_in}."
                        ),
                        remediation=(
                            f"Upgrade to {vuln.fixed_in} (or your vendor's backport). "
                            "If you cannot patch today, set "
                            "session.upload_progress.enabled = Off and isolate the host "
                            "behind the vendor WAF rules for this disclosure."
                        ),
                        references=[vuln.advisory, "https://www.php.net/downloads.php?source=Y"],
                    )
                )
            res.add(
                Finding(
                    id="PHP2SHELL-MITIGATE",
                    title="Interim mitigation available while you schedule the upgrade",
                    severity="MEDIUM",
                    category="configuration",
                    detail="\n".join(f"- {m}" for m in vulndb.MITIGATIONS),
                    evidence="PHP security advisory 2026-10-21.",
                    remediation="Apply the php.ini / pool changes, then restart the SAPI.",
                    references=["https://www.php.net/index.php#2026-10-20-1"],
                )
            )
        elif status == "PATCHED":
            res.add(
                Finding(
                    id="PHP2SHELL-PATCHED",
                    title=f"PHP {format_version(res.php_version)} includes the php2shell fixes",
                    severity="INFO",
                    category="vulnerable-php-runtime",
                    detail=(
                        "The detected release is at or above the fixed version for its "
                        "branch, so CVE-2026-109618 and CVE-2026-109619 are remediated "
                        "at the engine level."
                    ),
                    evidence=f"Detected via {res.version_source or 'passive fingerprint'}.",
                    remediation="Keep the runtime patched; verify no other PHP install "
                                "(container, panel, cron, CLI) is still on an old build.",
                )
            )
        else:
            res.add(
                Finding(
                    id="PHP2SHELL-UNKNOWN",
                    title="PHP detected but the runtime version could not be verified",
                    severity="HIGH",
                    category="unverifiable",
                    detail=(
                        "The version is hidden or unreachable from the outside. Every PHP "
                        "release back to 5.4 is affected by at least one of the two CVEs, so "
                        "an unverified host must be treated as exposed until someone checks "
                        "`php -v` on the box."
                    ),
                    evidence=res.status_reason,
                    remediation="Run `php -v` (and check the panel/container tag), then "
                                "re-scan with --php-version if it is not externally visible.",
                )
            )

        # Configuration hygiene that matters for this class of bug.
        if res.version_source in ("X-Powered-By / Server header", "X-Powered-By header"):
            res.add(
                Finding(
                    id="PHP2SHELL-EXPOSE-PHP",
                    title="PHP advertises its exact version in HTTP headers (expose_php=On)",
                    severity="LOW",
                    category="configuration",
                    detail=(
                        "Version disclosure is not a vulnerability, but it lets an attacker "
                        "pick the matching php2shell exploit chain without guessing, and it "
                        "tells them when you have not patched yet."
                    ),
                    evidence=f"X-Powered-By: {res.version_source}",
                    remediation="Set expose_php = Off in php.ini.",
                )
            )

        cms = res.cms
        if cms:
            res.add(
                Finding(
                    id="PHP2SHELL-CMS-CONTEXT",
                    title=f"{cms} {res.cms_version} detected on an application-agnostic flaw".replace("  ", " "),
                    severity="INFO",
                    category="context",
                    detail=(
                        vulndb.CMS_RUNTIME_HINTS.get(cms, "")
                        + " Note that this is not a CMS bug: the vulnerable code is the PHP "
                        "engine itself, so application-level patching will not help."
                    ),
                    evidence=f"{cms} {res.cms_version}".strip(),
                    remediation="Patch PHP, then confirm the CMS still runs on the new runtime.",
                )
            )

    # -- misc -------------------------------------------------------------
    def _resolve_ip(self, url: str) -> None:
        host = host_of(url)
        try:
            self.result.resolved_ip = socket.gethostbyname(host)
        except Exception:
            self.result.resolved_ip = None

    def _record(self, label: str, url: str, resp: Response) -> None:
        self.result.probes_run += 1
        self.result.evidence.append(
            EvidenceItem(label=label, url=url, status=resp.status,
                         headers=_interesting_headers(resp),
                         note=resp.error or "")
        )
        if self.verbose:
            print(f"    [{label}] {url} -> {resp.status or resp.error}")

    def _add_network_finding(self, error: str) -> None:
        self.result.add(
            Finding(
                id="SCAN-TRANSPORT",
                title="Target could not be reached",
                severity="INFO",
                category="transport",
                detail=f"The scanner could not complete a request: {error}",
                evidence=error,
                remediation="Confirm DNS, egress firewall rules and that the host serves "
                            "HTTP(S). Scanning an origin behind a CDN requires scanning the "
                            "origin directly.",
            )
        )


def _interesting_headers(resp: Response) -> dict:
    keep = ("server", "x-powered-by", "set-cookie", "via", "x-cache",
            "x-litespeed-cache", "x-fpm", "cf-ray", "x-served-by")
    return {k: v for k, v in resp.headers.items() if k in keep}


def cookie_is_suspicious(value: str) -> bool:
    """Heuristic for the memory-disclosure signature in a PHPSESSID value.

    PHP session ids are short alphanumerics. A cookie carrying percent-encoded
    binary or a very long high-entropy blob is the shape Wiz reported for the
    leaked worker-memory cookie.
    """
    if not value:
        return False
    encoded = len(PCT_RE.findall(value))
    if len(value) > 90 and encoded >= 8:
        return True
    if encoded >= 24:
        return True
    return False
