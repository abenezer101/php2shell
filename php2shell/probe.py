"""Opt-in active checks.

These are deliberately *behavioural*, not exploitative: the tool never sends a
payload that corrupts memory or executes code. It reproduces only the benign
request shapes that the public write-ups say sit next to the bug, and looks for
observable symptoms.

They are off by default. Run them only against systems you are authorised to
test, and prefer the passive verdict when in doubt.
"""

from __future__ import annotations

import random
import string
import time
from typing import List, Optional

from .detect import cookie_is_suspicious
from .http import HttpClient, Response
from .model import EvidenceItem, Finding, ScanResult


def _boundary() -> str:
    return "----php2shellscan" + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=16)
    )


def build_multipart(fields: dict) -> tuple:
    """A plain, well-formed RFC1867 body - nothing malicious."""
    boundary = _boundary()
    parts: List[bytes] = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode()
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return boundary, b"".join(parts)


def run_probes(client: HttpClient, result: ScanResult, burst: int = 5,
               verbose: bool = False) -> ScanResult:
    """Execute the opt-in checks and annotate the ScanResult."""
    if not result.is_php:
        result.notes.append("Active probes skipped: target is not confirmed PHP.")
        return result

    _probe_session_cookie_shape(client, result, verbose)
    _probe_multipart_stability(client, result, burst, verbose)

    result.add(
        Finding(
            id="PHP2SHELL-DETECT-GUIDANCE",
            title="Post-compromise and exploitation indicators to hunt for",
            severity="INFO",
            category="detection-engineering",
            detail="\n".join(f"- {i}" for i in _indicator_list()),
            evidence="Wiz detection guidance + Huntress process-lineage hunting advice.",
            remediation=(
                "Feed these into your SIEM/EDR. If any of them fired before you patched, "
                "treat the host as compromised, image it, rotate every secret the worker "
                "could read, and rebuild from a patched image."
            ),
            references=[
                "https://www.wiz.io/blog/php2shell-php-rce",
                "https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities",
                "https://github.com/Neo23x0/process-watcher",
            ],
        )
    )
    return result


def _indicator_list() -> List[str]:
    from .vulndb import BEHAVIOURAL_INDICATORS
    return BEHAVIOURAL_INDICATORS


def _probe_session_cookie_shape(client: HttpClient, result: ScanResult,
                                verbose: bool) -> None:
    """Ask for a normal multipart POST and inspect the session cookie shape.

    A cookie containing percent-encoded binary after a multipart request is the
    documented symptom of the stale PS(id) pointer path. A normal PHP session id
    is 26-32 alphanumeric characters.
    """
    boundary, body = build_multipart({"php2shell_scan": "shape-check"})
    resp = client.post(
        result.target,
        body=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        },
    )
    result.probes_run += 1
    result.evidence.append(
        EvidenceItem(label="multipart cookie-shape probe", url=resp.url,
                     status=resp.status, headers={"set-cookie": resp.header("set-cookie")},
                     note=resp.error or "")
    )
    if verbose:
        print(f"    [cookie-shape probe] {resp.url} -> {resp.status or resp.error}")

    for cookie in resp.header_list("set-cookie"):
        if not cookie.lower().startswith("phpsessid"):
            continue
        value = cookie.split(";", 1)[0].partition("=")[2]
        if cookie_is_suspicious(value):
            result.add(
                Finding(
                    id="PHP2SHELL-COOKIE-ANOMALY",
                    title="PHPSESSID response cookie contains percent-encoded binary",
                    severity="CRITICAL",
                    category="active-probe",
                    detail=(
                        "A multipart request produced a session cookie whose value is a long "
                        "percent-encoded blob. That is the signature Wiz described for the "
                        "stale PS(id) pointer path being used to URL-encode reclaimed worker "
                        "memory into a response cookie. Treat this host as actively leaking "
                        "process memory, and therefore as compromised-adjacent: the same "
                        "primitives chain into RCE."
                    ),
                    evidence=f"PHPSESSID length={len(value)}, sample={value[:120]!r}",
                    remediation="Patch immediately, then rotate every secret in the "
                                "application's config and invalidate sessions.",
                    references=["https://www.wiz.io/blog/php2shell-php-rce"],
                )
            )


def _probe_multipart_stability(client: HttpClient, result: ScanResult,
                               burst: int, verbose: bool) -> None:
    """Send a handful of ordinary multipart requests and count 5xx/resets.

    Repeated 500s and worker churn alongside multipart traffic are the
    low-noise signal the write-ups point defenders at. A normal site returns
    200/302/403 here, so a 5xx cluster is worth flagging even though it is not
    proof of exploitability.
    """
    errors = 0
    fives = 0
    latency: List[float] = []
    for i in range(max(1, burst)):
        boundary, body = build_multipart({"php2shell_scan": f"stability-{i}"})
        resp = client.post(
            result.target,
            body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        result.probes_run += 1
        latency.append(resp.elapsed)
        if resp.error:
            errors += 1
        if resp.status >= 500:
            fives += 1
        time.sleep(0.2)

    if verbose:
        print(f"    [stability probe] {fives} x 5xx, {errors} transport errors "
              f"in {len(latency)} requests")

    if fives or errors:
        result.add(
            Finding(
                id="PHP2SHELL-STABILITY",
                title=f"Multipart requests produced {fives} server error(s) and {errors} failure(s)",
                severity="MEDIUM" if fives >= 2 else "LOW",
                category="active-probe",
                detail=(
                    "Ordinary multipart upload requests drew repeated 5xx responses or "
                    "dropped connections. On its own this is a stability symptom, but the "
                    "combination of multipart traffic plus 500s plus eventual worker churn "
                    "is exactly the pattern investigators were told to look for."
                ),
                evidence=f"{fives} x HTTP 5xx, {errors} transport errors out of {len(latency)}",
                remediation="Check the PHP error log for memory-limit fatals during the "
                            "scan window, then patch and review worker restart counts.",
            )
        )
