"""Report writers: JSON (machine), Markdown (tickets), HTML (self-contained)."""

from __future__ import annotations

import datetime as dt
import html
import json
import os
from typing import List, Optional

from .codebase import CodebaseReport
from .model import CodebaseFix, Finding, ScanResult
from .version import format_version
from .vulndb import VULNERABILITIES


def _stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def out_dir(base: str = "php2shell-reports") -> str:
    os.makedirs(base, exist_ok=True)
    return base


# ---------------------------------------------------------------------------
def write_json(scan: Optional[ScanResult], code: Optional[CodebaseReport],
               fixes: List[CodebaseFix], base: str = "php2shell-reports") -> str:
    payload = {
        "tool": "php2shell-scanner",
        "version": "1.0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "scan": scan.to_dict() if scan else None,
        "codebase": None if not code else {
            "root": code.root,
            "files_scanned": code.files_scanned,
            "php_files": code.php_files,
            "runtimes": [
                {
                    "path": r.path, "line": r.line_no, "raw": r.raw,
                    "version": format_version(r.version), "kind": r.kind,
                }
                for r in code.runtimes
            ],
            "findings": [f.to_dict() for f in code.findings],
        },
        "proposed_fixes": [
            {
                "path": f.path, "source": f.source, "reason": f.reason,
                "applied": f.applied, "backup": f.backup,
                "changed": f.changed,
            }
            for f in fixes
        ],
    }
    path = os.path.join(out_dir(base), f"report-{_stamp()}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def write_markdown(scan: Optional[ScanResult], code: Optional[CodebaseReport],
                   fixes: List[CodebaseFix], base: str = "php2shell-reports") -> str:
    lines: List[str] = []
    a = lines.append
    a("# php2shell exposure report")
    a("")
    a(f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    a("")
    if scan:
        a("## Remote assessment")
        a("")
        a("| Field | Value |")
        a("| --- | --- |")
        for k, v in [
            ("Target", scan.target),
            ("Resolved IP", scan.resolved_ip or "n/a"),
            ("PHP detected", "yes" if scan.is_php else "no"),
            ("PHP version", format_version(scan.php_version)),
            ("Version source", scan.version_source or "n/a"),
            ("Server", scan.server_software or "n/a"),
            ("SAPI hints", scan.sapi or "n/a"),
            ("CMS", f"{scan.cms} {scan.cms_version}".strip() or "n/a"),
            ("Verdict", f"**{scan.verdict}** (risk {scan.risk_score}/100)"),
        ]:
            a(f"| {k} | {v} |")
        a("")
        if scan.status_reason:
            a(f"> {scan.status_reason}")
            a("")
        a("### Findings")
        a("")
        for f in scan.sorted_findings():
            a(f"#### `{f.severity}` {f.id} - {f.title}")
            a("")
            if f.detail:
                a(f.detail)
                a("")
            if f.evidence:
                a("```")
                a(f.evidence[:1500])
                a("```")
                a("")
            if f.remediation:
                a(f"**Remediation.** {f.remediation}")
                a("")
            if f.references:
                a("References: " + ", ".join(f"<{r}>" for r in f.references))
                a("")
    if code:
        a("## Code base")
        a("")
        a(f"Root: `{code.root}`  ")
        a(f"Files scanned: {code.files_scanned} (PHP: {code.php_files})")
        a("")
        if code.runtimes:
            a("| File | Line | Pin |")
            a("| --- | --- | --- |")
            for r in code.runtimes[:25]:
                a(f"| `{r.path}` | {r.line_no} | `{r.raw}` |")
            a("")
        if code.findings:
            a("### Code base findings")
            a("")
            for f in code.findings:
                a(f"- **{f.severity}** `{f.id}` {f.title}")
                if f.evidence:
                    a(f"  - evidence: `{f.evidence.splitlines()[0][:160]}`")
            a("")
    if fixes:
        a("## Proposed remediation")
        a("")
        for f in fixes:
            state = "applied" if f.applied else "proposed"
            a(f"- `{f.path}` ({f.source}, {state}) - {f.reason}")
            if f.backup:
                a(f"  - backup: `{f.backup}`")
        a("")

    a("## Background")
    a("")
    for v in VULNERABILITIES:
        a(f"- **{v.cve}** - {v.title} ({v.severity}, {v.cvss}). Fixed in {v.fixed_in}.")
        a(f"  {v.advisory}")
    a("")
    a("Sources: Huntress Rapid Response (2026-10-20/21) and Wiz Research "
      "\"PHP2Shell\" (2026-10-21).")
    path = os.path.join(out_dir(base), f"report-{_stamp()}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


# ---------------------------------------------------------------------------
COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
    "LOW": "#2563eb", "INFO": "#64748b",
}


def write_html(scan: Optional[ScanResult], code: Optional[CodebaseReport],
               fixes: List[CodebaseFix], base: str = "php2shell-reports") -> str:
    e = html.escape
    verdict = scan.verdict if scan else "UNKNOWN"
    score = scan.risk_score if scan else 0
    vcolor = {"VULNERABLE": "#dc2626", "PATCHED": "#16a34a",
              "UNKNOWN": "#ca8a04", "NOT_PHP": "#64748b"}.get(verdict, "#64748b")

    def finding_html(f: Finding) -> str:
        c = COLORS.get(f.severity, "#64748b")
        refs = " ".join(
            f'<a href="{e(r)}" style="color:#2563eb;text-decoration:none">{e(r[:60])}</a>'
            for r in f.references if r.startswith("http")
        )
        evidence = (
            f'<pre style="background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;'
            f'overflow:auto;font-size:12px;line-height:1.5;white-space:pre-wrap">{e(f.evidence[:2000])}</pre>'
            if f.evidence else ""
        )
        detail = e(f.detail).replace("\n", "<br>") if f.detail else ""
        rem = (
            f'<div style="margin-top:10px;padding:10px 12px;background:#f0fdf4;'
            f'border-left:3px solid #16a34a;border-radius:4px;font-size:13px">'
            f'<strong>Remediation.</strong> {e(f.remediation)}</div>' if f.remediation else ""
        )
        return f"""
        <div style="border:1px solid #e2e8f0;border-left:4px solid {c};border-radius:8px;
                    padding:16px 18px;margin-bottom:14px;background:#fff">
          <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
            <span style="background:{c};color:#fff;font-size:11px;font-weight:700;
                         letter-spacing:.06em;padding:3px 8px;border-radius:4px">{e(f.severity)}</span>
            <span style="font-family:ui-monospace,monospace;font-size:12px;color:#64748b">{e(f.id)}</span>
          </div>
          <div style="font-size:15px;font-weight:600;color:#0f172a;margin-bottom:6px">{e(f.title)}</div>
          <div style="font-size:13px;color:#334155;line-height:1.6">{detail}</div>
          {evidence}
          {rem}
          <div style="margin-top:8px;font-size:11px">{refs}</div>
        </div>"""

    findings = "".join(finding_html(f) for f in (scan.sorted_findings() if scan else []))
    code_findings = "".join(finding_html(f) for f in (code.findings if code else []))

    runtime_rows = ""
    if code and code.runtimes:
        rows = "".join(
            f'<tr><td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;'
            f'font-family:ui-monospace,monospace;font-size:12px">{e(r.path)}:{r.line_no}</td>'
            f'<td style="padding:6px 10px;border-bottom:1px solid #e2e8f0;'
            f'font-family:ui-monospace,monospace;font-size:12px">{e(r.raw)}</td></tr>'
            for r in code.runtimes[:25]
        )
        runtime_rows = f"""
        <h3 style="font-size:15px;margin:24px 0 10px">Pinned PHP runtimes</h3>
        <table style="width:100%;border-collapse:collapse;background:#fff;
                      border:1px solid #e2e8f0;border-radius:8px;overflow:hidden">
          <thead><tr style="background:#f8fafc;text-align:left">
            <th style="padding:8px 10px;font-size:12px;color:#475569">Location</th>
            <th style="padding:8px 10px;font-size:12px;color:#475569">Pin</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    fix_rows = ""
    if fixes:
        fix_rows = "".join(
            f'<li style="margin-bottom:8px;font-size:13px">'
            f'<code style="background:#f1f5f9;padding:2px 6px;border-radius:4px">{e(f.path)}</code> '
            f'<span style="color:#64748b">({e(f.source)}'
            f'{", applied" if f.applied else ", proposed"})</span><br>'
            f'<span style="color:#334155">{e(f.reason)}</span></li>'
            for f in fixes
        )
        fix_rows = f'<h3 style="font-size:15px;margin:24px 0 10px">Remediation plan</h3><ul>{fix_rows}</ul>'

    php_ver = format_version(scan.php_version) if scan else "not detected"
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>php2shell report - {e(scan.target if scan else 'codebase')}</title></head>
<body style="margin:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#0f172a">
<div style="max-width:880px;margin:0 auto;padding:32px 20px 64px">

  <div style="background:linear-gradient(135deg,#0f172a,#1e293b);border-radius:14px;
              padding:26px 28px;color:#fff;margin-bottom:22px">
    <div style="font-size:11px;letter-spacing:.14em;color:#94a3b8;text-transform:uppercase">
      php2shell exposure report</div>
    <div style="font-size:24px;font-weight:700;margin:8px 0 4px">
      {e(scan.target if scan else (code.root if code else 'unknown target'))}</div>
    <div style="font-size:13px;color:#cbd5e1">
      CVE-2026-109618 &amp; CVE-2026-109619 &middot; PHP engine RCE, CVSS 9.2 &middot;
      generated {dt.datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
    <div style="display:flex;gap:26px;margin-top:20px;flex-wrap:wrap">
      <div><div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.1em">Verdict</div>
        <div style="font-size:19px;font-weight:700;color:{vcolor}">{e(verdict)}</div></div>
      <div><div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.1em">Risk</div>
        <div style="font-size:19px;font-weight:700">{score}<span style="font-size:12px;color:#94a3b8">/100</span></div></div>
      <div><div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.1em">PHP</div>
        <div style="font-size:19px;font-weight:700">{e(php_ver)}</div></div>
      <div><div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.1em">CMS</div>
        <div style="font-size:19px;font-weight:700">{e((scan.cms if scan else '') or 'n/a')}</div></div>
    </div>
  </div>

  <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:14px 18px;
              font-size:13px;color:#7c2d12;margin-bottom:22px">
    <strong>Read this first.</strong> These are bugs in the PHP engine, not in the CMS or the
    application. Application hardening cannot fix them. The only complete remediation is
    PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (or a vendor backport). Where patching is not
    possible today, disable <code>session.upload_progress</code>.
  </div>

  <h2 style="font-size:17px;margin:0 0 12px">Remote findings</h2>
  {findings or '<p style="color:#64748b;font-size:13px">No remote findings recorded.</p>'}

  {('<h2 style="font-size:17px;margin:28px 0 12px">Code base findings</h2>' + code_findings) if code_findings else ''}
  {runtime_rows}
  {fix_rows}

  <h2 style="font-size:17px;margin:28px 0 10px">Sources</h2>
  <ul style="font-size:13px;color:#334155;line-height:1.8">
    <li><a href="https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities"
           style="color:#2563eb">Huntress - Rapid Response: php2shell (2026-10-20/21)</a></li>
    <li><a href="https://www.wiz.io/blog/php2shell-php-rce"
           style="color:#2563eb">Wiz Research - PHP2Shell (2026-10-21)</a></li>
    <li><a href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"
           style="color:#2563eb">GHSA-w8hw-w9fx-j79w (CVE-2026-109618)</a></li>
    <li><a href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
           style="color:#2563eb">GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)</a></li>
  </ul>
  <div style="margin-top:28px;padding-top:14px;border-top:1px solid #e2e8f0;
              font-size:11px;color:#94a3b8">
    Scan only systems you are authorised to test. This tool fingerprints and reports;
    it does not exploit.
  </div>
</div></body></html>"""
    path = os.path.join(out_dir(base), f"report-{_stamp()}.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
