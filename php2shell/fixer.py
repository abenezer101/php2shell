"""Turn findings into concrete edits in the user's code base.

Flow:
  1. deterministic rules fix what is mechanical (upload-progress flag, exact
     patch-level image bumps);
  2. the LLM reviews the remaining pins and proposes edits as JSON;
  3. every edit is written as a unified diff first, then optionally applied
     with a .bak backup next to the original.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import time
from typing import Dict, List, Optional

from .codebase import CodebaseReport, is_editable, load_mitigation_snippet
from .llm import LLMClient, LLMError, parse_patch_json
from .model import CodebaseFix, ScanResult
from .version import format_version
from .vulndb import FIXED_RELEASES, VULNERABILITIES

MAX_FILES_TO_MODEL = 8
MAX_CHARS_PER_FILE = 12_000
MAX_TOTAL_CHARS = 60_000

SYSTEM_PROMPT = """You are a senior PHP platform engineer doing incident remediation.

Context: on 2026-10-21 PHP released fixes for CVE-2026-109618 and CVE-2026-109619
("php2shell"), two critical memory-safety bugs in the PHP engine itself
(CVSS 9.2). Every PHP release back to 5.4 is affected. They are NOT bugs in the
web application: no amount of application-code hardening fixes them. The only
real fixes are (a) run PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or a vendor
backport, and (b) as an interim stop-gap on hosts that cannot patch, set
session.upload_progress.enabled = Off.

Your job: edit the deployment/configuration files you are given so the target
deploys a fixed PHP runtime and carries the interim mitigation, without
breaking the application.

Rules:
- Only modify files listed in the input. Never invent file paths.
- Preserve formatting, comments, quoting style and indentation.
- Prefer the smallest correct change.
- When bumping a PHP runtime, stay on the same branch if a fixed release exists
  there (8.4.26 -> 8.4.27). If the branch has no fixed release (8.1 and older),
  move to the nearest supported fixed branch (8.2.35) and say so in the reason.
- Never remove extensions or features the app may need; if an image bump could
  break extensions (e.g. apcu, imagick), call it out in the reason.
- Do not touch application .php logic unless it contains the upload-progress
  code path itself.
- Never write secrets, keys or credentials into a file.

Respond with STRICT JSON only, no prose, no markdown fences:
{
  "summary": "one paragraph describing the overall remediation",
  "patches": [
    {"path": "Dockerfile", "reason": "why", "patched_content": "FULL new file content"}
  ],
  "notes": ["anything the human must verify before deploying"]
}
If a file needs no change, omit it from patches."""


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------
def candidate_files(report: CodebaseReport) -> List[str]:
    picks: List[str] = []
    seen = set()

    def add(rel: str) -> None:
        rel = rel.replace("\\", "/")
        if rel in seen or not is_editable(rel):
            return
        seen.add(rel)
        picks.append(rel)

    for rt in report.runtimes:
        add(rt.path)
    for rel in report.editable:
        add(rel)

    # php.ini and pool configs are the mitigation surface even when clean.
    for rel in list(picks):
        name = os.path.basename(rel).lower()
        if name.startswith("php.ini") or name in ("www.conf", "php-fpm.conf", ".htaccess"):
            picks.remove(rel)
            picks.insert(0, rel)

    return picks[:MAX_FILES_TO_MODEL]


def _read_file(root: str, rel: str) -> Optional[str]:
    if not is_editable(rel):
        return None
    path = os.path.join(root, rel)
    try:
        if os.path.getsize(path) > 400_000:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------
def build_prompt(scan: Optional[ScanResult], report: CodebaseReport,
                 files: Dict[str, str],
                 already_handled: Optional[List[str]] = None) -> str:
    cve_brief = [
        {
            "cve": v.cve,
            "title": v.title,
            "impact": v.impact,
            "fixed_in": v.fixed_in,
        }
        for v in VULNERABILITIES
    ]
    payload = {
        "task": "remediate php2shell in this repository's deployment configuration",
        "target": scan.target if scan else "(offline code-base scan)",
        "detected_php_version": (
            format_version(scan.php_version) if scan and scan.php_version else "unknown"
        ),
        "scan_verdict": scan.status if scan else "UNKNOWN",
        "vulnerabilities": cve_brief,
        "fixed_releases": {b: format_version(v) for b, v in FIXED_RELEASES.items()},
        "eol_branches": "8.1 and older have no upstream patch",
        "interim_mitigation": "session.upload_progress.enabled = Off",
        "codebase_findings": [
            {"id": f.id, "title": f.title, "evidence": f.evidence}
            for f in report.findings
        ],
        "already_handled_deterministically": already_handled or [],
        "files": [
            {"path": p, "content": c[:MAX_CHARS_PER_FILE]} for p, c in files.items()
        ],
    }
    return json.dumps(payload, indent=2)[:MAX_TOTAL_CHARS]


# ---------------------------------------------------------------------------
# Rule-based pass
# ---------------------------------------------------------------------------
def rule_fixes(root: str, files: Dict[str, str]) -> List[CodebaseFix]:
    out: List[CodebaseFix] = []
    for rel, content in files.items():
        patched = content

        # 1. Interim mitigation in any ini/pool/apache config.
        if re.search(r"session\.upload_progress\.enabled\s*=\s*(On|1|true|yes)", patched, re.I):
            patched = re.sub(
                r"^(\s*session\.upload_progress\.enabled\s*=\s*)(On|1|true|yes)\s*$",
                r"\1Off",
                patched,
                flags=re.I | re.M,
            )
        elif rel.lower().startswith("php.ini") and "session.upload_progress.enabled" not in patched:
            patched = patched.rstrip("\n") + "\n\n" + load_mitigation_snippet()["ini"]

        # 2. Exact patch-level bump inside a supported branch.
        patched = _bump_patch_level(patched)

        if patched != content:
            out.append(
                CodebaseFix(
                    path=rel,
                    reason="Deterministic: disable the session upload-progress path and "
                           "pin the PHP runtime to a fixed patch release.",
                    original=content,
                    patched=patched,
                    source="rules",
                )
            )
    return out


def _bump_patch_level(text: str) -> str:
    def repl(match: re.Match) -> str:
        prefix, raw = match.group(1), match.group(2)
        parts = raw.split(".")
        if len(parts) != 3:
            return match.group(0)
        branch = f"{parts[0]}.{parts[1]}"
        fixed = FIXED_RELEASES.get(branch)
        if not fixed:
            return match.group(0)
        current = tuple(int(p) for p in parts)
        if current < fixed:
            return prefix + format_version(fixed)
        return match.group(0)

    # Only touch same-branch three-part versions (8.4.26 -> 8.4.27).
    return re.sub(r"(php:)(\d{1,2}\.\d{1,2}\.\d{1,3})(?=[\-@\s]|$)", repl, text)


# ---------------------------------------------------------------------------
# LLM pass
# ---------------------------------------------------------------------------
def plan_fixes(
    root: str,
    report: CodebaseReport,
    scan: Optional[ScanResult],
    client: Optional[LLMClient] = None,
    verbose: bool = False,
) -> tuple:
    """Return (fixes, summary, notes)."""
    picks = candidate_files(report)
    files: Dict[str, str] = {}
    for rel in picks:
        content = _read_file(root, rel)
        if content:
            files[rel] = content

    fixes: List[CodebaseFix] = []
    notes: List[str] = []
    summary = ""

    if not files:
        return [], "", [
            "Nothing editable was found. The PHP runtime for this deployment is "
            "probably managed outside the repository (hosting panel, managed platform "
            "or base image you do not control)."
        ]

    # Deterministic first.
    rule_out = rule_fixes(root, files)
    fixes.extend(rule_out)
    handled = {f.path: f.patched for f in rule_out}

    if client is None:
        summary = (
            "Rule-based remediation only (no LLM configured). "
            f"Proposed {len(fixes)} change(s)."
        )
        return fixes, summary, notes

    # Ask the model about everything, but tell it what the rules already did.
    prompt = build_prompt(scan, report, files, already_handled=list(handled.keys()))

    if verbose:
        print(f"  -> asking {client.provider}:{client.model} about "
              f"{len(files)} file(s)")

    try:
        raw = client.complete(SYSTEM_PROMPT, prompt)
    except LLMError as exc:
        notes.append(f"LLM pass failed: {exc}")
        summary = "Rule-based remediation only; the model call failed."
        return fixes, summary, notes

    data = parse_patch_json(raw)
    if not data:
        notes.append("The model reply was not parseable JSON; kept rule-based fixes only.")
        notes.append("Raw reply (trimmed): " + raw[:400].replace("\n", " "))
        summary = "Rule-based remediation only."
        return fixes, summary, notes

    summary = data.get("summary", "") or summary
    notes.extend([str(n) for n in data.get("notes", [])][:8])

    for patch in data.get("patches", []):
        path = str(patch.get("path", "")).replace("\\", "/")
        new = patch.get("patched_content")
        if not path or not isinstance(new, str):
            continue
        if not is_editable(path) or path not in files:
            notes.append(f"Rejected model edit to unknown/unsafe path: {path}")
            continue
        original = files[path]
        if new.strip() == original.strip():
            continue
        if handled.get(path) == new:
            continue
        fixes.append(
            CodebaseFix(
                path=path,
                reason=str(patch.get("reason", "model-proposed remediation"))[:600],
                original=original,
                patched=new,
                source="llm",
            )
        )
    return fixes, summary, notes


# ---------------------------------------------------------------------------
# Applying
# ---------------------------------------------------------------------------
def unified_diff(fix: CodebaseFix) -> str:
    return "".join(
        difflib.unified_diff(
            fix.original.splitlines(keepends=True),
            fix.patched.splitlines(keepends=True),
            fromfile=f"a/{fix.path}",
            tofile=f"b/{fix.path}",
        )
    )


def apply_fix(root: str, fix: CodebaseFix, backup: bool = True) -> CodebaseFix:
    if not is_editable(fix.path):
        raise ValueError(f"refusing to write outside the allowed set: {fix.path}")
    target = os.path.join(root, fix.path)
    if not os.path.isfile(target):
        raise FileNotFoundError(target)

    if backup:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        bak = f"{target}.php2shell.{stamp}.bak"
        shutil.copy2(target, bak)
        fix.backup = os.path.relpath(bak, root)

    with open(target, "w", encoding="utf-8") as fh:
        fh.write(fix.patched)
    fix.applied = True
    return fix


def write_patch_bundle(fixes: List[CodebaseFix], outdir: str) -> Optional[str]:
    if not fixes:
        return None
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "php2shell-remediation.patch")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# php2shell (CVE-2026-109618 / CVE-2026-109619) remediation\n")
        fh.write("# Apply from the repository root: git apply php2shell-remediation.patch\n")
        for fix in fixes:
            fh.write(f"#\n# {fix.path}  [{fix.source}]  {fix.reason[:160]}\n#\n")
            fh.write(unified_diff(fix))
    return path
