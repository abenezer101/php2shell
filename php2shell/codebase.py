"""Local code-base audit: where is the PHP runtime pinned, and is the
stop-gap mitigation present?

This stage works without any network access or LLM. It answers "which file do I
have to change?" so the fixer has something concrete to edit.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .model import Finding
from .version import format_version, parse_version
from .vulndb import EOL_BRANCHES, FIXED_RELEASES

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "bower_components",
    "__pycache__", ".idea", ".vscode", "dist", "build", "out", "target",
    ".next", ".nuxt", "coverage", ".venv", "venv", "cache", "tmp",
}

# Dot-directories that genuinely hold deployment configuration, so the walker
# must not skip them with the rest of the hidden files.
KEEP_DOT_DIRS = {".github", ".gitlab", ".devcontainer", ".circleci", ".buildkite"}

TEXT_EXT = {
    ".php", ".ini", ".conf", ".yml", ".yaml", ".json", ".lock", ".toml", ".xml",
    ".txt", ".md", ".sh", ".env", ".dockerfile", ".cfg", ".properties", ".htaccess",
    ".neon", ".plist", ".service",
}

MAX_FILE_BYTES = 400_000
MAX_FILES = 40_000

# Files the fixer is allowed to edit. Application .php files are only edited
# through the LLM path, and only when the finding is about app code.
CONFIG_FILENAMES = {
    "dockerfile", "dockerfile.prod", "dockerfile.dev", "php.ini", "php.ini-production",
    "php.ini-development", ".htaccess", "composer.json", "docker-compose.yml",
    "docker-compose.yaml", "platform.app.yaml", "fly.toml", "nixpacks.toml",
    "apache2.conf", "httpd.conf", "nginx.conf", "php-fpm.conf", "www.conf",
    "Procfile", "heroku.yml", "bitbucket-pipelines.yml", ".gitlab-ci.yml",
}
CONFIG_SUFFIXES = (".ini", ".conf", ".yaml", ".yml", ".toml", ".json", ".htaccess")
CONFIG_PATH_HINTS = (".github/workflows", ".gitlab", "docker", "deploy", "ci", ".devcontainer")


@dataclass
class PinnedRuntime:
    path: str
    line_no: int
    line: str
    version: Optional[Tuple[int, int, int]]
    branch: str
    kind: str          # docker | composer | ci | platform | docs
    raw: str = ""


@dataclass
class CodebaseReport:
    root: str
    files_scanned: int = 0
    php_files: int = 0
    runtimes: List[PinnedRuntime] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    mitigations_present: Dict[str, str] = field(default_factory=dict)
    editable: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    @property
    def dirty(self) -> bool:
        return bool(self.findings)


def _is_texty(path: str) -> bool:
    name = os.path.basename(path).lower()
    if name in CONFIG_FILENAMES or name.startswith("dockerfile"):
        return True
    ext = os.path.splitext(name)[1]
    return ext in TEXT_EXT or name in (".htaccess", "php.ini")


def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def walk(root: str) -> Iterable[str]:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and (not d.startswith(".") or d in KEEP_DOT_DIRS)
        ]
        for name in filenames:
            count += 1
            if count > MAX_FILES:
                return
            yield os.path.join(dirpath, name)


# ---------------------------------------------------------------------------
# Patterns for pinned runtimes
# ---------------------------------------------------------------------------
DOCKER_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?php:([\w.\-]+)", re.I)
COMPOSER_PHP = re.compile(r'"php(?:-64bit)?"\s*:\s*"([^"]+)"')
CI_PHP_VERSION = re.compile(r"(?:php[-_]?version|php)\s*:\s*['\"]?v?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)['\"]?\s*$", re.I)
PLATFORM_PHP = re.compile(r"php\s*[:=]\s*['\"]?(\d{1,2}(?:\.\d{1,2}){0,2})", re.I)
GENERIC_PHP_VERSION = re.compile(r"php[\-_ ]?(?:version)?[\"'=:\s]+v?(\d{1,2}\.\d{1,2}\.\d{1,3})", re.I)

UPLOAD_PROGRESS = re.compile(
    r"^\s*session\.upload_progress\.enabled\s*=\s*(On|Off|1|0|true|false|yes|no|on|off)\b",
    re.I | re.M,
)

FIXED_FLAT = {b: v for b, v in FIXED_RELEASES.items()}


def _classify(path: str) -> Optional[str]:
    name = os.path.basename(path).lower()
    parent = path.lower()
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "docker"
    if name == "composer.json":
        return "composer"
    if ".github/workflows" in parent or ".gitlab-ci" in parent or name in (
        "bitbucket-pipelines.yml", ".gitlab-ci.yml"
    ):
        return "ci"
    if name in ("platform.app.yaml", "nixpacks.toml", "fly.toml", "heroku.yml", "procfile"):
        return "platform"
    return None


def scan(root: str) -> CodebaseReport:
    root = os.path.abspath(os.path.expanduser(root))
    report = CodebaseReport(root=root)
    if not os.path.isdir(root):
        report.findings.append(
            Finding(
                id="CODE-PATH",
                title="Code base path is not a directory",
                severity="INFO",
                category="codebase",
                detail=f"{root} does not exist or is not a directory.",
            )
        )
        return report

    ini_files: List[str] = []

    for path in walk(root):
        if not _is_texty(path):
            continue
        text = _read(path)
        if text is None:
            report.skipped.append(path)
            continue
        report.files_scanned += 1
        rel = os.path.relpath(path, root)
        name = os.path.basename(path).lower()

        if name.endswith(".php"):
            report.php_files += 1
        if name.startswith("php.ini") or name.endswith(".ini"):
            ini_files.append(path)

        kind = _classify(path)
        _collect_runtime(report, rel, text, kind)

        if kind is None and _looks_configy(rel):
            _collect_runtime(report, rel, text, "platform", generic_ok=True)

    _check_mitigations(report, ini_files, root)
    _summarise(report)
    return report


def _looks_configy(rel: str) -> bool:
    low = rel.lower()
    return any(hint in low for hint in CONFIG_PATH_HINTS) or low.endswith(
        (".ini", ".conf", ".yaml", ".yml", "docker-compose.yaml", "docker-compose.yml")
    )


def _collect_runtime(report: CodebaseReport, rel: str, text: str,
                     kind: Optional[str], generic_ok: bool = False) -> None:
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 400:
            continue
        found: Optional[Tuple[str, Optional[Tuple[int, int, int]]]] = None

        m = DOCKER_FROM.search(line)
        if m:
            tag = m.group(1)                    # e.g. 8.3.36-fpm, 8.1-apache, latest
            ver = parse_version(tag.replace("-", "."))
            found = ("docker", ver)
        if found is None:
            m = COMPOSER_PHP.search(line)
            if m:
                found = ("composer", parse_version(m.group(1)))
        if found is None and kind == "ci":
            m = CI_PHP_VERSION.search(line.strip())
            if m:
                found = ("ci", parse_version(m.group(1)))
        if found is None and kind == "platform":
            m = PLATFORM_PHP.search(line)
            if m:
                found = ("platform", parse_version(m.group(1)))
        if found is None and generic_ok:
            m = GENERIC_PHP_VERSION.search(line)
            if m:
                found = ("platform", parse_version(m.group(1)))

        if not found or not found[1]:
            continue
        version = found[1]
        branch = f"{version[0]}.{version[1]}"
        report.runtimes.append(
            PinnedRuntime(path=rel, line_no=i, line=line.strip()[:200], version=version,
                          branch=branch, kind=found[0], raw=line.strip()[:200])
        )


def _check_mitigations(report: CodebaseReport, ini_files: List[str], root: str) -> None:
    """Where is session.upload_progress.enabled set, and to what?"""
    for path in ini_files:
        text = _read(path) or ""
        rel = os.path.relpath(path, root)
        for m in UPLOAD_PROGRESS.finditer(text):
            setting = m.group(1).lower()
            state = "Off" if setting in ("off", "0", "false", "no") else "On"
            report.mitigations_present.setdefault(rel, state)
            report.editable.append(rel)

    for path in walk(root):
        name = os.path.basename(path).lower()
        if not (name.endswith((".conf", ".yaml", ".yml", ".htaccess")) or name.startswith("dockerfile")):
            continue
        text = _read(path) or ""
        if not text:
            continue
        rel = os.path.relpath(path, root)
        if "upload_progress" in text:
            state = "Off" if re.search(
                r"upload_progress\.enabled\s*[= ]\s*(off|0|false|no)", text, re.I
            ) else "On"
            report.mitigations_present.setdefault(rel, state)
            report.editable.append(rel)


def _summarise(report: CodebaseReport) -> None:
    # 1. Runtime pins.
    vulnerable_pins: List[PinnedRuntime] = []
    for rt in report.runtimes:
        fixed = FIXED_FLAT.get(rt.branch)
        if fixed and rt.version and rt.version < fixed:
            vulnerable_pins.append(rt)
        elif rt.branch in EOL_BRANCHES:
            vulnerable_pins.append(rt)
        if rt.path not in report.editable and _is_config_file(rt.path):
            report.editable.append(rt.path)

    seen = set()
    unique_pins = []
    for rt in vulnerable_pins:
        key = (rt.path, rt.line_no)
        if key in seen:
            continue
        seen.add(key)
        unique_pins.append(rt)

    if unique_pins:
        evid = "\n".join(
            f"{rt.path}:{rt.line_no}  {rt.line}" for rt in unique_pins[:12]
        )
        target = sorted({f"{rt.branch} -> {format_version(FIXED_FLAT[rt.branch])}"
                         if rt.branch in FIXED_FLAT else f"{rt.branch} (EOL)"
                         for rt in unique_pins})
        report.findings.append(
            Finding(
                id="CODE-RUNTIME-PIN",
                title=f"{len(unique_pins)} vulnerable PHP runtime pin(s) in the code base",
                severity="CRITICAL",
                category="codebase",
                detail=(
                    "These files decide which PHP build is deployed. Changing them is the "
                    "actual fix; nothing in application code prevents these CVEs.\n\n"
                    "Required moves: " + "; ".join(target)
                ),
                evidence=evid,
                remediation="Bump the runtime pins to a fixed release and redeploy.",
                references=[r.path for r in unique_pins[:12]],
            )
        )

    if not report.runtimes:
        report.findings.append(
            Finding(
                id="CODE-NO-PIN",
                title="No PHP runtime pin found in this repository",
                severity="MEDIUM",
                category="codebase",
                detail=(
                    "No Dockerfile, composer.json platform requirement or CI PHP version was "
                    "found. The runtime probably comes from a hosting panel or a shared "
                    "platform, which means the fix happens outside this repository."
                ),
                evidence=f"Scanned {report.files_scanned} files under {report.root}",
                remediation="Identify the runtime owner (panel, PaaS buildpack, base image), "
                            "or add an explicit pin so this is auditable next time.",
            )
        )

    # 2. Mitigation presence.
    off_anywhere = [p for p, s in report.mitigations_present.items() if s == "Off"]
    on_anywhere = [p for p, s in report.mitigations_present.items() if s == "On"]
    if on_anywhere:
        report.findings.append(
            Finding(
                id="CODE-UPLOAD-PROGRESS-ON",
                title="session.upload_progress.enabled is explicitly On",
                severity="HIGH",
                category="codebase",
                detail=(
                    "Session upload progress is enabled in configuration. It is the exact "
                    "code path behind CVE-2026-109618's memory-disclosure primitive, and PHP "
                    "recommends turning it off as the stop-gap for hosts that cannot patch."
                ),
                evidence="\n".join(on_anywhere),
                remediation="Set session.upload_progress.enabled = Off and restart the SAPI.",
            )
        )
    elif not off_anywhere:
        report.findings.append(
            Finding(
                id="CODE-NO-MITIGATION",
                title="No session.upload_progress.enabled = Off anywhere in the repo",
                severity="MEDIUM",
                category="codebase",
                detail=(
                    "The interim mitigation is not configured in this repository. `Off` is "
                    "the PHP default, so this is only a real gap if the deployment turns it "
                    "on elsewhere - but a host that cannot reach a fixed PHP release needs "
                    "this line pinned in the image/pool config."
                ),
                evidence=f"Scanned {len(report.mitigations_present)} config file(s)",
                remediation="Add the directive to the image's php.ini or FPM pool config.",
            )
        )

    if report.php_files == 0:
        report.findings.append(
            Finding(
                id="CODE-NO-PHP",
                title="No .php files in this repository",
                severity="INFO",
                category="codebase",
                detail="The runtime pin may still matter, but there is no application code "
                       "to review here.",
            )
        )

    report.editable = sorted(set(report.editable))


def _is_config_file(rel: str) -> bool:
    name = os.path.basename(rel).lower()
    return (
        name in CONFIG_FILENAMES
        or name.startswith("dockerfile")
        or name.endswith(CONFIG_SUFFIXES)
    )


def is_editable(rel: str) -> bool:
    """Guard used by the fixer before it writes anything."""
    rel = rel.replace("\\", "/")
    if rel.startswith("../") or "/../" in rel:
        return False
    if any(part in SKIP_DIRS for part in rel.split("/")[:-1]):
        return False
    return _is_config_file(rel) or rel.endswith(".php")


def load_mitigation_snippet() -> Dict[str, str]:
    """Ready-made text blocks the fixer can insert."""
    return {
        "ini": (
            "; php2shell (CVE-2026-109618 / CVE-2026-109619) interim mitigation.\n"
            "; Removes the session upload-progress code path until the runtime is patched.\n"
            "session.upload_progress.enabled = Off\n"
            "session.upload_progress.cleanup = On\n"
        ),
        "fpm": (
            "; php2shell interim mitigation (FPM pool)\n"
            "php_admin_value[session.upload_progress.enabled] = Off\n"
        ),
        "apache": (
            "# php2shell interim mitigation (mod_php)\n"
            "php_admin_flag session.upload_progress.enabled Off\n"
        ),
    }
