"""Vulnerability knowledge base for the php2shell disclosure (Oct 2026).

Everything in this module is transcribed from public reporting:

  * Huntress - "Rapid Response: php2shell, Leaked Critical PHP Vulnerabilities"
    https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
  * Wiz - "PHP2Shell: AI uncovers critical RCE vulnerabilities affecting 70% of
    the Internet"
    https://www.wiz.io/blog/php2shell-php-rce
  * PHP advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp

No exploit code lives here. The tool only needs to know which versions are
fixed, which configurations reduce exposure, and what an intrusion looks like
after the fact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .version import branch, compare, format_version

Version = Tuple[int, int, int]

# ---------------------------------------------------------------------------
# Fixed releases, per branch. Anything below these numbers on the same branch
# is vulnerable. Source: PHP 2026-10-21 security release.
# ---------------------------------------------------------------------------
FIXED_RELEASES: Dict[str, Version] = {
    "8.5": (8, 5, 12),
    "8.4": (8, 4, 27),
    "8.3": (8, 3, 36),
    "8.2": (8, 2, 35),
}

# Branches that are past end-of-life. No upstream patch exists; the PHP team
# published minimal source backports for 7.4 / 8.0 / 8.1 and vendors may
# backport further, so we can never call these "safe" from a banner alone.
EOL_BRANCHES = {"5.4", "5.5", "5.6", "6.0", "7.0", "7.1", "7.2", "7.3", "7.4",
                "8.0", "8.1"}

# Backports the PHP security team shipped for unsupported branches.
SOURCE_BACKPORTS = {"7.4", "8.0", "8.1"}

# Server APIs PHP itself lists as exposed to unauthenticated attack.
EXPOSED_SAPIS = (
    "php-fpm", "fpm-fcgi", "apache2handler (mod_php)", "cgi-fcgi (php-cgi)",
    "frankenphp", "litespeed",
)


@dataclass(frozen=True)
class Vulnerability:
    cve: str
    title: str
    severity: str
    cvss: str
    summary: str
    impact: str
    fixed_in: str
    advisory: str


VULNERABILITIES: List[Vulnerability] = [
    Vulnerability(
        cve="CVE-2026-109618",
        title="Upload-progress unserializer use-after-free / remote memory disclosure",
        severity="CRITICAL",
        cvss="9.2 (CVSS v4.0)",
        summary=(
            "PHP parses RFC1867 multipart requests during request startup, before "
            "normal module initialisation. Session upload-progress handling can "
            "publish a session id in PS(id); an out-of-memory error aborts the "
            "request before cleanup, leaving that pointer dangling. A later "
            "multipart request handled by the same worker can URL-encode the "
            "reclaimed heap into a PHPSESSID response cookie, disclosing live "
            "worker memory (passwords, tokens, API keys, certificates). The "
            "decoder side (BG(unserialize) bookkeeping published across a fatal "
            "allocation failure) is the memory-corruption primitive that chains "
            "with the disclosure into unauthenticated RCE."
        ),
        impact=(
            "Unauthenticated remote code execution as the web worker account "
            "(validated over HTTP against mod_php with default php.ini input and "
            "memory limits, and against prefork configurations with multiple "
            "workers). Also unauthenticated, application-agnostic process-memory "
            "disclosure - works even when the application never calls "
            "session_start()."
        ),
        fixed_in="PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35",
        advisory="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    ),
    Vulnerability(
        cve="CVE-2026-109619",
        title="Fatal-error backtrace use-after-free / OPcache type confusion",
        severity="CRITICAL",
        cvss="9.2 (CVSS v4.0)",
        summary=(
            "PHP retains the backtrace of the most recent fatal error in "
            "EG(last_fatal_error_backtrace). A fatal out-of-memory error destroys "
            "the request heap without undefining that executor-global value, so the "
            "worker keeps a pointer into the previous request's memory. If the same "
            "worker emits a diagnostic early in the next request it follows "
            "attacker-reclaimed memory. A second variant is an OPcache type "
            "confusion: an allocation failure during zend_accel_script_persist() "
            "advances the process-local CG(map_ptr_last) frontier without "
            "publishing the shared frontier, so another worker can reuse a slot "
            "for a different runtime object and shared metadata resolves to a "
            "pointer of the wrong type."
        ),
        impact=(
            "Unauthenticated heap use-after-free, memory disclosure and remote code "
            "execution with web worker privileges. Demonstrated pre-auth RCE against "
            "Drupal (backtrace UAF) and WordPress (OPcache type confusion)."
        ),
        fixed_in="PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35",
        advisory="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
    ),
]

MITIGATIONS: List[str] = [
    "Disable session upload progress: session.upload_progress.enabled = Off "
    "(php.ini or per-pool php_admin_value). This removes the known abuse case and "
    "is the primary stop-gap for end-of-life branches.",
    "Remove the exposure instead of hiding it: upgrade to PHP 8.5.12 / 8.4.27 / "
    "8.3.36 / 8.2.35, or apply the vendor backport for your distribution.",
    "Count multipart request starts per worker and cap the number of "
    "simultaneous unfinished uploads (php_fpm process limits, request_terminate_timeout).",
    "Keep memory_limit realistic; the bug is triggered on allocation failure, so "
    "an absurdly low limit widens the trigger surface and an unlimited one removes "
    "the OOM path entirely, which is why 0/unlimited is not a recommended 'fix'.",
    "Put the PHP runtime behind a WAF/CDN rule set that the vendor published for "
    "this disclosure (Cloudflare, Fastly, AWS, Google Cloud, Imperva, Akamai).",
    "Isolate end-of-life PHP from the internet; never expose php-cgi (CVE-2024-4577 "
    "style argument injection also applies).",
    "Rotate any secret that lived in an affected worker's memory: DB passwords, "
    "APP_KEY / salts, API keys, TLS private keys, SMTP credentials.",
]

# Behavioural indicators of exploitation attempts (from the Wiz threat-detection
# guidance and Huntress' process-lineage hunting advice).
BEHAVIOURAL_INDICATORS: List[str] = [
    "Unusual multipart/form-data requests followed by memory-limit errors or "
    "repeated HTTP 500 responses from the same worker.",
    "Unexpectedly large or malformed PHPSESSID response cookies (percent-encoded "
    "binary blobs from worker memory).",
    "Unexplained PHP worker churn: workers exiting or respawning in bursts "
    "without matching request volume.",
    "PHP worker (php-fpm, php-cgi, httpd, apache2) spawning sh, bash, cmd.exe, "
    "powershell.exe, python, perl, curl, wget, nc or certutil.",
    "Command lines containing /dev/tcp/, mkfifo, or PHP one-liners writing a "
    "temp .php file, executing it and deleting it.",
    "Recon burst straight from the web server: whoami, id, uname -a, ipconfig.",
]

# Application-stack context: the CMS does not create the bug, but it tells the
# fixer where runtime versions are pinned.
CMS_RUNTIME_HINTS: Dict[str, str] = {
    "WordPress": "PHP version comes from the host image/panel, not wp-config.php. "
                 "Check the base image, the container platform, or the hosting panel.",
    "Drupal": "composer.json pins php in the platform/require block; also check "
              "the container base image and settings.php for ini overrides.",
    "Joomla": "configuration.php rarely holds the runtime version; check the "
              "hosting panel or container image.",
    "MediaWiki": "composer.json require.php plus the container image.",
}

# Files worth reading when looking for a pinned PHP runtime.
RUNTIME_MANIFESTS = (
    "composer.json",
    "composer.lock",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "php.ini",
    "php.ini-production",
    "php.ini-development",
    ".htaccess",
    "wp-config.php",
    "configuration.php",
    "settings.php",
    "platform.app.yaml",
    "Procfile",
    "nixpacks.toml",
    "heroku.yml",
)


def fixed_for(version: Version) -> Optional[Version]:
    """The fixed release for this version's branch, or None if we have none."""
    return FIXED_RELEASES.get(branch(version))


def assess(version: Optional[Version]) -> Tuple[str, str]:
    """Classify a discovered PHP version.

    Returns (status, human reason) where status is one of:
      VULNERABLE  - definitely below the fixed release for its branch
      PATCHED     - at or above the fixed release
      UNKNOWN     - cannot tell (no version, or a branch we have no data for)
    """
    if version is None:
        return "UNKNOWN", (
            "PHP was detected but its version could not be determined. Version "
            "must be verified directly on the host (php -v / phpinfo / panel)."
        )

    b = branch(version)
    fixed = FIXED_RELEASES.get(b)

    if fixed is None:
        if b in EOL_BRANCHES:
            return "VULNERABLE", (
                f"PHP {b} is end-of-life and no upstream fixed release exists. The "
                f"vulnerabilities affect releases back to PHP 5.4, so {format_version(version)} "
                f"is affected. Apply session.upload_progress.enabled=Off now, then "
                f"upgrade or use a vendor/backport build."
                + (" PHP shipped a minimal source backport for this branch."
                   if b in SOURCE_BACKPORTS else "")
            )
        return "UNKNOWN", (
            f"PHP {format_version(version)} is newer than the branches this tool "
            f"knows about (8.2-8.5). Confirm the release postdates the 2026-10-21 "
            f"security release."
        )

    if compare(version, fixed) < 0:
        return "VULNERABLE", (
            f"PHP {format_version(version)} is below the fixed release "
            f"{format_version(fixed)} for branch {b}. Both CVE-2026-109618 and "
            f"CVE-2026-109619 apply to every PHP release back to 5.4."
        )
    return "PATCHED", (
        f"PHP {format_version(version)} is at or above {format_version(fixed)}, the "
        f"fixed release for branch {b}."
    )


def cves_for(version: Optional[Version]) -> List[Vulnerability]:
    status, _ = assess(version)
    return list(VULNERABILITIES) if status != "PATCHED" else []
