"""PHP version parsing and comparison helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

# Matches things like "8.2.35", "8.4", "7.4.33-1+deb11u1", "5.6.40".
_VERSION_RE = re.compile(r"(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?")

# Strings that show up in headers / footers instead of a version number.
_OPAQUE = {
    "": None,
    "unknown": None,
    "n/a": None,
    "na": None,
    "hidden": None,
    "disabled": None,
    "removed": None,
}


def parse_version(text: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Extract a comparable (major, minor, patch) tuple from free text.

    Returns None when no plausible PHP version can be found. A missing patch
    level is treated as 0, which is the safe assumption when judging whether a
    release predates a security fix.
    """
    if not text:
        return None
    raw = str(text).strip().lower()
    if raw in _OPAQUE:
        return None

    # Strip a leading "php" / "php/" prefix so "php/8.1.2" works.
    haystack = raw.replace("php/", "").replace("php", " ")
    match = _VERSION_RE.search(haystack)
    if not match:
        return None

    major, minor, patch = (int(g) if g is not None else 0 for g in match.groups())
    # Guard against obvious false positives such as "1.1" from a server banner.
    if major < 4 or major > 9:
        return None
    return (major, minor, patch)


def format_version(v: Optional[Tuple[int, int, int]]) -> str:
    if not v:
        return "unknown"
    return f"{v[0]}.{v[1]}.{v[2]}"


def version_string(v: Optional[Tuple[int, int, int]]) -> str:
    """Render a version for humans: 8.2.0 -> 8.2, 8.2.35 -> 8.2.35."""
    if not v:
        return "unknown"
    if v[2] == 0:
        return f"{v[0]}.{v[1]}"
    return f"{v[0]}.{v[1]}.{v[2]}"


def branch(v: Tuple[int, int, int]) -> str:
    return f"{v[0]}.{v[1]}"


def compare(a: Tuple[int, int, int], b: Tuple[int, int, int]) -> int:
    """Return -1, 0 or 1 for a < b, a == b, a > b."""
    if a == b:
        return 0
    return -1 if a < b else 1
