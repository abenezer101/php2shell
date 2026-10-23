"""Terminal presentation helpers (no dependencies)."""

from __future__ import annotations

import os
import sys
from typing import Iterable, List, Optional, Sequence

_COLOR = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
)

RESET = "\033[0m" if _COLOR else ""
BOLD = "\033[1m" if _COLOR else ""
DIM = "\033[2m" if _COLOR else ""
RED = "\033[31m" if _COLOR else ""
GREEN = "\033[32m" if _COLOR else ""
YELLOW = "\033[33m" if _COLOR else ""
BLUE = "\033[34m" if _COLOR else ""
MAGENTA = "\033[35m" if _COLOR else ""
CYAN = "\033[36m" if _COLOR else ""
GREY = "\033[90m" if _COLOR else ""

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH": YELLOW,
    "MEDIUM": CYAN,
    "LOW": BLUE,
    "INFO": GREY,
}

_SILENT = False


def set_silent(value: bool = True) -> None:
    """Suppress every human-facing print (used for --json output)."""
    global _SILENT
    _SILENT = value


def _p(*args, **kwargs) -> None:
    if not _SILENT:
        print(*args, **kwargs)


BANNER = r"""
██████╗ ██╗  ██╗██████╗     ██████╗     ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██║  ██║██╔══██╗    ╚════██╗    ██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝███████║██████╔╝     █████╔╝    ███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██╔══██║██╔═══╝     ██╔═══╝     ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ██║  ██║██║         ███████╗    ███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝         ╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
"""

BANNER_SUB = "                                                               Developed by abenezer101"
BANNER_RULE = "  " + "─" * 70


def banner(subtitle: str = "") -> None:
    _p(f"{CYAN}{BANNER}{RESET}")
    _p(f"{CYAN}{BOLD}{BANNER_SUB}{RESET}")
    _p(f"{CYAN}{DIM}{BANNER_RULE}{RESET}")
    _p(f"  {DIM}CVE-2026-109618 / CVE-2026-109619 - critical PHP engine RCE (CVSS 9.2){RESET}")
    if subtitle:
        _p(f"  {DIM}{subtitle}{RESET}")
    _p()


def rule(char: str = "─", width: int = 60) -> None:
    _p(f"{GREY}{char * width}{RESET}")


def header(text: str) -> None:
    _p(f"\n{BOLD}{text}{RESET}")
    rule()


def kv(key: str, value: str, width: int = 24) -> None:
    _p(f"  {GREY}{key.ljust(width)}{RESET}{value}")


def severity_badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, "")
    return f"{color}{BOLD}[{sev:<8}]{RESET}"


def info(msg: str) -> None:
    _p(f"  {CYAN}•{RESET} {msg}")


def ok(msg: str) -> None:
    _p(f"  {GREEN}✓{RESET} {msg}")


def warn(msg: str) -> None:
    _p(f"  {YELLOW}!{RESET} {msg}")


def error(msg: str) -> None:
    if not _SILENT:
        print(f"  {RED}✗{RESET} {msg}", file=sys.stderr)


def dim(msg: str) -> None:
    _p(f"{GREY}{msg}{RESET}")


def bullet_list(items: Iterable[str], marker: str = "·") -> None:
    for item in items:
        lines = str(item).splitlines() or [""]
        _p(f"    {GREY}{marker}{RESET} {lines[0]}")
        for extra in lines[1:]:
            _p(f"      {extra}")


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{BOLD}{prompt}{suffix}:{RESET} ").strip()
    except EOFError:
        return default
    return answer or default


def ask_secret(prompt: str) -> str:
    """Read a key without echoing it. Falls back to plain input when stdin is
    not a TTY (piped input, CI)."""
    try:
        import getpass
        return getpass.getpass(f"{BOLD}{prompt}:{RESET} ").strip()
    except (Exception, EOFError):
        try:
            return input(f"{BOLD}{prompt}:{RESET} ").strip()
        except EOFError:
            return ""


def ask_choice(prompt: str, options: Sequence[str], default: str = "") -> str:
    """Numbered menu. Returns the chosen key (the text before ' - ')."""
    print()
    keys: List[str] = []
    for i, opt in enumerate(options, 1):
        key = opt.split(" - ", 1)[0].strip()
        keys.append(key)
        label = opt.split(" - ", 1)[1] if " - " in opt else ""
        print(f"  {BOLD}{i}{RESET}) {key:<10} {label}")
    while True:
        raw = ask(prompt, default)
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return keys[int(raw) - 1]
        for key in keys:
            if raw.lower() == key.lower():
                return key
        print(f"  {YELLOW}Pick 1-{len(options)} or the option name.{RESET}")


def confirm(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    try:
        raw = input(f"{BOLD}{prompt} [{suffix}]:{RESET} ").strip().lower()
    except EOFError:
        return default
    if not raw:
        return default
    return raw in ("y", "yes")
