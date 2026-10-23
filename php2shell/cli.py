"""Command line entry point and the interactive scan -> fix loop."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import report as report_mod
from . import ui
from .codebase import CodebaseReport, scan as scan_codebase
from .detect import Detector
from .fixer import apply_fix, plan_fixes, unified_diff, write_patch_bundle
from .http import HttpClient
from .llm import DEFAULT_MODELS, LLMClient, LLMError
from .model import CodebaseFix, ScanResult
from .probe import run_probes
from .version import format_version, parse_version

LEGAL = (
    "Only scan systems you own or have written authorisation to test. The "
    "scanner sends ordinary HTTP requests and never exploits the vulnerability."
)


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell",
        description="Detect and remediate CVE-2026-109618 / CVE-2026-109619 "
                    "(php2shell) on PHP platforms.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  php2shell                                  # interactive, asks for a target\n"
            "  php2shell scan example.com                 # remote scan only\n"
            "  php2shell scan example.com --probe         # add opt-in behavioural probes\n"
            "  php2shell scan example.com --codebase ./www --fix   # scan then remediate\n"
            "  php2shell audit ./www                      # code base only, no network\n"
            "  php2shell scan example.com --php-version 8.3.30   # when the banner hides it\n"
        ),
    )
    p.add_argument("positional", nargs="*", metavar="[scan|audit|fix] TARGET",
                   help="optional verb (scan / audit / fix) then a domain, URL or path")

    p.add_argument("--codebase", "-c", metavar="PATH",
                   help="path to the PHP project to audit/remediate")
    p.add_argument("--fix", action="store_true",
                   help="go straight to the remediation flow after scanning")
    p.add_argument("--probe", action="store_true",
                   help="run opt-in behavioural probes (multipart shape + stability)")
    p.add_argument("--php-version", metavar="X.Y[.Z]",
                   help="assert the PHP version instead of fingerprinting it")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout (default 10s)")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--proxy", metavar="URL", help="HTTP(S) proxy")
    p.add_argument("--llm-provider", default="openai", choices=sorted(DEFAULT_MODELS),
                   help="LLM provider for the fix stage (default openai)")
    p.add_argument("--llm-key", metavar="KEY",
                   help="API key (prefer the env var so it stays out of shell history)")
    p.add_argument("--llm-model", metavar="NAME", help="model name override")
    p.add_argument("--llm-base-url", metavar="URL",
                   help="override the API base URL (Azure OpenAI, local gateway, ...)")
    p.add_argument("--apply", action="store_true",
                   help="apply edits without asking for confirmation")
    p.add_argument("--dry-run", action="store_true",
                   help="never write to the code base, only produce a patch file")
    p.add_argument("--report-dir", default="php2shell-reports", help="where reports go")
    p.add_argument("--json", action="store_true", help="print the scan result as JSON")
    p.add_argument("--quiet", action="store_true", help="suppress the banner and commentary")
    p.add_argument("--verbose", "-v", action="store_true", help="show every HTTP probe")
    p.add_argument("--yes", "-y", action="store_true", help="assume yes for prompts")
    return p


# ---------------------------------------------------------------------------
def resolve_args(argv: Optional[List[str]]) -> argparse.Namespace:
    args = build_parser().parse_args(argv)
    # Accept "scan <target>" / "audit <path>" as an optional verb, while keeping
    # bare `php2shell example.com` working.
    args.target = None
    args.subcommand = None
    positional = list(args.positional or [])

    verbs = {"scan", "audit", "fix"}
    if positional and positional[0].lower() in verbs:
        args.subcommand = positional.pop(0).lower()

    if positional:
        first = positional.pop(0)
        if args.subcommand == "audit":
            args.codebase = args.codebase or first
        else:
            args.target = first
    if positional:
        # A second bare argument is treated as the code base for `fix`.
        if args.subcommand in ("fix", "scan") and not args.codebase:
            args.codebase = positional.pop(0)

    if args.subcommand == "fix" and not args.fix:
        args.fix = True
    if args.subcommand == "audit" and args.target is None and args.codebase:
        args.codebase = os.path.expanduser(args.codebase)

    return args


# ---------------------------------------------------------------------------
class App:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.scan: Optional[ScanResult] = None
        self.code: Optional[CodebaseReport] = None
        self.fixes: List[CodebaseFix] = []
        self.client = HttpClient(
            timeout=args.timeout,
            verify_tls=not args.insecure,
            proxy=args.proxy,
        )
        self.paths: dict = {}

    # -- remote scan ------------------------------------------------------
    def do_scan(self, target: str) -> ScanResult:
        ui.header(f"Remote scan → {target}")
        forced = parse_version(self.args.php_version) if self.args.php_version else None
        detector = Detector(self.client, verbose=self.args.verbose)
        result = detector.run(target)

        if forced:
            result.is_php = True
            result.php_version = forced
            result.version_source = "--php-version (operator supplied)"
            from . import vulndb
            result.status, result.status_reason = vulndb.assess(forced)
            result.findings = [f for f in result.findings
                               if not f.id.endswith(("-UNKNOWN", "-PATCHED"))]
            if result.status == "VULNERABLE":
                for v in vulndb.VULNERABILITIES:
                    from .model import Finding
                    result.add(Finding(
                        id=f"PHP2SHELL-{v.cve}", title=f"{v.cve}: {v.title}",
                        severity=v.severity, category="vulnerable-php-runtime",
                        detail=f"{v.summary}\n\nImpact: {v.impact}",
                        evidence=f"Operator asserted PHP {format_version(forced)}; "
                                 f"fixed in {v.fixed_in}.",
                        remediation=f"Upgrade to {v.fixed_in}.",
                        references=[v.advisory]))

        if self.args.probe:
            ui.info("Running opt-in behavioural probes…")
            run_probes(self.client, result, verbose=self.args.verbose)

        self.scan = result
        return result

    def render_scan(self, res: ScanResult) -> None:
        if self.args.json:
            import json
            sys.stdout.write(json.dumps(res.to_dict(), indent=2) + "\n")
            return

        ui.header("Result")
        ui.kv("Target", res.target)
        ui.kv("Resolved", res.resolved_ip or "unresolved")
        ui.kv("PHP detected",
              f"{ui.GREEN}yes{ui.RESET} (confidence {res.php_confidence}/10)"
              if res.is_php else f"{ui.GREY}no{ui.RESET}")
        ui.kv("PHP version", f"{ui.BOLD}{format_version(res.php_version)}{ui.RESET} "
                             f"{ui.GREY}({res.version_source or 'no source'}){ui.RESET}")
        if res.server_software:
            ui.kv("Server", res.server_software)
        if res.sapi:
            ui.kv("SAPI hints", res.sapi)
        if res.cms:
            ui.kv("CMS", f"{res.cms} {res.cms_version}".strip())

        verdict = res.verdict
        if verdict == "VULNERABLE":
            ui.kv("Verdict", f"{ui.RED}{ui.BOLD}VULNERABLE{ui.RESET} "
                             f"{ui.GREY}risk {res.risk_score}/100{ui.RESET}")
        elif verdict == "PATCHED":
            ui.kv("Verdict", f"{ui.GREEN}{ui.BOLD}PATCHED{ui.RESET}")
        elif verdict == "NOT_PHP":
            ui.kv("Verdict", f"{ui.GREY}NOT PHP / not confirmed{ui.RESET}")
        else:
            ui.kv("Verdict", f"{ui.YELLOW}{ui.BOLD}UNVERIFIED{ui.RESET}")

        if res.status_reason:
            print()
            ui.dim("  " + res.status_reason.replace("\n", "\n  "))

        print()
        if res.findings:
            for f in res.sorted_findings():
                print(f"  {ui.severity_badge(f.severity)} {ui.BOLD}{f.title}{ui.RESET}")
                if f.id.startswith("PHP2SHELL-") and f.severity in ("CRITICAL", "HIGH"):
                    first = f.detail.split("\n\n")[0]
                    print(f"      {ui.GREY}{first[:300]}{'…' if len(first) > 300 else ''}{ui.RESET}")
                print(f"      {ui.GREY}{f.id}{ui.RESET}")
        if res.notes:
            print()
            for n in res.notes:
                ui.warn(n)
        print()
        ui.kv("HTTP probes", str(res.probes_run))

    # -- code base --------------------------------------------------------
    def do_codebase(self, root: str) -> CodebaseReport:
        ui.header(f"Code base audit → {root}")
        report = scan_codebase(root)
        self.code = report
        ui.kv("Root", report.root)
        ui.kv("Files scanned", str(report.files_scanned))
        ui.kv("PHP files", str(report.php_files))
        ui.kv("Runtime pins", str(len(report.runtimes)))
        print()
        if not report.findings:
            ui.ok("No code base findings.")
        for f in report.findings:
            print(f"  {ui.severity_badge(f.severity)} {ui.BOLD}{f.title}{ui.RESET}")
            if f.evidence:
                for line in f.evidence.splitlines()[:4]:
                    print(f"      {ui.GREY}{line[:150]}{ui.RESET}")
            print()
        return report

    # -- remediation ------------------------------------------------------
    def make_llm(self) -> Optional[LLMClient]:
        provider = self.args.llm_provider
        key = self.args.llm_key or LLMClient.resolve_key(provider)

        ui.header("LLM fix engine")
        ui.dim(f"  Provider: {provider}   Model: {self.args.llm_model or DEFAULT_MODELS[provider]}")

        if provider != "mock" and not key:
            if self.args.yes or not sys.stdin.isatty():
                ui.warn("No API key found. Falling back to the offline 'mock' engine "
                        "(rule-based edits only).")
                provider = "mock"
            else:
                ui.dim("  The key is used only for this run; it is never written to disk.")
                ui.dim("  You can also export PHP2SHELL_LLM_KEY / OPENAI_API_KEY instead.")
                key = ui.ask_secret(f"{provider} API key (blank = offline mock engine)")
                if not key:
                    ui.warn("No key given. Using the offline 'mock' engine.")
                    provider = "mock"

        try:
            client = LLMClient(
                provider=provider,
                api_key=key or "",
                model=self.args.llm_model or "",
                base_url=self.args.llm_base_url or "",
            )
            client.validate()
        except LLMError as exc:
            ui.error(str(exc))
            ui.info("Continuing with rule-based remediation only.")
            return None

        ui.ok(f"Ready: {client.provider}:{client.model}")
        return client

    def do_fix(self, root: str) -> List[CodebaseFix]:
        if self.code is None or os.path.abspath(root) != os.path.abspath(self.code.root):
            self.do_codebase(root)

        client = self.make_llm()
        ui.header("Planning remediation")
        fixes, summary, notes = plan_fixes(
            self.code.root, self.code, self.scan, client, verbose=self.args.verbose
        )
        self.fixes = fixes

        if summary:
            print()
            print(f"  {ui.BOLD}{summary}{ui.RESET}")
        for n in notes:
            ui.warn(n)

        if not fixes:
            print()
            ui.warn("No editable files produced a change.")
            ui.info("If the runtime is managed outside this repository, the fix is a "
                    "hosting action: upgrade PHP or set session.upload_progress.enabled=Off "
                    "on the server/panel.")
            return []

        print()
        for fix in fixes:
            print(f"  {ui.BOLD}{fix.path}{ui.RESET} {ui.GREY}[{fix.source}]{ui.RESET}")
            print(f"      {ui.GREY}{fix.reason[:200]}{ui.RESET}")
            diff = unified_diff(fix)
            for line in diff.splitlines()[:40]:
                if line.startswith(("+++", "---")):
                    print(f"      {ui.BOLD}{line}{ui.RESET}")
                elif line.startswith("+"):
                    print(f"      {ui.GREEN}{line}{ui.RESET}")
                elif line.startswith("-"):
                    print(f"      {ui.RED}{line}{ui.RESET}")
                elif line.startswith("@@"):
                    print(f"      {ui.CYAN}{line}{ui.RESET}")
            print()

        patch_path = write_patch_bundle(fixes, self.args.report_dir)
        if patch_path:
            ui.ok(f"Patch bundle written: {patch_path}")
            self.paths["patch"] = patch_path

        if self.args.dry_run:
            ui.info("Dry run: nothing written to the code base.")
            return fixes

        go = self.args.apply or self.args.yes
        if not go:
            go = ui.confirm(f"Apply {len(fixes)} change(s) now (backups are kept)?", False)
        if not go:
            ui.info("Left the files untouched. Apply the patch when you are ready.")
            return fixes

        for fix in fixes:
            try:
                apply_fix(self.code.root, fix, backup=True)
                ui.ok(f"Patched {fix.path}"
                      + (f" {ui.GREY}(backup {fix.backup}){ui.RESET}" if fix.backup else ""))
            except Exception as exc:
                ui.error(f"{fix.path}: {exc}")

        print()
        ui.info("Next steps: rebuild/redeploy, then confirm the live runtime with "
                "`php -v` or a re-scan.")
        ui.info("Rotate secrets that may have sat in an unpatched worker's memory "
                "(DB passwords, APP_KEY, API keys, TLS keys).")
        return fixes

    # -- reporting --------------------------------------------------------
    def write_reports(self) -> None:
        if not (self.scan or self.code):
            return
        paths = []
        paths.append(report_mod.write_json(self.scan, self.code, self.fixes, self.args.report_dir))
        paths.append(report_mod.write_markdown(self.scan, self.code, self.fixes, self.args.report_dir))
        paths.append(report_mod.write_html(self.scan, self.code, self.fixes, self.args.report_dir))
        if self.args.json:
            for p in paths:
                print(f"report: {p}", file=sys.stderr)
            return
        ui.header("Reports")
        for p in paths:
            ui.ok(p)


# ---------------------------------------------------------------------------
def interactive(args: argparse.Namespace) -> int:
    app = App(args)
    ui.banner(LEGAL)

    target = args.target
    if not target:
        target = ui.ask("Target domain or URL to scan")
        if not target:
            ui.error("No target given.")
            return 2

    result = app.do_scan(target)
    app.render_scan(result)

    vulnerable = result.status in ("VULNERABLE", "UNKNOWN") and result.is_php

    if args.fix and args.codebase and os.path.isdir(os.path.expanduser(args.codebase)):
        app.do_fix(os.path.expanduser(args.codebase))
        app.write_reports()

    while True:
        print()
        if vulnerable:
            ui.rule("━")
            print(f"  {ui.RED}{ui.BOLD}ACTION REQUIRED{ui.RESET} - this host is running an "
                  f"affected PHP build.")
            ui.rule("━")
            choice = ui.ask_choice(
                "What next?",
                [
                    "FIX  - point me at the code base and patch the bug",
                    "REPORT - write the JSON/Markdown/HTML report",
                    "RESCAN - scan again or try a different target",
                    "EXIT - stop here",
                ],
                default="FIX",
            )
        else:
            choice = ui.ask_choice(
                "What next?",
                [
                    "AUDIT - audit a local PHP code base anyway",
                    "REPORT - write the JSON/Markdown/HTML report",
                    "RESCAN - scan another target",
                    "EXIT - stop here",
                ],
                default="REPORT",
            )

        choice = choice.upper()

        if choice.startswith("FIX"):
            root = args.codebase or ui.ask("Path to the PHP project (code base root)")
            if not root:
                ui.warn("No path given, so there is nothing to edit.")
                ui.info("You can still harden the host manually: upgrade PHP or set "
                        "session.upload_progress.enabled = Off.")
                continue
            root = os.path.expanduser(root)
            if not os.path.isdir(root):
                ui.error(f"{root} is not a directory.")
                continue
            app.do_fix(root)
            app.write_reports()

        elif choice.startswith("AUDIT"):
            root = args.codebase or ui.ask("Path to the PHP project")
            if root and os.path.isdir(os.path.expanduser(root)):
                app.do_codebase(os.path.expanduser(root))
                if ui.confirm("Plan and apply fixes now?", False):
                    app.do_fix(app.code.root)
                app.write_reports()
            else:
                ui.error("Not a directory.")

        elif choice.startswith("REPORT"):
            app.write_reports()

        elif choice.startswith("RESCAN"):
            target = ui.ask("Target domain or URL", target)
            result = app.do_scan(target)
            app.render_scan(result)
            vulnerable = result.status in ("VULNERABLE", "UNKNOWN") and result.is_php

        elif choice.startswith("EXIT"):
            print()
            ui.dim("  Summary of where you stand:")
            if result.status == "VULNERABLE":
                ui.warn(f"{target} still runs PHP {format_version(result.php_version)} "
                        f"and remains exposed until it is upgraded.")
            elif result.status == "PATCHED":
                ui.ok(f"{target} appears patched.")
            else:
                ui.warn(f"{target} could not be verified - check `php -v` on the host.")
            print()
            return 0
        else:
            ui.warn("Unknown option.")
    return 0


def non_interactive(args: argparse.Namespace) -> int:
    if args.json:
        ui.set_silent(True)
    app = App(args)
    if not args.quiet:
        ui.banner(LEGAL)

    exit_code = 0

    if args.target:
        result = app.do_scan(args.target)
        app.render_scan(result)
        if result.status == "VULNERABLE":
            exit_code = 1
        elif result.status == "UNKNOWN" and result.is_php:
            exit_code = 2

    root = args.codebase
    if root or args.fix:
        if not root:
            ui.error("--fix needs --codebase PATH")
            return 2
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            ui.error(f"{root} is not a directory.")
            return 2
        if args.fix:
            app.do_fix(root)
            if any(f.applied for f in app.fixes) or app.fixes:
                exit_code = max(exit_code, 1) if not all(f.applied for f in app.fixes) else exit_code
        else:
            app.do_codebase(root)

    if app.scan or app.code:
        app.write_reports()
    return exit_code


def main(argv: Optional[List[str]] = None) -> int:
    args = resolve_args(argv)

    if args.subcommand == "audit" and not args.codebase:
        ui.error("usage: php2shell audit <path>")
        return 2

    # A terminal gets the guided scan -> flag -> fix/exit loop. Automation
    # (--json, --quiet, --apply, --yes, or a non-TTY stdin) gets the flat run.
    want_interactive = (
        not args.json
        and not args.quiet
        and not args.apply
        and not args.yes
        and sys.stdin.isatty()
    )

    try:
        if want_interactive:
            return interactive(args)
        return non_interactive(args)
    except KeyboardInterrupt:
        print()
        ui.warn("Interrupted.")
        return 130
    except LLMError as exc:
        ui.error(f"LLM error: {exc}")
        return 3
