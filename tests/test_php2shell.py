"""Test suite for the php2shell scanner.  Run with:  python3 -m pytest -q
(or python3 -m unittest discover -s tests)"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell import vulndb                                        # noqa: E402
from php2shell.codebase import scan as scan_codebase                # noqa: E402
from php2shell.detect import Detector, cookie_is_suspicious         # noqa: E402
from php2shell.fixer import (apply_fix, plan_fixes, rule_fixes,     # noqa: E402
                             unified_diff, write_patch_bundle)
from php2shell.http import HttpClient                               # noqa: E402
from php2shell.llm import LLMClient, parse_patch_json               # noqa: E402
from php2shell.version import parse_version, format_version         # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SAMPLE = os.path.join(ROOT, "examples", "sample-app")

sys.path.insert(0, os.path.join(ROOT, "examples"))
import fake_php_host  # noqa: E402


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_version("8.2.35"), (8, 2, 35))
        self.assertEqual(parse_version("PHP/8.1.2"), (8, 1, 2))
        self.assertEqual(parse_version("php 7.4"), (7, 4, 0))
        self.assertEqual(parse_version("8.3.36-1+deb12u1"), (8, 3, 36))
        self.assertIsNone(parse_version("unknown"))
        self.assertIsNone(parse_version(""))
        self.assertIsNone(parse_version("1.2"))

    def test_format(self):
        self.assertEqual(format_version((8, 2, 35)), "8.2.35")
        self.assertEqual(format_version(None), "unknown")


class AssessTests(unittest.TestCase):
    def test_supported_branches(self):
        for version, fixed in [
            ((8, 5, 11), (8, 5, 12)),
            ((8, 4, 26), (8, 4, 27)),
            ((8, 3, 35), (8, 3, 36)),
            ((8, 2, 34), (8, 2, 35)),
        ]:
            status, _ = vulndb.assess(version)
            self.assertEqual(status, "VULNERABLE", version)
            status, _ = vulndb.assess(fixed)
            self.assertEqual(status, "PATCHED", fixed)

    def test_eol_is_vulnerable(self):
        for v in [(5, 6, 40), (7, 4, 33), (8, 0, 30), (8, 1, 2)]:
            status, reason = vulndb.assess(v)
            self.assertEqual(status, "VULNERABLE", v)
            self.assertIn("end-of-life", reason)

    def test_unknown(self):
        self.assertEqual(vulndb.assess(None)[0], "UNKNOWN")
        self.assertEqual(vulndb.assess((8, 9, 1))[0], "UNKNOWN")

    def test_fixed_releases_match_advisory(self):
        self.assertEqual(vulndb.FIXED_RELEASES, {
            "8.5": (8, 5, 12), "8.4": (8, 4, 27),
            "8.3": (8, 3, 36), "8.2": (8, 2, 35),
        })


class CookieTests(unittest.TestCase):
    def test_normal_cookie(self):
        self.assertFalse(cookie_is_suspicious("a" * 26))
        self.assertFalse(cookie_is_suspicious(""))

    def test_memory_disclosure_shape(self):
        blob = "".join(f"%{i:02X}" for i in range(1, 40))
        self.assertTrue(cookie_is_suspicious(blob))


class LiveHostTests(unittest.TestCase):
    """Spins the fake PHP host up in-process and scans it."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), fake_php_host.make_handler("8.1.2", True))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_detects_php_and_version(self):
        client = HttpClient(timeout=5, delay=0)
        result = Detector(client).run(self.url)
        self.assertTrue(result.is_php)
        self.assertEqual(result.php_version, (8, 1, 2))
        self.assertEqual(result.status, "VULNERABLE")
        ids = {f.id for f in result.findings}
        self.assertIn("PHP2SHELL-CVE-2026-109618", ids)
        self.assertIn("PHP2SHELL-CVE-2026-109619", ids)

    def test_patched_host_is_clean(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), fake_php_host.make_handler("8.4.27", True))
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            result = Detector(HttpClient(timeout=5, delay=0)).run(f"http://127.0.0.1:{port}")
            self.assertEqual(result.php_version, (8, 4, 27))
            self.assertEqual(result.status, "PATCHED")
        finally:
            server.shutdown()
            server.server_close()

    def test_unreachable_target(self):
        result = Detector(HttpClient(timeout=2, delay=0)).run("http://127.0.0.1:1")
        self.assertFalse(result.is_php)
        self.assertTrue(any(f.id == "SCAN-TRANSPORT" for f in result.findings))


class CodebaseTests(unittest.TestCase):
    def test_finds_all_three_pins(self):
        report = scan_codebase(SAMPLE)
        paths = {r.path for r in report.runtimes}
        self.assertIn("Dockerfile", paths)
        self.assertIn("composer.json", paths)
        self.assertIn(".github/workflows/ci.yml", paths)
        self.assertTrue(report.php_files >= 1)
        ids = {f.id for f in report.findings}
        self.assertIn("CODE-RUNTIME-PIN", ids)
        self.assertIn("CODE-UPLOAD-PROGRESS-ON", ids)

    def test_missing_path(self):
        report = scan_codebase("/nope/does/not/exist")
        self.assertTrue(report.findings)


class FixerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "app")
        shutil.copytree(SAMPLE, self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rule_fix_flips_upload_progress(self):
        files = {"docker/php.ini": open(os.path.join(self.root, "docker/php.ini")).read()}
        fixes = rule_fixes(self.root, files)
        self.assertTrue(fixes)
        self.assertIn("session.upload_progress.enabled = Off", fixes[0].patched)

    def test_patch_bump_same_branch(self):
        files = {"Dockerfile": "FROM php:8.4.20-fpm\n"}
        fixes = rule_fixes(self.root, files)
        self.assertEqual(fixes[0].patched.strip(), "FROM php:8.4.27-fpm")

    def test_no_change_when_already_fixed(self):
        files = {"Dockerfile": "FROM php:8.4.27-fpm\n"}
        self.assertEqual(rule_fixes(self.root, files), [])

    def test_mock_plan_and_apply(self):
        report = scan_codebase(self.root)
        client = LLMClient(provider="mock")
        fixes, summary, notes = plan_fixes(self.root, report, None, client)
        paths = {f.path for f in fixes}
        self.assertIn("Dockerfile", paths)
        self.assertIn("composer.json", paths)
        self.assertIn("docker/php.ini", paths)

        fix = next(f for f in fixes if f.path == "Dockerfile")
        apply_fix(self.root, fix)
        self.assertTrue(fix.applied)
        self.assertTrue(fix.backup and fix.backup.endswith(".bak"))
        content = open(os.path.join(self.root, "Dockerfile")).read()
        self.assertIn("FROM php:8.2.35-apache", content)

    def test_diff_and_bundle(self):
        report = scan_codebase(self.root)
        fixes, _, _ = plan_fixes(self.root, report, None, LLMClient(provider="mock"))
        self.assertIn("--- a/Dockerfile", unified_diff(next(f for f in fixes if f.path == "Dockerfile")))
        path = write_patch_bundle(fixes, self.tmp)
        self.assertTrue(os.path.exists(path))
        self.assertIn("git apply", open(path).read())

    def test_refuses_unsafe_paths(self):
        from php2shell.fixer import _read_file
        self.assertIsNone(_read_file(self.root, "../../etc/passwd"))
        self.assertIsNone(_read_file(self.root, "vendor/autoload.php"))


class LLMParsingTests(unittest.TestCase):
    def test_json_in_fences(self):
        raw = 'Here you go:\n```json\n{"summary": "x", "patches": []}\n```'
        self.assertEqual(parse_patch_json(raw)["summary"], "x")

    def test_json_with_prose(self):
        raw = 'Sure! {"summary": "y", "patches": []} hope that helps'
        self.assertEqual(parse_patch_json(raw)["summary"], "y")

    def test_garbage(self):
        self.assertEqual(parse_patch_json("no json here"), {})

    def test_mock_docker_branches(self):
        from php2shell.llm import _mock_docker_tag
        out = _mock_docker_tag("FROM php:8.1-apache\nFROM php:8.4.20-fpm\nFROM php:8.4.27\n")
        self.assertIn("FROM php:8.2.35-apache", out)
        self.assertIn("FROM php:8.4.27-fpm", out)
        self.assertIn("FROM php:8.4.27", out)


class ReportTests(unittest.TestCase):
    def test_writers_produce_files(self):
        from php2shell import report as rep
        tmp = tempfile.mkdtemp()
        try:
            code = scan_codebase(SAMPLE)
            fixes, _, _ = plan_fixes(SAMPLE, code, None, LLMClient(provider="mock"))
            for fn in (rep.write_json, rep.write_markdown, rep.write_html):
                path = fn(None, code, fixes, tmp)
                self.assertTrue(os.path.exists(path))
                self.assertGreater(os.path.getsize(path), 200)
            html = [f for f in os.listdir(tmp) if f.endswith(".html")][0]
            body = open(os.path.join(tmp, html)).read()
            self.assertIn("CVE-2026-109618", body)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
