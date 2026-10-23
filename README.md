```
██████╗ ██╗  ██╗██████╗     ██████╗     ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██║  ██║██╔══██╗    ╚════██╗    ██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝███████║██████╔╝     █████╔╝    ███████╗███████║█████╗  ██║     ██║     
██╔═══╝ ██╔══██║██╔═══╝     ██╔═══╝     ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║     ██║  ██║██║         ███████╗    ███████║██║  ██║███████╗███████╗███████╗
╚═╝     ╚═╝  ╚═╝╚═╝         ╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```

<div align="center">

**CVE-2026-109618 · CVE-2026-109619 · PHP Engine RCE (CVSS 9.2)**

*A passive scanner + LLM-powered fixer for the most critical PHP engine vulnerabilities ever disclosed.*

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-cyan?logo=python&logoColor=white)](https://python.org)
[![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)](pyproject.toml)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-cyan.svg)](CONTRIBUTING.md)
[![Author](https://img.shields.io/badge/Author-abenezer101-cyan?logo=github)](https://github.com/abenezer101)

</div>

---

## What is php2shell?

**php2shell** is an open-source CLI tool that:

1. **Scans** any domain or URL to detect whether it is running a PHP version affected by CVE-2026-109618 and CVE-2026-109619 — two memory-safety bugs in the PHP engine itself (not in any CMS or framework).
2. **Audits** your code base for pinned runtime versions and vulnerable configuration flags.
3. **Fixes** the exposure — deterministically where possible, and via your chosen LLM for complex cases — producing a reviewed, `git apply`-able patch.

> **Why a dedicated tool?**
> These are bugs in the PHP **engine**, not WordPress, Drupal, or Joomla. Application patches don't help. You must change the PHP build or disable the vulnerable code path in the runtime config — that's exactly what this tool targets.

Background and full technical breakdown → [`docs/THREAT-BRIEF.md`](docs/THREAT-BRIEF.md)
Public write-ups: [Huntress](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities) · [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce)

---

## Quick Start

**No dependencies. Python 3.9+ only.**

```bash
# Clone and run immediately
git clone https://github.com/abenezer101/php2shell.git
cd php2shell
python3 php2shell.py --help
```

```bash
# Or install as a CLI command
pip install -e .
php2shell scan example.com
```

```bash
# Run the test suite (24 tests, no network needed)
python3 -m pytest -q
```

---

## Interactive Flow

```bash
python3 php2shell.py
```

```
Target domain or URL to scan: acme-store.com

Remote scan → https://acme-store.com
──────────────────────────────────────────────
  Target                  https://acme-store.com
  Resolved                203.0.113.42
  PHP detected            yes (confidence 9/10)
  PHP version             8.1.14 (X-Powered-By header)
  Server                  Apache/2.4.56 (Debian)
  SAPI hints              mod_php (likely)
  CMS                     WordPress 6.4.2
  Verdict                 VULNERABLE risk 95/100

  [CRITICAL] CVE-2026-109618: Upload-progress unserializer use-after-free
  [CRITICAL] CVE-2026-109619: Fatal-error backtrace use-after-free
  [MEDIUM  ] Interim mitigation available while you schedule the upgrade
  [LOW     ] PHP advertises its exact version in HTTP headers (expose_php=On)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ACTION REQUIRED — this host is running an affected PHP build.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  1) FIX       point me at the code base and patch the bug
  2) REPORT    write the JSON/Markdown/HTML report
  3) RESCAN    scan again or try a different target
  4) EXIT      stop here

What next? [FIX]:
```

Choose **FIX** and the tool walks you through code-base audit → LLM patch generation → unified diff review → safe apply with `.bak` backups.

```
  ✓ Patched Dockerfile (backup Dockerfile.php2shell.20261022-213008.bak)
  ✓ Patch bundle written: php2shell-reports/php2shell-remediation.patch
```

---

## Command Line Reference

```bash
php2shell                                         # interactive — asks for a target
php2shell scan example.com                        # scan → offer fix/report/exit
php2shell scan example.com --probe                # + opt-in behavioural probes
php2shell scan example.com --codebase ./www --fix # scan + immediately fix
php2shell audit ./www                             # code-base only, no network
php2shell scan example.com --php-version 8.3.30  # override fingerprinting
php2shell scan example.com --json                 # machine-readable, no prompts
```

| Flag | Meaning |
|---|---|
| `-c, --codebase PATH` | PHP project root to audit / remediate |
| `--fix` | go straight into the remediation flow |
| `--probe` | run opt-in behavioural probes *(see Ethics below)* |
| `--php-version X.Y[.Z]` | assert runtime version instead of fingerprinting |
| `--timeout`, `--proxy`, `--insecure` | HTTP behaviour |
| `--llm-provider` | `openai` (default) · `anthropic` · `gemini` · `mock` |
| `--llm-key`, `--llm-model`, `--llm-base-url` | key / model / gateway override |
| `--apply` | apply edits without confirming |
| `--dry-run` | never touch the code base, only emit the patch file |
| `--report-dir` | where reports go (default `php2shell-reports/`) |
| `--json`, `--quiet`, `--verbose`, `--yes` | output and automation control |

**Exit codes:** `0` clean · `1` vulnerable / unapplied fixes · `2` bad usage · `3` LLM error · `130` interrupted

### LLM Key Handling

The key is resolved in this order and **never written to disk**:

```bash
export PHP2SHELL_LLM_KEY=sk-...      # checked first, any provider
export OPENAI_API_KEY=...            # or ANTHROPIC_API_KEY / GEMINI_API_KEY
```

Leave blank at the prompt to fall back to the built-in **`mock`** engine — fully offline, deterministic, great for CI and demos. For Azure OpenAI or a self-hosted gateway, use `--llm-base-url`.

---

## How It Works

### Scan Pipeline

| Step | What happens |
|---|---|
| **Transport** | HTTPS first, auto HTTP fallback, TLS on, 0.35 s pacing, redirects recorded but not followed off-host |
| **PHP detection** | `X-Powered-By`, `Server`, `PHPSESSID` cookies, `.php` links, CMS paths, `phpinfo` easter egg — weighted confidence score |
| **Version** | `X-Powered-By`, `Server`, `composer.json`, `phpinfo` pages, in-page strings |
| **Verdict** | Compared against fixed releases per branch (see table below) |
| **Context** | CMS & version, SAPI hints, `expose_php` hygiene |

### Fixed Release Table

| Branch | First safe release |
|---|---|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |
| ≤ 8.1 | End-of-life — no upstream patch; mitigate then upgrade |

> Any version where fingerprinting is not possible is reported as **UNKNOWN / HIGH** — every PHP release back to 5.4 is affected.

### Fix Pipeline

1. **Code-base audit** — walks the repo (skipping `vendor/`, `node_modules/`, caches) and finds every PHP runtime pin: `Dockerfile FROM php:...`, `composer.json`, GitHub Actions workflows, `platform.app.yaml`, compose files, `php.ini`, FPM pools, `.htaccess`.
2. **Deterministic pass** — mechanical edits with no model: flip `session.upload_progress.enabled On → Off`, bump exact patch releases inside a supported branch.
3. **LLM pass** — remaining files, CVE facts, scan verdict, and audit findings are sent to your provider. Returns strict JSON patches; anything touching an unknown path is rejected.
4. **Review** — every change is printed as a unified diff and written to `php2shell-remediation.patch` *before* anything is touched.
5. **Apply** — on confirmation, files are written with timestamped `.bak` backups.

**Safety rails:** edits restricted to config/deployment files; no writes outside project root; no `vendor/`/`node_modules/`; 400 KB per-file ceiling; the model is instructed never to write secrets.

---

## Reports

Every run writes to `--report-dir` (`php2shell-reports/` by default):

| File | Format |
|---|---|
| `report-<stamp>.json` | Full machine-readable result |
| `report-<stamp>.md` | Ticket-ready summary with tables and evidence |
| `report-<stamp>.html` | Self-contained HTML (no external assets), safe to email |
| `php2shell-remediation.patch` | Unified diff of all proposed fixes (`git apply`-able) |

---

## Findings Reference

| ID | Severity | Meaning |
|---|---|---|
| `PHP2SHELL-CVE-2026-109618` | 🔴 CRITICAL | Runtime predates the fix; UAF + memory disclosure |
| `PHP2SHELL-CVE-2026-109619` | 🔴 CRITICAL | Runtime predates the fix; backtrace UAF + OPcache confusion |
| `PHP2SHELL-COOKIE-ANOMALY` | 🔴 CRITICAL | Probe saw the memory-disclosure cookie shape |
| `PHP2SHELL-UNKNOWN` | 🟠 HIGH | PHP confirmed but version unverifiable → treat as exposed |
| `CODE-RUNTIME-PIN` | 🔴 CRITICAL | Vulnerable PHP pinned in the repo |
| `CODE-UPLOAD-PROGRESS-ON` | 🟠 HIGH | Vulnerable code path is enabled |
| `PHP2SHELL-MITIGATE` | 🟡 MEDIUM | Interim controls available while scheduling upgrade |
| `CODE-NO-MITIGATION` | 🟡 MEDIUM | No interim mitigation pinned anywhere |
| `CODE-NO-PIN` | 🟡 MEDIUM | Runtime managed outside the repo |
| `PHP2SHELL-STABILITY` | 🔵 LOW/MED | 5xx cluster under multipart traffic |
| `PHP2SHELL-EXPOSE-PHP` | 🔵 LOW | `expose_php=On` reveals exact version to attackers |
| `PHP2SHELL-DETECT-GUIDANCE` | ⚪ INFO | SIEM/EDR hunting indicators |

---

## Ethics & Responsible Use

> **Only scan systems you own or have written authorisation to test.**

The **default scan** is fully passive: ordinary GET requests to a fixed path list + fingerprinting headers. It never sends an exploit and never attempts memory corruption.

`--probe` adds two **opt-in** behavioural checks (still non-exploitative):

1. **Cookie shape** — one well-formed multipart POST, inspecting whether the `PHPSESSID` cookie contains percent-encoded binary (the documented memory-disclosure symptom).
2. **Stability** — a handful of ordinary multipart requests, counting 5xx responses and dropped connections.

Neither check can execute code. Both touch the code path adjacent to the memory bug — on production systems, prefer the passive verdict and check the target's change-control rules first.

---

## Project Layout

```
php2shell/
├── php2shell.py                  # entry point
├── php2shell/
│   ├── cli.py                    # argparse + interactive scan→fix→exit loop
│   ├── detect.py                 # remote PHP/CMS fingerprinting
│   ├── probe.py                  # opt-in behavioural probes
│   ├── vulndb.py                 # CVEs, fixed releases, mitigations, indicators
│   ├── codebase.py               # local runtime-pin + config audit
│   ├── fixer.py                  # rule pass, LLM pass, diffs, safe apply
│   ├── llm.py                    # openai / anthropic / gemini / mock
│   ├── report.py                 # json / markdown / html writers
│   ├── http.py                   # transport layer
│   ├── model.py                  # data models
│   ├── ui.py                     # terminal presentation helpers
│   └── version.py                # version detection utilities
├── examples/
│   ├── fake_php_host.py          # local test target (PHP 8.1.2)
│   └── sample-app/               # deliberately vulnerable project to fix
├── tests/
│   └── test_php2shell.py         # 24 unit tests, zero network
├── docs/
│   └── THREAT-BRIEF.md           # full CVE technical breakdown
├── demo.sh                       # one-shot end-to-end demo
└── pyproject.toml
```

---

## Try It Locally (End-to-End Demo)

```bash
# Terminal 1 — spin up a fake vulnerable host on port 8089
python3 examples/fake_php_host.py --port 8089 --version 8.1.2

# Terminal 2 — scan + fix against the sample app (no LLM key needed)
cp -r examples/sample-app /tmp/demo-app
python3 php2shell.py scan http://127.0.0.1:8089 \
    --codebase /tmp/demo-app --fix --llm-provider mock --dry-run

# Or run both in one go
./demo.sh
```

---

## Limitations

- **Version visibility** — `expose_php=Off` and CDNs hide versions. The tool reports UNKNOWN rather than guessing. Use `--php-version` once you know it, or scan the origin directly.
- **CDN fronting** — A CDN answers for the PHP origin. Scan the origin, or run the code-base audit and check container tags.
- **Containers** — A `Dockerfile` is not a running container. Confirm the deployed image digest matches what you patched.
- **Backports** — Distributions backport fixes without changing the version string, so a "vulnerable" banner on a patched distro package is possible. Confirm with your vendor's advisory.
- **No exploitation** — The tool proves exposure by version and behaviour, not by executing a payload. A PATCHED verdict from a version banner is weaker evidence than `php -v` on the host.
- **LLM is advisory** — Review every diff. A runtime jump can change bundled extensions; test before deploying to production.

---

## Contributing

Contributions are welcome and appreciated!

```bash
# Fork the repo, then:
git clone https://github.com/abenezer101/php2shell.git
cd php2shell

# Create a feature branch
git checkout -b feature/my-improvement

# Run tests before and after your change
python3 -m pytest -q

# Submit a pull request
```

**Good first issues:**
- Add detection for additional PHP fingerprinting paths
- Extend `vulndb.py` with new CVE entries
- Add support for additional LLM providers
- Improve the HTML report template

Please match the code style used in existing files and preserve the **zero external dependencies** constraint.

---

## License

```
MIT License

Copyright (c) 2026 abenezer101

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

<div align="center">

Made with ☕ by **[abenezer101](https://github.com/abenezer101)**

⭐ Star the repo if this saved your stack

</div>
