# Threat brief: php2shell (CVE-2026-109618 / CVE-2026-109619)

Distilled from the two write-ups this tool is built on. Every claim below traces
back to one of them.

**Sources**

1. Huntress — *Rapid Response: php2shell, Leaked Critical PHP Vulnerabilities*
   <https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities>
   (published 2026-10-20, updated 2026-10-21)
2. Wiz Research — *PHP2Shell: AI uncovers critical RCE vulnerabilities affecting
   70% of the Internet* <https://www.wiz.io/blog/php2shell-php-rce>
   (2026-10-21)

Primary advisories: [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
(CVE-2026-109618) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
(CVE-2026-109619).

---

## 1. Timeline

| When (2026) | What |
| --- | --- |
| Oct 20, morning | A Hacker News post leaks that two critical PHP vulnerabilities are heading for disclosure. Post is removed, screenshots circulate. watchTowr confirms they are real. |
| Oct 20 | PHP publishes an advance notice: two critical flaws, CVSS v4.0 **9.2**, security release scheduled for **Oct 21, 14:00 UTC** — a day earlier than the original embargo. PHP reserves the right to ship sooner if details leak or exploitation appears. |
| Oct 21, ~09:30 ET | PHP ships **8.5.12, 8.4.27, 8.3.36, 8.2.35**. |
| Oct 21, ~16:30 ET | Technical write-ups land (Calif, Wiz, OpenAI, PHP Foundation). Huntress had not observed in-the-wild exploitation on partner systems at that point, but other researchers reported attacks emerging. |

## 2. Why this is different from a CMS bug

The vulnerable code is **PHP itself**. Wiz demonstrated unauthenticated RCE
against `wordpress:latest`, `drupal:latest` and `joomla:latest` container images,
but those are only *demonstration targets*: a Hello-World page on an affected
runtime is equally exploitable. Every PHP release in the last decade — back to
**5.4** — is affected by at least one of the bugs.

Practical consequence for defenders: you cannot fix this with a plugin update, a
WAF rule on `/wp-login.php`, or application hardening. You fix it by changing the
PHP build, or by removing the vulnerable code path from the config.

## 3. The four bugs, under two CVEs

All four are memory-safety issues in how PHP handles **fatal errors while
processing requests, particularly out-of-memory errors**. Those bugs leave a
corrupted internal engine state behind after a request dies unexpectedly; a later
request handled by the same worker can reuse that stale state, producing memory
disclosure or corruption.

### CVE-2026-109618

**a) Upload-progress unserializer use-after-free.** PHP's Session module can
decode session data during upload-progress handling inside the pre-initialisation
window. The decoder stores request-owned bookkeeping in `BG(unserialize)`. A
fatal allocation failure interrupts the path, destroys the request heap, and
leaves the unserializer's global state published. On a later request the same
worker consumes attacker-reclaimed memory as live unserializer bookkeeping —
a strong memory-corruption primitive. Chained with the disclosure below, this
gives unauthenticated RCE on WordPress, Drupal and Joomla.

**b) Remote process-memory disclosure.** PHP parses RFC1867 multipart requests
during request startup, before normal module initialisation. Session
upload-progress handling can initialise Session state this early and publish a
session id in `PS(id)`. An out-of-memory error aborts the request before cleanup;
PHP then destroys the request heap and may leave `PS(id)` pointing at the freed
allocation. A later multipart request reaches the upload-progress cleanup path
before normal Session initialisation resets the pointer. PHP trusts the stale
pointer and length as a live `zend_string` and **URL-encodes the reclaimed heap
into a `PHPSESSID` response cookie**. It works even if the application never
calls `session_start()`, which makes it application-agnostic. Attackers can read
passwords, auth tokens, API keys and certificates belonging to other requests or
the server itself.

### CVE-2026-109619

**c) Fatal-error backtrace use-after-free.** PHP retains the backtrace of the
most recent fatal error in `EG(last_fatal_error_backtrace)`. A fatal OOM destroys
the request heap without undefining that executor-global value. If the same
worker emits a diagnostic early in the next request, it touches the pointer
before the executor reinitialises that state and follows attacker-reclaimed
memory. Demonstrated as pre-auth RCE against **Drupal**.

**d) OPcache type confusion.** OPcache persists compiled structures in shared
memory and assigns indices into per-worker runtime-pointer maps, coordinated
through a shared frontier. During `zend_accel_script_persist()`, PHP advances the
process-local `CG(map_ptr_last)` frontier and publishes the shared frontier only
after persistence completes. An allocation failure between those events leaves
the local advance in place with partially persisted objects pointing at slots the
shared state still considers free. Another worker reusing such a slot for a
different runtime object makes stale shared metadata resolve to the wrong type —
cross-worker type confusion in shared OPcache. Demonstrated as pre-auth RCE
against **WordPress**.

Wiz notes there are further tracked and untracked variants with different
requirements and impacts; PHP's patch fixes the class of bug at the core.

## 4. Exposure

PHP lists as at-risk anything serving web requests: **PHP-FPM, Apache with
mod_php, php-cgi, FrankenPHP, LiteSpeed**. An exploit exists for `mod_php` where
an unauthenticated request triggers the attack **before any application code
runs**.

## 5. What to do

**Patch. This is the only complete remediation.**

| Branch | Fixed release |
| --- | --- |
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |

- Linux distributions and LTS vendors had patches ahead of publication — check
  your vendor's packaging.
- **PHP 8.1 and older** get no official update. Vendors may backport; the PHP
  security team published minimal source backports for **7.4, 8.0 and 8.1**.
- Users of the volunteer `rpms.remirepo.net` repository were told to move to
  distribution packages or build from source.

**If you cannot patch today**

- Set `session.upload_progress.enabled = Off` in `php.ini`. Huntress explicitly
  recommends this for end-of-life branches; it removes the known abuse case.
- Apply the vendor WAF/CDN rule sets published for this disclosure (Cloudflare,
  Fastly, AWS, Google Cloud, Imperva, Akamai, Microsoft, Vercel).
- Isolate end-of-life PHP from the internet.
- Inventory *everything* that runs PHP, including vendor software and appliances
  that never advertise it.

## 6. Detection

Exploitation happens below the application layer, so application logs may hold
little context. What to hunt for:

- Unusual multipart requests followed by **memory-limit errors** or repeated
  **HTTP 500** responses.
- Unexpectedly **large or malformed `PHPSESSID` response cookies** — a
  percent-encoded blob where a 26–32 character session id belongs.
- Unexplained **PHP worker churn**: workers exiting or respawning in bursts
  without matching request volume.
- PHP worker processes (`php-fpm`, `php-cgi`, `httpd`, `apache2`) spawning
  `sh`, `bash`, `cmd.exe`, `powershell.exe`, `python`, `perl`, `curl`, `wget`,
  `nc`, `certutil`.
- Command lines containing `/dev/tcp/`, `mkfifo`, or PHP one-liners that write a
  temp `.php` file, execute it and delete it.
- Recon straight from the web server: `whoami`, `id`, `uname -a`, `ipconfig`.

Wiz's Sensor customers got an out-of-the-box response policy to terminate
processes showing php2shell exploitation behaviour.

## 7. The AI angle

These bugs sat in PHP for more than a decade. Exploiting them required chaining
multiple faults and adapting to each target's memory layout through repeated
testing — at the edge of what human researchers could practically do. Wiz used
**Wiz Atlas**, **Gemini 4 Argon** and **GPT-5.6 Sol**; Gemini 4 Argon
contributed to finding the bug, exploit development, detection engineering and
patch validation. Californ (Calif) revisited earlier PHP memory-limit findings
through OpenAI's **Patch the Planet** initiative.

The takeaway defenders should internalise: *complexity is no longer a meaningful
barrier*. Bugs that were impractical to exploit become viable targets, and
detection time compresses.

## 8. How this tool maps to the brief

| Brief item | Implementation |
| --- | --- |
| Inventories PHP installs | remote fingerprinting + `--php-version` assertion |
| Version-vs-fix judgement | `php2shell/vulndb.py` (fixed releases, EOL branches) |
| Interim mitigation | config fixes for `session.upload_progress.enabled` |
| Detection guidance | indicator findings carried into every report |
| Post-exploitation hygiene | "rotate secrets the worker could read" reminder |
| Application-agnostic framing | every report states that app-level patching will not help |
