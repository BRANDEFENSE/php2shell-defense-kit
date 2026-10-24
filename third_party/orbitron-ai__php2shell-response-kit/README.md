# php2shell — CVE-2026-109618 / CVE-2026-109619 · ORBITRON response kit

> **Status: v1.3.0 — FIXES RELEASED (2026-10-21).** PHP published **8.5.12, 8.4.27, 8.3.36 and 8.2.35**.
> Scripts now know the fixed versions and check the interim mitigations from the PHP advisory; new rules
> for the trigger condition. Sections marked *pre-disclosure* are kept for the record. See [CHANGELOG.md](CHANGELOG.md).
>
> Türkçe sürüm: [README.tr.md](README.tr.md)

## TL;DR

* Two critical, unauthenticated remote code execution bugs in PHP core (CVSS v4.0 9.2 each).
  **Fixed in PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (21 Oct 2026). PHP 8.1 and older: no upstream fix.
* **Root cause (from the official fix):** when `memory_limit` is reached **while PHP parses the request**
  (POST / multipart / upload data — before any script runs), PHP aborts and leaves request state
  half-initialised (CVE-2026-109618) or stale for the **next request on the same worker** (CVE-2026-109619).
  Any reachable `.php` file is enough; mod_php is the highest-risk SAPI, PHP-FPM is affected too.
* **Update and restart all PHP workers — that is the only complete fix.**
* Interim mitigations from the PHP advisory (reduce exposure only): `memory_limit = -1` **plus a
  cgroup/container memory limit**, `post_max_size = 8M` (32M if uploads are needed),
  `session.upload_progress.enabled = 0`, `fatal_error_backtraces = 0` (8.5). In our lab only
  `memory_limit = -1` stopped the abort for PHP's own regression-test request (§9).
* This kit: inventory scripts (fixed-version + mitigation check, containers included) and rules for Sigma,
  Splunk, QRadar, CrowdStrike Falcon, SentinelOne, Wazuh, YARA and ModSecurity — each labelled with what
  was tested.

## 1. What happened?

| Item | Status |
|---|---|
| Fixed releases 8.5.12, 8.4.27, 8.3.36, 8.2.35 (21 Oct 2026) | **Confirmed** — php.net release announcements |
| CVE-2026-109618 = GHSA-w8hw-w9fx-j79w, CVE-2026-109619 = GHSA-6wmf-4rv5-p3rp | **Confirmed** — PHP NEWS and fix commit "Avoid state corruption via bailout" |
| Bug class: state corruption after an out-of-memory abort during request start-up / request parsing; stale request state reused by the next request | **Confirmed** — php.net advisory text and the fix (OOM bailout replaced by unwinding; globals reset; parser stops at the soft limit) |
| mod_php highest risk; unauthenticated, before application code runs | **Confirmed** — php.net |
| Two critical PHP security bugs, CVSS v4.0 9.2 each | **Confirmed** by php.net (advance notice of 20 Oct) |
| Bug class: remote code execution in PHP core, unauthenticated | Reported by watchTowr (reproduced CVE-2026-109618) and others; PHP has not published details |
| CVE IDs CVE-2026-109618 / CVE-2026-109619 | From watchTowr and the leaked material; the php.net notice does not name them; records are reserved |
| Nickname "php2shell", exploit tool "PHP2Shell" claiming PHP ≥ 5.4 | Reported (screenshot leak) — unconfirmed |
| Affected versions "PHP 5 through 8" | Reported — **unconfirmed** |
| Fixes for supported branches only (8.2, 8.3, 8.4, 8.5) | Reported; consistent with PHP's support policy |
| Link to *Session Upload Progress* (`ext/session`), memory corruption | Pre-disclosure assessment by GMO Flatt Security. **The fix shows it is one path, not the cause**: it also hardens the upload-progress handler (no class resolution / user code before request start-up, no leftover `$_SESSION`) |
| Exploitation in the wild | None reported as of 21 Oct morning (watchTowr, Huntress) |

Timeline: 20 Oct ~15:20 UTC a Hacker News post leaks the upcoming disclosure → 20 Oct 19:33 UTC PHP
publishes the advance notice → 21 Oct: fixed releases and advisory on php.net.

## 2. Why it matters

* PHP runs a large share of the public web: WordPress/WooCommerce, Magento/Adobe Commerce, Shopware,
  Drupal, Laravel/Symfony apps, hosting control panels and many appliances that bundle PHP.
* A core-interpreter RCE is reachable through *any* application on the affected runtime — application
  hardening and application-level WAF plugins run *after* PHP has processed the request.
* Researchers (e.g. Sansec) expect mass exploitation within minutes of the release, because the patch
  diff reveals the bug.
* Large end-of-life population: internet scans count hundreds of thousands of hosts advertising PHP 8.1
  or older, which will not receive an upstream fix.

## 3. Affected systems — what we know now

| Runtime | Situation (21 Oct) |
|---|---|
| PHP 8.2 / 8.3 / 8.4 / 8.5 from php.net, Remi, deb.sury.org, official Docker images, Windows builds | **Fixed upstream in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** — repackaged builds follow |
| PHP 8.1 and older (upstream EOL) | **No upstream fix.** Only distribution/ESM/vendor backports or an upgrade |
| Distribution packages (RHEL/Rocky/Alma, Debian, Ubuntu, SUSE) | Fix arrives via the distribution's security process — timing differs, see §7 |
| All SAPIs (mod_php, PHP-FPM, CGI/FastCGI, LiteSpeed) | php.net: mod_php highest risk. Persistent workers (mod_php, FPM, LiteSpeed) carry stale state between requests; per-request CGI processes do not reuse it |

## 4. What to check (use the scripts)

| Script | Platform | What it does |
|---|---|---|
| [`scripts/linux/php2shell-check.sh`](scripts/linux/php2shell-check.sh) | Linux (RHEL family, Debian/Ubuntu, Alpine, cPanel/Plesk/CloudLinux/Remi paths) | Finds every PHP binary and SAPI, reads the **effective** settings per SAPI (CLI, FPM, CGI, mod_php ini set), lists FPM-pool / web-server / `.user.ini` / `.htaccess` overrides, owning package + origin (distro, Remi, Sury), whether the package changelog already lists the CVEs, running processes, **whether the running FPM workers / Apache children were started after the last config change and still run the current binary** (`LOADED` / `STALE` / `RESTART REQUIRED`), and **PHP inside containers / Kubernetes pods on the host** (Docker, Podman, containerd, CRI-O) inspected read-only via `/proc/<pid>/root` — version, package, `session.upload_progress` and running state per container, with pod/container names when `crictl`/`docker`/`podman` is available |
| [`scripts/windows/php2shell-check.ps1`](scripts/windows/php2shell-check.ps1) | Windows (IIS FastCGI, XAMPP, WAMP, Laragon, Plesk, PATH, running processes) | Same for Windows; evaluates each IIS FastCGI application with its own arguments/`PHPRC`, and checks whether running `php-cgi.exe` / Apache processes predate the last `php.ini` change or the PHP binary (incl. IIS `monitorChangesTo`) |

Both are **read-only**, make no network connections and do not attempt exploitation. JSON output for
fleet collection (e.g. via ORBITRON Command Engine, Ansible, SCCM/Intune).

```bash
sudo bash php2shell-check.sh                 # human readable
sudo bash php2shell-check.sh -o report.json  # + JSON
sudo bash php2shell-check.sh --no-containers   # skip the (read-only) container / pod inspection
sudo bash php2shell-check.sh --container-exec  # additionally run 'php -r' via docker/podman exec for exact CLI values
```
```powershell
powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1 -OutFile report.json
```
Exit codes: `0` no PHP, `1` PHP found and all runtimes confirmed patched, `2` PHP found and at least
one runtime **not confirmed** patched.

Since v1.3.0 the fixed versions **8.2.35 8.3.36 8.4.27 8.5.12** are built in (override with
`PHP2SHELL_FIXED_UPSTREAM`). The Linux script does **not** apply upstream version comparison to
distribution packages that backport fixes (RHEL/Ubuntu keep old version numbers) — for those it relies on
the package changelog listing the CVE. Each runtime also gets an `Interim:` line (JSON
`interim_mitigations`) showing which of the four advisory settings are in effect, and the override list
now includes pool / vhost / per-directory `memory_limit` and `post_max_size` values, which can silently
undo a php.ini mitigation.

Checklist:
1. Inventory every PHP runtime **and the SAPI the web server actually uses** (CLI values ≠ FPM values).
2. Flag upstream-EOL branches (≤ 8.1) that are not covered by a distribution/ESM backport.
3. Record where your packages come from (distro, Remi, Sury, panel vendor) — that decides *when* you can patch.
4. Prioritise internet-facing hosts; prepare change windows for 21 Oct after 14:00 UTC.
5. Check that FPM pools / containers are **restarted** after updating (a running worker keeps the old binary).
   The settings above are read from the ini files on disk; the `Running:` line shows whether the running
   processes actually use them. `STALE` = reload needed, `RESTART REQUIRED` = processes still run a binary that
   was replaced by a package update.

## 5. Known workarounds — current status

PHP's advisory lists these interim mitigations. **They reduce exposure; they do not make an installation
safe.** Set them in php.ini, the FPM pool (`php_admin_value` / `php_admin_flag`) or the web-server config
— **not** with `ini_set()` or `.user.ini` — and **restart all PHP workers**.

```ini
memory_limit = -1                      ; FPM: php_admin_value[memory_limit] = -1 (apps cannot override)
post_max_size = 8M                     ; 32M if file uploads are required
session.upload_progress.enabled = 0
fatal_error_backtraces = 0             ; PHP 8.5 only
```

| Workaround | Status (21 Oct, after release) | Notes |
|---|---|---|
| `memory_limit = -1` | **Key interim mitigation** (php.net). In our lab the only setting that stopped the out-of-memory abort during parsing (§9) | **Creates a DoS risk**: a few-MB request can cost hundreds of MB to parse. Cap memory with a cgroup/container limit (systemd `MemoryMax=` on php-fpm/httpd, container memory limit, IIS app-pool private memory limit) and size `pm.max_children` accordingly. php.net: use cgroups, **not** `RLIMIT_AS` / `RLIMIT_DATA`. |
| `post_max_size = 8M` (32M with uploads) | Supporting (php.net) | 8M is the PHP default. **Alone it did not stop** the abort in our lab: a 3 MB body exhausted 128M. |
| `session.upload_progress.enabled = 0` | Supporting (php.net); removes one amplifier | **Alone it did not stop** the abort in our lab. `INI_PERDIR`: php.ini, FPM `php_admin_flag`, Apache `php_admin_flag`. |
| `fatal_error_backtraces = 0` | PHP 8.5 only (php.net) | Restart workers afterwards. |
| `session.use_strict_mode = 1` | **Not a mitigation** (our lab, §9) | Still good hygiene. |
| WAF / ModSecurity | **Hunting + body limits** | The recommended `SecRequestBodyNoFilesLimit 131072` + `SecRequestBodyLimitAction Reject` rejected PHP's regression-test body in our lab. Rules 9109622/23 log part-header floods and body errors. |
| Web-server allow-list: only existing, intended `.php` entry points reach PHP; `LimitRequestBody` / `client_max_body_size`; `GET`/`HEAD` only where no forms exist | **Effective, low cost** (§9a) | PHP-FPM parses bodies even for non-existent scripts. Apache: `<If "! -f %{REQUEST_FILENAME}">Require all denied</If>` in a `.php` `FilesMatch`; nginx: `try_files $uri =404;`. If PHP only serves a contact form, consider stopping PHP until the fixed package is installed. |
| Restrict exposure (VPN/IP allow-list, take admin panels offline, isolate EOL hosts) | Effective risk reduction | CERT-EU advises isolating internet-facing applications until fixed. |
| Least privilege for the PHP user, egress filtering, read-only web roots | Limits impact | Recommended by Flatt Security; also reduces webshell persistence. |
| Patch | **The fix** | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 upstream; distribution timing see §7. Restart workers. |

## 6. Detection & monitoring rules

Detailed detection & response field guide (log examples, SAPI differences, correlation): [docs/php2shell-detection-and-response-guide.md](docs/php2shell-detection-and-response-guide.md). The branded PDF edition's document-control version (v1.2) maps to this repo's guide; the repo Markdown may carry later refinements. Branded PDF editions: [EN](docs/ORBITRON_php2shell_EN_v1.2.pdf) · [TR](docs/ORBITRON_php2shell_TR_v1.2.pdf).

Since the fix is public, there are two kinds of rules here: **trigger-condition** rules (PHP ran out of
memory while parsing a request — the state the bug needs — and part-header floods at the WAF), and
**behavioural** rules for what an attacker does *after* code execution.
**All SIEM/EDR queries are UNTESTED on live platforms** (generated with pySigma from the Sigma sources);
YARA, ModSecurity and the scripts were tested in our lab. Baseline 1–2 h before alerting.

| Use case | Sigma (source) | Splunk | QRadar | CrowdStrike Falcon | SentinelOne | Wazuh | Other |
|---|---|---|---|---|---|---|---|
| Linux: PHP/web server spawns shell, interpreter, download/recon tool | `lnx_..._spawns_shell_or_lolbin.yml` | `.spl`, `.cim.spl` | `.aql`, `.payload.aql` | `.logscale` | `.dv`, `.pq` | 109610–109612 (auditd) | — |
| Linux: reverse-shell / recon command line from PHP | `lnx_..._suspicious_cmdline.yml` | ✓ | ✓ | ✓ | ✓ | 109613 | — |
| Windows: php-cgi/php/httpd/w3wp spawns shell/LOLBin | `win_..._spawns_shell_or_lolbin.yml` | ✓ | ✓ | ✓ | ✓ | 109620 (Sysmon) | — |
| Webshell / `.user.ini` / `.htaccess` written to web root | `lnx_/win_..._file_written_to_webroot.yml` | ✓ | ✓ | use Falcon built-in webshell detections | ✓ | 109615, 109616, 109621 | YARA |
| **PHP out of memory while parsing the request** (`Allowed memory size … in Unknown on line 0`) — trigger condition | `php2shell_php_oom_during_request_parsing.yml` | ✓ | payload | ✓ (needs log ingestion) | — | 109627, 109629 (burst) | — |
| **Out-of-memory during parsing followed by a worker crash within 2 min** | — | — | — | — | — | 109628 (level 14) | — |
| **PHP-FPM worker exited with code 70** (OOM during start-up — the clean exit, not a signal crash) | `php2shell_php_fpm_worker_exit_code70.yml` | ✓ | payload | ✓ (needs log ingestion) | — | 109630, 109631 (with OOM) | — |
| PHP worker crash (SIGSEGV/SIGABRT) — memory-corruption attempts | `php2shell_php_worker_crash.yml` | ✓ | payload | ✓ (needs log ingestion) | — | 109625, 109626 | — |
| Multipart part-header flood / request-body errors | — | — | — | — | — | — | ModSecurity 9109622, 9109623 |
| Upload-progress field in multipart requests | — | — | — | — | — | — | ModSecurity 9109618/19/21 (+ blocking 9109620) |
| Webshells, auto_prepend persistence, upload-progress session leftovers | — | — | — | — | — | — | YARA `rules/yara/` |

Data requirements: process creation with parent image (Sysmon for Linux/Windows, auditd `execve`,
EDR), file creation telemetry for the web-root rules, PHP-FPM/Apache error logs for the crash rule,
request-body inspection for ModSecurity. The out-of-memory rule needs PHP errors in a forwarded log
(`log_errors=On`; for FPM `catch_workers_output=yes` or a pool `error_log`). On patched hosts the message
can still appear (PHP now stops cleanly) — treat it as an attempt indicator, not as a compromise.
Platform notes:

* **Splunk** — `.spl` uses Sysmon field names (`Image`, `ParentImage`, `CommandLine`), `.cim.spl` uses the CIM Endpoint data model.
* **QRadar** — field-based `.aql` needs Sysmon/EDR custom properties (*Parent Process Path*, *Command*); Linux OS DSM (auditd) usually lacks parent process → use `.payload.aql` or the Wazuh/auditd approach.
* **CrowdStrike Falcon** — LogScale / NG-SIEM / Advanced Event Search syntax on `ProcessRollup2`; file-write rules not generated (pipeline limitation).
* **SentinelOne** — `.dv` (Deep Visibility) keeps `endswith`; the `.pq` backend approximates `endswith` with `contains` (broader).
* **Wazuh** — `rules/wazuh/0910-orbitron-php2shell_rules.xml` + `auditd-php2shell.rules` + `ossec-agent-snippet.xml`. Validate with `wazuh-logtest`.
* **YARA** — `yara -r rules/yara/php2shell_hunting.yar /var/www` and the PHP session directory.
* Rebuild platform queries: `python3 tools/build_rules.py` (see `rules/BUILD_REPORT.md`).

Expected false positives: PHP apps that legitimately `exec()` (image/PDF tools, backups, deploy hooks,
control panels), PHP `mail()` (`sh -c sendmail`, filtered), CMS self-updates writing `.php` files,
crashing third-party extensions.

## 7. Patch timeline and how updates reach each platform

| Source | How the fix arrives | What to expect / how to verify |
|---|---|---|
| **php.net (upstream)** | New point releases for 8.2–8.5 on 21 Oct 14:00 UTC (or earlier) | Version number is the indicator (fixed versions published with the advisory) |
| **Windows** (windows.php.net builds, XAMPP/WAMP/Laragon, IIS) | Replace PHP binaries with the new build; repackaged stacks follow later | `php -v`; restart IIS app pools / Apache |
| **Remi (RHEL family) / deb.sury.org & ondrej PPA (Debian/Ubuntu)** | Track upstream releases and usually publish new upstream versions quickly | Upstream version number applies; `dnf update` / `apt upgrade`, restart FPM |
| **RHEL 8/9/10 → Rocky / AlmaLinux / Oracle** | Red Hat **backports** the fix into the existing package (version number does *not* change); Rocky/Alma rebuild the RHSA (Rocky's RLSA notices are mirrored from RHSA) | Historically not same-day: e.g. the May 2026 PHP fixes reached RHEL as RHSA-2026:22143 (php:8.2, RHEL 9, dated 20 Jul) and Rocky 8 as RLSA-2026:34354 (2 Jul). Check `dnf updateinfo list --cve CVE-2026-109618` and `rpm -q --changelog php-common \| grep CVE-2026-10961` |
| **Debian** | Debian Security Team releases a DSA; for PHP it has recently shipped the new upstream point release (e.g. DSA-6255-1 → `8.2.31-1~deb12u1`, the day after upstream) | `apt list --upgradable 'php*'`; security-tracker.debian.org |
| **Ubuntu** | USN with **backported** patches (keeps e.g. `8.3.6-0ubuntu0.24.04.x`); older releases via Ubuntu Pro/ESM | Past PHP USNs arrived days to weeks after upstream (e.g. USN-8564-1, 20 Jul). Check ubuntu.com/security/CVE-… and the changelog |
| **Containers** (official `php:` images, custom images) | Images are rebuilt after upstream release | Rebuild **and redeploy**; pinned base images will not update themselves |
| **Hosting panels / CloudLinux / appliances** (cPanel EA-PHP, Plesk, alt-php, vendors) | Vendor-specific | Ask the vendor/hosting provider *today* to stand by |
| **Upstream EOL (≤ 8.1)** | No upstream fix | Upgrade, vendor/ESM backport, or isolate |

In every case: **restart PHP-FPM / Apache / IIS app pools** after updating and re-run the checker.

## 8. Recommended plan for today

1. Run the v1.3.0 scripts: list runtimes that are `NOT PATCHED` / `NOT CONFIRMED`, their `Interim:` line and package source.
2. Upstream-tracking hosts (php.net, Remi, Sury, official images, Windows): update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, **restart** FPM / Apache / IIS app pools, rebuild **and redeploy** images. Re-run the script (`Running: LOADED`).
3. Distribution packages (RHEL/Rocky/Alma, Ubuntu): until the vendor package lists the CVEs, apply the interim mitigations **with** a cgroup memory limit, and restrict exposure.
4. Enable the out-of-memory, code-70 and crash rules (Wazuh 109627–109631, Sigma), ModSecurity body limits + 9109622 in log mode, and the behavioural rules.
5. Hunt on hosts that were exposed: `in Unknown on line 0` out-of-memory errors and worker crashes since 20 Oct, webshells (YARA), new `.user.ini`/`.htaccess`, cron jobs and accounts.
6. Upstream-EOL branches (≤ 8.1): upgrade, vendor/ESM backport, or isolate.

## 9. Lab notes

### 9a. Patch analysis (21 Oct, after release) — official fix and regression tests only

Method: diff of `php-8.3.35..php-8.3.36` (fix commit `3c832b523e`, "Avoid state corruption via bailout",
same fix on all four branches); PHP's **own** new `.phpt` regression tests run against debug + ASan builds
of unpatched 8.3.35 and patched 8.3.36 (php-cgi). No exploit code was written or used.

* What the fix changes: an out-of-memory during request start-up no longer `longjmp`s out of half-built
  state; the request parser (`main/rfc1867.c`, `main/php_variables.c`, `main/SAPI.c`) checks a soft limit and
  stops cleanly; globals that could survive into the next request are reset (`$_GET/$_POST/...` slots,
  last error, module state); the multipart parser keeps only `Content-Disposition` / `Content-Type` part
  headers and ignores duplicates; the upload-progress handler no longer resolves classes or runs user code
  (`__wakeup`, autoload) before request start-up and no longer leaves `$_SESSION` behind in scripts that
  never call `session_start()`.
* Unpatched 8.3.35: 5 of 27 applicable new tests fail (two multipart part-header flood tests →
  out-of-memory during parsing; three upload-progress session tests). Patched 8.3.36: 27/27 pass.
* Interim mitigations against PHP's regression-test body (one field, 600,000 header lines, 3 MB), unpatched
  8.3.35 php-cgi: default settings → `Allowed memory size of 134217728 bytes exhausted … in Unknown on line 0`;
  `post_max_size=8M` → same; `session.upload_progress.enabled=0` → same; `memory_limit=-1` → request
  completes (≈218 MB peak in the debug build). Patched 8.3.36 with default settings: ≈2 MB peak.
* **PHP-FPM parses the request body even when the script does not exist.** Unpatched 8.3.35 php-fpm
  (unix socket, lab only): a multipart request with an upload-progress field to a missing `.php` wrote the
  session file and then answered `404 File not found`; PHP's regression-test body sent to a missing `.php`
  produced `Allowed memory size … in Unknown on line 0` and the worker exited. With Apache
  `SetHandler "proxy:unix:…|fcgi://…"` (RHEL/Rocky default `php.conf`) or nginx `fastcgi_pass` without
  `try_files`, **any `/random.php` URL reaches PHP**. Fix at the web server: deny `.php` that does not exist
  (Apache `<If "! -f %{REQUEST_FILENAME}">Require all denied</If>` inside `<FilesMatch "\.php$">`, nginx
  `try_files $uri =404;`) and allow-list the PHP entry points you really use.
* Limits of this test: debug + ASan builds (memory accounting differs from release builds); single-request
  CGI — the cross-request reuse (CVE-2026-109619) in persistent workers was not reproduced.

### 9b. Pre-disclosure: upload-progress mechanism (Ubuntu 24.04, PHP 8.3.6, mod_php and built-in server)

We tested the *mechanism* Flatt Security pointed to — not the vulnerability:
* A multipart request containing a field named `PHP_SESSION_UPLOAD_PROGRESS` made PHP create a session
  file **even though the target script never calls `session_start()`**, using the session ID chosen by
  the client (`session.use_strict_mode=Off`).
* With `session.use_strict_mode=On` PHP still wrote the progress data, under a random ID → strict mode
  does not stop the mechanism.
* With `session.upload_progress.enabled=0` no session file was created.
* With the default `session.upload_progress.cleanup=On` the session file remained as an empty file.
* A request to a non-existent `.php` path (404) did not trigger it **with mod_php and the built-in server**,
  where the web server checks the file first. **This does not hold for PHP-FPM behind a proxy handler** — see §9a.
* ModSecurity 2.9: log rules fired only for multipart requests carrying the field; normal uploads were
  not flagged; the blocking variant returned 403.
* ModSecurity 2.9.7 (v1.3.0): 9109622 fired for multipart requests with 1,000 part-header lines (file and
  non-file parts), not for a normal upload; PHP's 3 MB regression-test body was rejected (HTTP 400) by the
  recommended body-limit configuration before it reached PHP.

## 10. References

* PHP — security releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (21 Oct 2026): https://www.php.net/archive/2026.php#2026-10-21-1
* PHP source — fix commit "Avoid state corruption via bailout" (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp): https://github.com/php/php-src/commit/3c832b523ee13b1a010177d2ff84aea18be0015e
* PHP — Upcoming Critical PHP Security Release (20 Oct 2026): https://www.php.net/archive/2026.php#2026-10-20-1
* GMO Flatt Security — php2shell overview and guidance (JA, updated 21 Oct): https://blog.flatt.tech/entry/php2shell
* Sansec — Critical PHP RCE: https://sansec.io/research/php2shell
* Huntress — Rapid Response: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
* The Hacker News: https://thehackernews.com/2026/10/php2shell-two-unpatched-critical-php.html
* Phoenix Security: https://phoenix.security/php-core-rce-cve-2026-109618-109619-critical-remote-code-execution/
* PHP manual — Session Upload Progress: https://www.php.net/manual/en/session.upload-progress.php
* Red Hat RHSA-2026:22143 · Rocky RLSA-2026:34354 · Debian DSA-6255-1 · Ubuntu USN-8564-1 (patch-latency data points)

## 11. Running it from ORBITRON

ORBITRON customers can run the same investigation as a ready-made command playbook,
*PHP exposure and behavior investigation*: read-only PHP / web-worker inventory and bounded
evidence collection across the fleet.

![ORBITRON playbook: PHP exposure and behavior investigation](docs/images/orbitron-php2shell-investigation-playbook.png)

The playbook branches on the host OS. Linux hosts and container hosts collect PHP inventory,
workers, files, connections and Docker; Windows web hosts collect PHP/IIS inventory, workers,
files and connections. Each branch returns its evidence and a coverage report, and unsupported
operating systems are reported as such, so gaps stay visible.

The scripts in `scripts/` are standalone and do not require ORBITRON.

## Disclaimer & license

Provided as-is for defensive use, without warranty. Validate scripts and rules in your environment
before production use. No exploit code is or will be published here. Scripts and rules: MIT License
(see [LICENSE](LICENSE)). © 2026 ORBITRON.
