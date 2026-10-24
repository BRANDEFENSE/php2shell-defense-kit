# Lab validation: which rules caught what

**v0.3.0, 24 October 2026.** This page answers a plain question: does the kit really work? It is the answer for the part we could test. Short version: the rules that look at the PHP error log and at the shape of the HTTP request catch the memory-exhaustion attack in the lab, but only some of the time. The one rule family that spots the data leak is the upload-progress field. Most of the rules for what happens after a break-in could not be tested, because the lab never produced a break-in.

## What was tested

A lab of official `php:*-apache` and `php:*-fpm` containers (nginx in front of FPM), started with `--network none`, with a loopback packet capture inside. Builds: 8.3.35, 8.4.26 and 8.5.11 (unpatched) and 8.3.36, 8.4.27 and 8.5.12 (patched). The lab sent only our own synthetic requests (no third-party exploit, no external target). Every run was turned into labelled records, the **corpus** in `tests/lab-corpus/`:

| Label | Meaning | Cases | Requests | Log lines |
|---|---|---|---|---|
| attack-oom | unpatched build, request-startup memory exhaustion | 120 | 264 | 1,156 |
| attack-leak | unpatched build, another session's data visible in `$_SESSION` of the upload-progress request | 31 | 31 | 17 |
| patched-graceful | fixed build, same requests: either a clean memory error or no memory error at all (the header-flood bodies), never a leak | 84 | 168 | 472 |
| benign | 8 runs of ordinary requests and health checks, plus 34 runs of a script-level out-of-memory error inside a shutdown function (php-src test `oom_shutdown_function_next_request`: a real memory error, but not request-startup, so labelled not-attack) | 42 | 445 | 1,323 |
| **Total** | | **277** | **908** | **2,968** |

Requests are stored as metadata only (method, path, content type, body size, part and part-header counts, field names, status). No payload is stored. The pcaps stay in the lab folder.

## Method

- **Sigma:** each rule is parsed with pySigma and its condition is evaluated against the real records of the matching log type (PHP error log, FPM master log, nginx error log, request records). Correlation rules (the exit-code-70 storm) use a 5-minute window. A rule is **not tested** when the field it needs does not exist in lab telemetry. This tests rule logic on real lab records, not a SIEM field mapping.
- **Suricata 7.0.8, Zeek (Corelight package), ModSecurity v3.0.17 (DetectionOnly, CRS image):** run offline on the lab captures or on the same request sequence. Where the rules assume ports 80/443 and 8080 was used, only the port variable was changed.
- **YARA:** both PHP rule files scanned the 8 benign PHP files of the lab.
- Counts below are **cases** (one lab run each), "hit" meaning at least one alert in that run.

## Our own Sigma rules (21)

| Rule | attack-oom | attack-leak | benign | patched | Note |
|---|---|---|---|---|---|
| php_startup_oom_fatal (new) | 74/120 | 0/31 | 0/42 | 34/84 | Startup fatal "in Unknown on line 0". No benign hit |
| php_memory_exhaustion (narrowed, deprecated) | 74/120 | 0/31 | 0/42 (was **24/42**) | 34/84 | Was noisy: fired on script-level memory errors (all 24 hits come from the 34 shutdown-function runs). Now needs "in Unknown on line 0", so it matches the same lines as php_startup_oom_fatal. Kept only for rule-id stability |
| php_fpm_child_exit_70_storm (new) | 7/120 | 0/31 | 0/42 | 6/84 | Needs 5 exits in 5 minutes per pool. Lab bursts are short, so it rarely reaches the threshold |
| nginx_body_too_large (new) | 4/120 | 0/31 | 0/42 | 0/84 | Only fires where nginx rejects the body |
| http_post_rejected_413 (new) | 8/120 | 0/31 | 0/42 | 0/84 | All 8 front-end rejections, Apache and nginx, seen from the response side (`nginx_body_too_large` sees only the 4 behind nginx) |
| http_upload_progress_field (hunting only, level informational) | 24/120 | 31/31 | 4/42 | 28/84 | Catches every leak case. The 4 benign hits are legitimate upload-progress forms and cannot be told apart by field name alone, so the rule was demoted to informational: use it to find sites that use the feature, not to alert. Alert with the next rule |
| http_upload_progress_with_body_session_id (new) | 24/120 | 31/31 | 0/42 | 28/84 | Catches every leak case and none of the benign ones |
| http_multipart_flood (new) | 72/120 | 0/31 | 0/42 | 42/84 | Many parts or part headers. Misses the leak, which is a small request |
| linux_php_worker_crash | 0/120 | 0/31 | 0/42 | 0/84 | Needs syslog crash lines; containers do not produce them. Effectively not tested |
| php_execution_timeout | 0/120 | 0/31 | 0/42 | 0/84 | Nothing in the lab timed out |
| http_large_session_cookie | not tested | | | | No response-cookie telemetry in the lab |
| 10 process and file rules (linux_web_*, linux_webroot_php_write, windows_*) | not tested | | | | Need process or file events; no remote code execution was reproduced |

Patched builds receive the same attack requests (answered normally or stopped with a clean error), so request-shape rules fire there too. That is expected: these rules say "someone sent this request", not "the host is vulnerable".

## Third-party Sigma rules (14, unchanged copies)

The files are byte-for-byte upstream copies; we did not tune them. Rules marked noisy are also flagged in `third_party/catalog.json` (field `notes`).

| Rule | attack-oom | attack-leak | benign | patched |
|---|---|---|---|---|
| php2shell_oversized_phpsessid | not tested (needs cookie field) | | | |
| php2shell_php_oom_during_request_parsing | 74/120 | 0/31 | 0/42 | 34/84 |
| php2shell_worker_crash_or_oom **(noisy in our lab, tune before alerting)** | 76/120 | 0/31 | **24/42** | 34/84 |
| php2shell_upload_progress_marker **(noisy in our lab, tune before alerting)** | 24/120 | 31/31 | 4/42 | 28/84 |
| php2shell_php_fpm_worker_exit_code70 | 38/120 | 0/31 | 0/42 | 17/84 |
| php2shell_php_worker_crash | 2/120 | 0/31 | 0/42 | 0/84 |
| php2shell_poc_user_agent | not tested (the lab ran no PoC tool) | | | |
| 7 process and file rules (3 Linux, 2 Windows, worker child process, reverse shell) | not tested | | | |

## Why 46 of 120 attack-oom runs have no hit

Short answer: in 42 of the 46 runs there was nothing to log; in the other 4 the worker crashed or was killed before PHP could write a fatal, a gap in our log rules (below). In the 42, PHP never ran out of memory, so there was no fatal line. In the 4 (the 600,000-header body under `RLIMIT_AS` or the 96M container limit) the worker segfaulted after `mmap()` failed, was killed by the kernel (FPM) or disappeared and was replaced (Apache, container limit); no log rule of ours caught the crash or kill (the request rule `http_multipart_flood` did flag the request). The case table records the outcome of each run: 74 logged the startup fatal (72 caught by `php_startup_oom_fatal` in the plain runs plus 2 more where the front end also answered 413), 46 had `no-memory-error`.

| Why no memory error | Runs | Explanation |
|---|---|---|
| `memory_limit=-1` | 10 | The control removed the trigger, as the advisory says |
| Container memory limit 96M with `memory_limit=-1` | 10 | 8 runs: no memory error. 2 runs (600,000-header body): no PHP memory error; on FPM the kernel killed the worker ("exited on signal 9 (SIGKILL)"), on Apache the worker disappeared and was replaced with no log line |
| `RLIMIT_AS` 300M with `memory_limit=-1` | 10 | 8 runs: no memory error. 2 runs (600,000-header body): no PHP memory fatal; PHP's allocator printed `mmap() failed` (Apache error log and FPM worker output), then Apache logs a segfault and FPM logs "exited on signal 11 (SIGSEGV)" |
| Default `memory_limit=128M` with the four small payloads | 8 | Those payloads were built for an 8M limit (the lab's low-memory profile); at the 128M default they do not exhaust memory. Only the 600,000 part-header body does |
| Front-end body limit 1M | 6 | nginx or Apache answered 413 before PHP saw the body |
| `session.upload_progress.enabled=0` | 2 | This control removed the 4,000-part upload-progress trigger. The other four triggers still ran out of memory with it off |

Logging worked in this lab: the same setup wrote the fatal line in the other 74 runs, and the 46 runs contain only 19 PHP error lines, all unrelated warnings from the next-request probe. For production the rule can only see what PHP writes, so `log_errors` must be on and the `error_log` must be a file your collector reads. On FPM, worker output reaches the log only if the pool sends it there (`catch_workers_output = yes`); that advice is general PHP practice and was not tested here, and we did not run with logging turned off.

Small gap found while checking: the FPM kill and both segfaults appear in the FPM master and Apache error logs; the Apache worker lost under the container limit left no log line at all (connection reset, worker replaced). `linux_php_worker_crash` is written for kernel syslog crash lines; replayed on these FPM and Apache lines it does not match them (0 hits). Our own rules do not cover these lines in this version. Two bundled third-party rules do: `php2shell_php_worker_crash` matches both segfaults and `php2shell_worker_crash_or_oom` matches both FPM exits. Only the Apache worker lost under the container limit is seen by no log rule. The advisory warns against `RLIMIT_AS`; a container limit is a blast-radius control, not a mitigation.

## Other engines (offline)

| Engine and rule | attack-oom | attack-leak | benign | patched |
|---|---|---|---|---|
| Suricata 20260001 upload progress with body session id (break-the-build, bundled) | 2/22 | 2/2 | 0/96 | 4/24 |
| Suricata 20260004 upload progress, large body (break-the-build, bundled) | 1/22 | 0/2 | 0/96 | 0/24 |
| Suricata 20260006 part-header inflation (break-the-build, bundled) | 2/22 | 0/2 | 0/96 | 2/24 |
| Suricata 3000650 (Corelight, bundled) **(noisy in our lab, tune before alerting)** | 2/22 | 2/2 | **4/96** | 4/24 |
| Suricata 3000651 (Corelight, bundled) | 4/22 | 0/2 | 0/96 | 0/24 |
| ModSecurity 9109623 (bundled) | 11/11 | 0/1 | 0/24 | not separable |
| ModSecurity 9109618 (bundled) **(noisy in our lab, tune before alerting)** | 1/11 | 1/1 | **1/24** | not separable |
| ModSecurity 20260001 (break-the-build, bundled) | 1/11 | 1/1 | 0/24 | not separable |
| ModSecurity 20260008 (break-the-build, bundled) **(noisy in our lab, tune before alerting)** | 0/11 | 0/1 | **1/24** | not separable |
| ModSecurity 9109621, 9109622 (bundled) | 1/11, 2/11 | 0/1 | 0/24 | not separable |
| ModSecurity 20260004, 20260006, 20260007, 9109619 | 0/11 | 0/1 | 0/24 | not separable |
| Zeek: Potentially_Affected_PHP_Version | fires on every unpatched capture, none on patched | | | |
| Zeek: Multipart_Header_Flood, Large_Form_Key, PHP_Crash_Sequence, Serialized_Integer_Overflow | 0 notices | | | |
| YARA (our php_triage and ORBITRON hunting rules) | 0 hits on 8 benign files | | | |

Suricata counts are captures (22 attack-oom, 2 leak, 96 benign, 24 patched), not lab cases. A web application firewall cannot see the PHP version, so for most of these rules the patched column mirrors the attack column (Suricata 3000651 and 20260004 are exceptions: they hit fewer or no patched captures). The Suricata rule 20260006 sees only the 150,000-part-header body, not the 600,000-header body, and the Zeek body notices did not fire at all: both are recorded as misses.

## Bottom line

- Honest limit on the benign numbers: only 8 of the 42 benign runs are ordinary traffic; the other 34 are the shutdown-function memory error. "0 of 42" for the startup rule therefore shows it does not fire on script-level memory errors, not that it is quiet on a busy production log. Narrowing `php_memory_exhaustion` also gives up detection of script-level memory errors, which the advisory says may still be reachable on FPM after normal startup.

- 15 Sigma rules could be run (10 ours, 5 third-party). 13 caught at least one attack-oom case; 3 caught the leak (the upload-progress field rules); the other attack signals are mostly "after the fact" log lines.
- The best single signal is the startup OOM fatal in the PHP error log (74 of 120 runs, zero benign hits). In 42 of the other 46 runs no memory error happened; in 4 the worker crashed or was killed (see "Why 46 of 120 attack-oom runs have no hit" above). Every run that did log the fatal was caught.
- Noise, before and after tuning: `php_memory_exhaustion` went from 24 of 42 benign cases to 0 (narrowed to the startup signature, same attack hits). `http_upload_progress_field` still hits 4 of 42 benign cases (legitimate upload-progress forms), so it is now informational and hunting only. The third-party `worker_crash_or_oom` (24 of 42), `upload_progress_marker` (4 of 42), Corelight 3000650, ModSecurity 9109618 and 20260008 are noisy in our lab: tune before alerting.
- The leak (another session's data in `$_SESSION`) is silent in the logs. Only the request-side upload-progress rules saw it.

## Not tested

All process and file rules (no code execution reproduced), response-cookie rules, user-agent rules, the Windows script, crash rules that need syslog, Splunk/Defender/osquery/Wazuh/CrowdSec/Elastic/QRadar rules (no engine in the lab; the SPL is generated from Sigma and not executed), nginx 413 under real proxy chains, the 8.1 and older branches.

## Limits

- Lab host is arm64 (Apple silicon) with official release builds. x86-64, distribution packages and debug builds may behave differently.
- No remote code execution was reproduced, so no post-exploitation rule was exercised.
- Counts are lab runs with short, synthetic traffic. They are not production false-positive rates; a real site will see more benign variety and far more volume.
- Patched builds were tested with the same requests; "graceful" means a clean error or no error, and no leak, in the lab; not a guarantee.
- Pcaps and request bodies are not shipped. The corpus is metadata and log lines only.
