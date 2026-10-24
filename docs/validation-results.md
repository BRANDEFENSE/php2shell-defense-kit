# Release validation results

**v0.3.0 · 24 October 2026 · macOS arm64 / Python venv**

**195 tests passed; 0 failures; 0 errors; 0 skipped** (`python3 -I -m pytest`).

The suite validated 21 Sigma rules, 62 event fixtures plus 16 missing-field checks, 21 Splunk selection-query conversions, a replay of the lab corpus through every runnable rule, 5 YARA rules with 13 inert samples, and collector/analysis regression cases. All included fixtures are synthetic; no PHP payload was executed and no external test target was contacted. The Linux collector ran only in this container, not a customer estate.

| Test dependency | Version |
|---|---|
| PyYAML | 6.0.3 |
| yara-python | 4.5.4 |
| pySigma | 1.5.1 |
| pySigma-backend-splunk | 2.1.0 |
| pytest | 9.1.1 |

## Lab results (Brandefense lab, 24 October 2026)

Full tables, method and limits: [lab-validation.md](lab-validation.md). Evidence corpus: `tests/lab-corpus/` (277 cases, 908 requests, 2,968 log lines, metadata only). Short result: 15 of 35 Sigma rules could be run on real lab records; 13 caught at least one memory-exhaustion case, 3 caught the data leak, none caught every case; after tuning, only the third-party `worker_crash_or_oom` still fires on benign script-level memory errors. 9 of 14 third-party and 11 of 21 own rules are **not tested** (no process, file, cookie or user-agent telemetry; no code execution reproduced). Suricata, Zeek, ModSecurity and YARA ran offline; the SPL, Defender, osquery, Wazuh, CrowdSec, Elastic and QRadar content was not run. `tools/php2shell-check.sh` was tested in lab containers; the `.ps1` is untested.

## Noise check on a real WordPress tree (Brandefense, 24 Oct 2026)

All 5 YARA rules were run with `tools/scan_yara.py` over a copy of our local WordPress (wp-admin, wp-includes, wp-content; 89,312 files scanned, 108 coverage gaps reported by the tool): **0 hits**. The first version of the file-write rule, before narrowing, hit 15 benign files (core, caching and image plugins) on the same tree. This is one site, not a false-positive rate.

## Executed

- pySigma parsing and parsed-condition fixture evaluation.
- pySigma Splunk backend conversion; query text was generated but not executed in Splunk.
- Real YARA compilation with warnings treated as errors and synthetic matching.
- Version/backport/prerelease classification, config quoting, symlink gaps and deleted mapped-module handling.
- Private report modes and secret-value exclusion in supplied synthetic source/log/SBOM cases.
- Linux inventory, offline audit/log/YARA/SBOM CLI smoke tests.
- A local loopback HEAD request proving redirect suppression and cookie-value nonretention.
- osquery query syntax against synthetic SQLite table definitions only.

## Not executed / no claim

- Remote code execution, and any exploit-prevention claim. (The lab reproduced the memory-exhaustion and stale-session behaviour on unpatched builds with our own synthetic requests; see the lab section.)
- Production traffic evaluation or a production false-positive/false-negative rate (the lab counts are small and synthetic).
- Native Windows/PowerShell, osquery, Microsoft Defender or Splunk execution.
- Docker/Kubernetes runtime collection or nginx configuration validation.

Those components remain documented examples pending local platform validation. This kit does not claim a clean environment, a new vulnerability or a production protection guarantee.
