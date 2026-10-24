# Changelog

## 0.3.0 (24 Oct 2026)
- security: no execution of discovered binaries. `tools/php2shell-check.sh` and `.ps1` read the PHP version from the file (banner string / version resource) instead of running `<binary> -v` on paths taken from `/proc`, process lists or the disk; the `<binary> -i` ini probe is removed; a php-fpm-named process with a non-root binary is not trusted. Re-tested in lab containers (fake process not executed).
- fix: pre-release builds (dev, alpha, beta, RC) are never "fixed" (WARN/unknown); only a final release at or above the fixed one passes. New tests in `tests/test_php2shell_check.py`.
- Note: the bundled Wazuh SCA post_max_size check is regex-based and can miss values in plain bytes or K units (noted in `third_party/catalog.json` and `docs/community-resources.md`; file unchanged).
- Added `tools/php2shell-check.sh` (lab-tested) and `tools/php2shell-check.ps1` (untested); doc `docs/php2shell-check.md`.
- Added the labelled lab corpus `tests/lab-corpus/` (277 cases, 908 request records, 2,968 log lines; metadata only) and replay tests `tests/test_lab_corpus.py`.
- Six new experimental Sigma rules: `php_startup_oom_fatal`, `php_fpm_child_exit_70_storm` (5 exits in 5 minutes per pool), `nginx_body_too_large`, `http_post_rejected_413`, `http_upload_progress_with_body_session_id`, `http_multipart_flood`; 21 Sigma rules and 21 SPL files in total, with false-positive notes in each rule.
- Every runnable rule replayed on the corpus; Suricata, Zeek, ModSecurity and YARA run offline. Results in `docs/lab-validation.md`; "not tested" where the lab had no telemetry.
- Noise tuning from the lab: `php_memory_exhaustion` narrowed to the request-startup signature (benign hits 24 of 42 to 0; status deprecated, same matches as `php_startup_oom_fatal`); `http_upload_progress_field` demoted to level informational (hunting only; 4 benign hits remain, documented). Third-party noisy rules flagged in `third_party/catalog.json` (`notes`) and `docs/lab-validation.md`; the files are unchanged.
- `docs/lab-validation.md`: explains the 46 of 120 attack-oom runs without a hit (no memory error occurred, not a rule gap) and the logging settings needed; notes a gap for worker kills and segfaults that appear only in FPM and Apache logs.
- Tests: new corpus tests for the narrowed rule and the 46 runs; fixture for `php_memory_exhaustion` updated.
- `docs/validation-results.md` and README "What actually works" updated; lab placeholder removed.

## 0.2.0 addendum (24 Oct 2026)
- Added `third_party/`: unchanged copies of nine permissively licensed community projects (Zeek/Suricata, Sigma, YARA, SPL/KQL/ES|QL/AQL, Wazuh, CrowdSec, ModSecurity, one data file) with LICENSE, SOURCE.md and `catalog.json`.
- Added `docs/community-resources.md`; NOTICE and README updated. Own rules and tools unchanged.

## 0.2.0 (merged kit)
- Review fixes applied. 15 Sigma rules (diagnostic rule dropped), narrowed YARA file-write rule, tools run under `python3 -I`, lab-results placeholder.

## 0.1.0 — 2026-10-24

- Initial English article and defensive operations package.
- 15 experimental Sigma rules, 5 YARA heuristics, compiled SPL and example MDE/osquery hunts.
- Read-only inventory, static/source review, HTTP header evidence, offline log and YARA triage tools.
- Synthetic detection tests and inventory regression tests; validation scope explicitly documented.
- Separate treatment of the October 23 related advisory and its configuration preconditions.
