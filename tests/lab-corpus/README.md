# Lab corpus

Labelled evidence from the Brandefense PHP2Shell lab (official php:*-apache and php:*-fpm images with nginx in front of FPM, started with `--network none`, arm64). It is **metadata only**: no request body and no exploit payload is stored.

| File | Content |
|---|---|
| `cases.jsonl` | one row per lab run (PHP version, SAPI, control, scenario, label, outcome) |
| `requests.jsonl` | one row per HTTP request: method, path, content type, body size, part and part-header counts, field names, status |
| `logs.jsonl` | PHP error log, FPM master log, FPM worker output (stderr), Apache and nginx error and access lines |
| `pcap-manifest.json` | names and hashes of the loopback captures. The pcaps themselves stay in the lab folder (they contain the synthetic attack bodies) |
| `*-results.json` | what each rule or engine did on the corpus (Sigma replay, Suricata, Zeek, ModSecurity, YARA) |

Labels: `attack-oom` (unpatched build, request-startup memory exhaustion), `attack-leak` (unpatched build, another session's data visible in `$_SESSION` of the upload-progress request), `patched-graceful` (fixed build, same requests: a clean memory error or no memory error at all, never a leak), `benign` (8 runs of ordinary requests and health checks, plus 34 runs of a script-level out-of-memory error in a shutdown function; see docs/lab-validation.md).

Rebuild: `python3 -I build_corpus.py <lab-dir>` (needs the lab folder, not shipped). Replay the Sigma rules: `replay.py`. Tests: `../test_lab_corpus.py`.
