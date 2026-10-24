# PHP2Shell Defense Kit

**Brandefense Research Team · v0.3.0 · advisory baseline: 24 October 2026**

A defensive, reviewable toolkit for finding PHP, checking remediation evidence, hunting suspicious activity, and testing detection logic for **PHP2Shell** (CVE-2026-109618 and CVE-2026-109619). Companion article: [How to Defend Against PHP2Shell](https://brandefense.io/blog/how-to-defend-against-php2shell/).

## In short

- **What it is:** read-only inventory and evidence tools, experimental Sigma, YARA, Splunk, Defender and osquery content, a fixed-version checker, and unchanged copies of nine community projects. No exploit code, no automatic blocking or remediation.
- **Proven in our lab:** against unpatched and patched PHP 8.3, 8.4 and 8.5 builds, the PHP startup out-of-memory fatal rule (`php_startup_oom_fatal`) caught 74 of 120 memory-exhaustion attack runs with no benign hit (in 42 of the other 46 nothing ran out of memory, in 4 the worker died without a PHP fatal). The data-leak case is silent in logs; only the upload-progress request rules saw it (31 of 31).
- **Not proven:** every process, file, cookie and user-agent rule, the Windows script and the SIEM queries could not be tested (the lab produced no code execution and none of that telemetry). Nothing here is a production false-positive rate or a prevention claim. Details: [docs/lab-validation.md](docs/lab-validation.md).

## Quick start

```bash
git clone https://github.com/BRANDEFENSE/php2shell-defense-kit.git
cd php2shell-defense-kit
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-test.txt
python -m pytest -q                      # all tests pass
python3 -I tools/inventory_linux.py --output reports/inventory.json   # read-only local PHP inventory
```

Then follow the [four steps below](#start-in-four-steps). Run the tools only on systems you administer.

This release contains **21 experimental Sigma rules, 5 original YARA heuristics, 21 compiled Splunk selection queries, 3 Microsoft Defender Advanced Hunting queries, 3 osquery inventory queries, 9 operator-facing tools (including the `php2shell-check` fixed-version checker), a labelled lab corpus, and a Python support module**. The tools cover Linux inventory, Windows inventory, static configuration review, source review, explicit HTTP header checks, offline log triage, offline SBOM inspection and offline YARA scanning. There is also a developer-only SPL compiler.

## What this kit establishes

- Inventory tools produce evidence and coverage gaps, not a universal vulnerability verdict.
- Package versions and headers are leads. Vendor backports and the running web runtime require separate proof.
- Sigma rules distinguish PHP-related runtime/HTTP signals from generic post-exploitation behavior.
- YARA rules classify suspicious PHP text or research artifacts. They do **not** detect the PHP engine vulnerability, prove compromise, or identify a PHP2Shell-specific malware family.
- Every rule is experimental. Lab and synthetic testing does not establish production false-positive rates or exploit coverage.
- No exploit, destructive request, credential collection, automatic remediation, automatic blocking or content deletion is included.

## What actually works (lab result, 24 October 2026)

We replayed every rule we could run against real records from a lab of unpatched and patched PHP builds (277 cases, 908 requests, 2,968 log lines). Plain version, details in [docs/lab-validation.md](docs/lab-validation.md):

- **Memory-exhaustion attack:** the best signal is the PHP startup fatal in the error log (`php_startup_oom_fatal`): 74 of 120 attack runs, no benign hit. In 42 of the other 46 runs nothing ran out of memory (a control removed the trigger, the front end rejected the body, or the payload was too small for the memory limit); in 4 the worker segfaulted, was killed or died and was replaced, with no PHP fatal written, no log rule of ours catches those (the request rule `http_multipart_flood` did flag the request). PHP must log errors to a file you collect.
- **Data leak (stale session):** silent in the logs. Only the upload-progress request rules saw it (31 of 31; 6 of those 31 requests were already stopped by a control, the rule sees the request, not whether the leak worked), and one of them (`http_upload_progress_with_body_session_id`) had no benign hit.
- **Noise, tuned:** `php_memory_exhaustion` went from 24 of 42 benign cases to 0 (narrowed to the startup signature). `http_upload_progress_field` still hits 4 of 42 benign cases (legitimate upload-progress forms), so it is informational and hunting only; alert with `http_upload_progress_with_body_session_id`. Third-party rules that are noisy in our lab (worker-crash-or-oom, upload-progress marker, Corelight 3000650, ModSecurity 9109618 and 20260008) are unchanged and flagged: tune before alerting.
- **Not tested:** all process, file, cookie and user-agent rules (the lab produced none of that telemetry; no code execution was reproduced), the Windows script, and the SIEM queries. They are marked "not tested", not "works".
- **Engines:** Suricata, Zeek, ModSecurity and YARA were run offline. They caught some attack shapes and missed others; three rules also hit benign traffic (Corelight 3000650, ModSecurity 9109618 and break-the-build's ModSecurity 20260008, each on 1 to 4 of the benign captures). YARA ran only on 8 benign PHP files and says nothing about attack shapes.
- **Benign baseline is thin:** only 8 of the 42 benign runs are ordinary traffic; the other 34 are a script-level memory error. Narrowing `php_memory_exhaustion` gives up detection of script-level memory errors.
- **Limits:** one arm64 lab, release builds, synthetic traffic. These are not production false-positive rates.
- `tools/php2shell-check.sh` (is the PHP that serves HTTP really fixed?) was tested in lab containers; `tools/php2shell-check.ps1` is **untested**. See [docs/php2shell-check.md](docs/php2shell-check.md).

## Start in four steps

1. Read [the current threat baseline](docs/advisory-baseline.md) and confirm the upstream/vendor advisories have not changed.
2. Collect [local inventory](docs/inventory.md), then complete the [remediation evidence checklist](docs/remediation.md).
3. Map your telemetry using [the field contract](docs/telemetry.md), deploy selected rules in detect mode and tune them.
4. Follow [the incident playbook](docs/incident-response.md) for suspicious findings. Use [the validation plan](docs/validation.md) to distinguish rule tests from actual prevention tests.

## Local collection examples

Python inventory and review tools require Python 3.10+ and otherwise use the standard library, except the YARA scanner. Outputs should stay in a private directory. Do not commit operational reports.

```bash
umask 077
mkdir -p reports
python3 -I tools/inventory_linux.py --output reports/inventory.json
python3 tools/audit_inventory.py reports/inventory.json --output reports/review.json
python3 tools/source_audit.py /srv/application --output reports/source-review.json
python3 tools/triage_logs.py /var/log/php/error.log --output reports/log-leads.json
```

Run on a system you administer. Elevated read privileges improve visibility but are not required. The default collector reads local `/proc`, package metadata and selected configuration directories; it changes no system settings. It does write the output report. Missing privileges remain coverage gaps.

Optional local container/orchestrator metadata collection:

```bash
python3 tools/inventory_linux.py --docker --kubernetes \
  --repo-root /srv/source --output reports/extended-inventory.json
```

`--docker` uses local Docker metadata only; access to the Docker socket is highly privileged. `--kubernetes` uses the current kubeconfig context and reads pod metadata across namespaces. Neither option executes in containers or reads secrets, ConfigMaps, environment values or full inspect documents. Container images without a `php` label may still embed PHP.

Optional, explicit normal HTTP HEAD requests:

```bash
python3 tools/http_inventory.py --urls authorized-urls.txt --output reports/headers.json
```

No discovery, port scan, path brute forcing or exploit requests are sent. Redirects are not followed. An absent PHP header is an unknown result.

Windows:

```powershell
.\tools\inventory_windows.ps1 -Output .\inventory-windows.json -ConfigRoot C:\PHP,C:\inetpub
```

The PowerShell collector is provided for review and local validation. **It was not executed on Windows in this release.** Protect the output with an appropriate NTFS ACL. Its schema is distinct from the Linux report; do not pass it to `audit_inventory.py`.

## Detection installation and tests

Use an isolated virtual environment for test tooling:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-test.txt
python3 -I -m pytest -q
python tools/build_splunk.py
python tools/scan_yara.py /srv/copied-webroot --output reports/yara-review.json
```

Treat samples under `tests/fixtures/` as inert text. Never copy them into a served directory or execute them. The tests pass text directly to YARA; they do not execute PHP.

See [rule coverage and tuning](docs/detection-guide.md), [test results](docs/validation-results.md), [lab validation](docs/lab-validation.md), [KQL hunts](queries/mde/README.md) and [osquery scope](queries/osquery/README.md). Compiled SPL contains selection logic only: add the correct index/sourcetype scope and field mappings before use.

## Community resources

Besides our own rules, `third_party/` carries detection content from nine public community projects, copied unchanged with their licences: Zeek and Suricata (Corelight), a multi-SIEM rule set (ORBITRON), Sigma (Senturkselim), Suricata and ModSecurity signals (break-the-build), Sentinel, Elastic and Splunk queries (Aplite), Defender exposure hunts (deathbydata), Wazuh rules, a CrowdSec AppSec rule and a fixed-version data file. Only rules, queries, configs and data are bundled; third-party programs are listed, not shipped. Exploit code and scanners that send attack requests were excluded entirely.

Read [docs/community-resources.md](docs/community-resources.md) for the full table (author, licence, what it is, bundled or not, our note). Third-party files were checked for syntax (Sigma parses, YARA compiles), and the third-party Sigma rules the lab telemetry allowed (5 of 14) and the Suricata, Zeek and ModSecurity files were also run offline in our lab (see docs/lab-validation.md); none has been run in production by us. Run them in alert mode first. Our `rules/` folder and the tools do not depend on `third_party/`.

## Repository map

| Path | Purpose |
|---|---|
| `rules/sigma/` | Experimental event detection rules |
| `rules/yara/` | Offline text triage heuristics |
| `rules/catalog.json` | Rule IDs, scopes and required fields |
| `queries/` | Splunk, MDE and osquery material |
| `tools/` | Read-only evidence collection and offline analysis |
| `docs/` | Baseline, operations, telemetry, tuning, tests and sources |
| `templates/` | Patch tracker, evidence record and lab result template |
| `tests/` | Synthetic event/file fixtures, regression tests, and `tests/lab-corpus/` (labelled lab evidence, metadata only, with replay tests) |
| `third_party/` | Unchanged copies of permissively licensed community rules, queries and data, each with LICENSE and SOURCE.md; index in `third_party/catalog.json` |

## Credits

`third_party/` bundles unchanged copies of nine public community projects (detection content only; each folder keeps its upstream LICENSE and a SOURCE.md with URL, commit and fetch date). They are written by their authors, not by Brandefense, and their own licences apply. Thank you to all of them.

| Project | Licence | What we bundle |
|---|---|---|
| [corelight/php2shell-detect](https://github.com/corelight/php2shell-detect) | BSD-3-Clause | Zeek scripts and a Suricata rule file |
| [orbitron-ai/php2shell-response-kit](https://github.com/orbitron-ai/php2shell-response-kit) | MIT | Multi-SIEM rules (Sigma, Splunk, QRadar, CrowdStrike, SentinelOne, Wazuh), YARA and ModSecurity |
| [Senturkselim/Am-I-Infected](https://github.com/Senturkselim/Am-I-Infected) | MIT | Sigma rules |
| [break-the-build/php-multipart-waf-signals](https://github.com/break-the-build/php-multipart-waf-signals) | MIT | Suricata and ModSecurity signals |
| [aplite-de/php2shell-detection-rules](https://github.com/aplite-de/php2shell-detection-rules) | MIT | Sentinel, Elastic and Splunk queries |
| [deathbydata/php2shell-exposurehunt](https://github.com/deathbydata/php2shell-exposurehunt) | MIT | Defender exposure hunts (Linux and Windows) |
| [mym0us3r/PHP2Shell-Detection-with-Wazuh](https://github.com/mym0us3r/PHP2Shell-Detection-with-Wazuh) | MIT | Wazuh decoders, rules and SCA policy |
| [sorenjohanson/crowdsec-cve-2026-109618-rule](https://github.com/sorenjohanson/crowdsec-cve-2026-109618-rule) | MIT | CrowdSec AppSec rule |
| [karlisl/php2shell-rules](https://github.com/karlisl/php2shell-rules) | CC0 1.0 | Fixed-version data file |

Other community projects are linked, not copied, in [docs/community-resources.md](docs/community-resources.md). The vulnerabilities were discovered and documented by the researchers and maintainers named in the PHP advisories (see [docs/sources.md](docs/sources.md)).

## Licensing and reporting

Original code and rules are MIT licensed ([LICENSE](LICENSE)); documentation is CC BY 4.0 ([LICENSE-DOCS](LICENSE-DOCS)), as with our other open datasets. Third-party detection content from nine community projects is copied unchanged into `third_party/` under its own licences (see [NOTICE](NOTICE)); other community projects are linked, not copied. See [LICENSE](LICENSE), [NOTICE](NOTICE) and [SECURITY.md](SECURITY.md).

No production incidents, remote code execution reproductions, new vulnerabilities or measured prevention rates are claimed by this release.
