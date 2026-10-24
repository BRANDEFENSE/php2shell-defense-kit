# Community resources

Snapshot of 24 October 2026. This page lists public defensive projects about PHP2Shell (CVE-2026-109618, CVE-2026-109619, and the related CVE-2026-115560 advisory) that we reviewed, and says which of them are copied into this kit. We list a project because its content looked useful and safe to read, not because we endorse it or have run it.

How we chose:

- We searched GitHub for `php2shell`, `CVE-2026-109618`, `CVE-2026-109619` and `CVE-2026-115560` and screened every result (1,072 distinct repositories). Most are exploit PoCs, labs, forks or empty repositories.
- Exploit PoCs, scanners that send crafted or crash-inducing requests, and weaponised code are left out completely: not copied, not linked.
- A project is **bundled** (copied unchanged into [`third_party/`](../third_party/)) only if its licence is permissive, the content is rules, queries, configs or data (no programs), and the logic matches the vendor advisories. Sigma files were checked with pySigma and YARA files compiled with yara-python; Suricata, Zeek and ModSecurity files were also run offline in our lab (see lab-validation.md); Wazuh, CrowdSec and the SIEM queries were read but not run.
- Scripts and programs written by others are **never bundled**, because we did not test them. They are listed here for you to review yourself.
- Copyleft (GPL, AGPL, EUPL), source-available (Elastic License 2.0) and unlicensed projects are listed only.
- We did not run any program from these projects; their rules and Zeek scripts ran only inside the offline lab engines.

Treat everything below as a lead for your own review. Detection content is experimental: run it in alert or log mode first, tune it, and keep patching PHP as the real fix.

## Bundled in this kit

All files are copied unchanged from the commit shown in each folder's `SOURCE.md`. The licence text is next to the files. Their authors wrote them; Brandefense did not.

| Project | Author | Licence | What it is | Our note |
|---|---|---|---|---|
| [corelight/php2shell-detect](https://github.com/corelight/php2shell-detect) | Corelight, Inc. (per LICENSE) | BSD-3-Clause | Zeek package (POST field-name length, serialized-data patterns, repeated MIME headers, session correlation, PHP version inventory) and 3 Suricata rules | Best-documented network detection we found. Needs Zeek 7.0 or later and HTTP visible to Zeek. The version-inventory and `PHP_SESSION_UPLOAD_PROGRESS` alerts are leads, not proof. Bundled: [`third_party/corelight__php2shell-detect`](../third_party/corelight__php2shell-detect/) |
| [orbitron-ai/php2shell-response-kit](https://github.com/orbitron-ai/php2shell-response-kit) | ORBITRON | MIT | Rules only: 8 Sigma, Splunk SPL, QRadar AQL, CrowdStrike LogScale, SentinelOne, Wazuh, 3 YARA hunting rules, log-only ModSecurity | Broadest SIEM coverage. Rules are marked experimental by the author. The child-process rule lists common tools such as `id` and `whoami`, so expect noise on hosts that shell out. Its inventory scripts are not bundled. [Folder](../third_party/orbitron-ai__php2shell-response-kit/) |
| [Senturkselim/Am-I-Infected](https://github.com/Senturkselim/Am-I-Infected) | Senturkselim | MIT | 6 Sigma rules (oversized PHPSESSID, PHP worker child process, reverse-shell command line, PoC user-agent, upload-progress marker, worker crash/OOM) | Careful wording, low-level rules for crash and OOM. The author's Python compromise-check script is not bundled; it runs as root, so review it yourself first. [Folder](../third_party/Senturkselim__Am-I-Infected/) |
| [break-the-build/php-multipart-waf-signals](https://github.com/break-the-build/php-multipart-waf-signals) | break-the-build | MIT | Alert/log-only Suricata and ModSecurity rules for selected multipart request shapes | The author states these are observation signals, not exploit signatures, and corrects an earlier mis-scoped finding. Upstream reports a Suricata 7.0.10 syntax check and lists traffic replay as pending; we replayed the Suricata and ModSecurity rules offline in our lab (see [lab-validation.md](lab-validation.md)). [Folder](../third_party/break-the-build__php-multipart-waf-signals/) |
| [aplite-de/php2shell-detection-rules](https://github.com/aplite-de/php2shell-detection-rules) | aplite-de (GitHub owner) | MIT | Hourly queries for Microsoft Sentinel (KQL), Elastic (ES\|QL) and Splunk (SPL) over web, PHP error and process logs, plus the log formats they expect | Needs the custom access-log format in `log-formats/`. Clear tuning notes. The Docker lab is not bundled. [Folder](../third_party/aplite-de__php2shell-detection-rules/) |
| [deathbydata/php2shell-exposurehunt](https://github.com/deathbydata/php2shell-exposurehunt) | deathbydata | MIT | Defender XDR Advanced Hunting exposure hunts (Linux and Windows): where is PHP running, evidence breakdown, listening web ports, cross-check with Defender vulnerability data | Inventory-style, read-only queries. The upstream LICENSE keeps the placeholder `[COPYRIGHT HOLDER]`; the MIT permission text is complete. Version evidence still needs backport checks. [Folder](../third_party/deathbydata__php2shell-exposurehunt/) |
| [mym0us3r/PHP2Shell-Detection-with-Wazuh](https://github.com/mym0us3r/PHP2Shell-Detection-with-Wazuh) | Kislley Rodrigues | MIT | Wazuh rules, decoders, Apache LogFormat and an SCA policy for Apache mod_php | Scope is Apache mod_php on Linux. Rule IDs 100100 to 100199 may collide with your local range. [Folder](../third_party/mym0us3r__PHP2Shell-Detection-with-Wazuh/) |
| [sorenjohanson/crowdsec-cve-2026-109618-rule](https://github.com/sorenjohanson/crowdsec-cve-2026-109618-rule) | sorenjohanson | MIT | CrowdSec AppSec rule for a multipart POST with a `PHP_SESSION_UPLOAD_PROGRESS` field | The bundled config uses `default_remediation: ban`, which blocks the source. The upstream author calls it a very broad block, not a full mitigation. Test before enabling. [Folder](../third_party/sorenjohanson__crowdsec-cve-2026-109618-rule/) |
| [karlisl/php2shell-rules](https://github.com/karlisl/php2shell-rules) | karlisl | CC0-1.0 | Data file: fixed PHP versions and vendor package versions (Ubuntu, Debian, RHEL) as of 22 October 2026 | We spot-checked the Debian and Ubuntu rows against the vendor trackers on 24 October. RHEL rows were not verified. A dated snapshot: refresh from the trackers before use. [Folder](../third_party/karlisl__php2shell-rules/) |

Index with file lists, formats and checksums: [`third_party/catalog.json`](../third_party/catalog.json). Our own rules and their catalog (`rules/catalog.json`) are unchanged.

## Referenced only (not bundled)

| Project | Author | Licence | What it is | Why not bundled / our note |
|---|---|---|---|---|
| [openai/php2shell-checker](https://github.com/openai/php2shell-checker) | OpenAI | Apache-2.0 | Node script and two agent skills: version warning from `X-Powered-By`/`Server` headers (HEAD, no redirects) or a local PHP | A program, not rules. Same limits as any header check: backports and hidden headers. States it sends no exploit probes |
| [getastra/php2shell-triage](https://github.com/getastra/php2shell-triage) | getastra (GitHub owner) | MIT | Read-only assessment script and triage playbook (walks `/proc` to find the real PHP binary behind each worker, flags workers running a replaced binary, 115 unit cases) | A program. Useful for the "worker not restarted" problem |
| [ericmann/php2shell-ioc](https://github.com/ericmann/php2shell-ioc) | ericmann (GitHub owner) | MIT | Read-only POSIX shell IOC triage (crash lines in logs, upload-progress leftovers in session files, web-root changes) for WordPress, Nextcloud, Laravel, Drupal | A program. States no network and zero file writes |
| [EXT-IT/php2shell-check](https://github.com/EXT-IT/php2shell-check) | EXT-IT (GitHub owner) | MIT | Linux and Windows read-only exposure check that reads package databases, finds containers and sends one ordinary GET per URL you give | A program. Handles the Ubuntu "version number does not change after the fix" case well. Recommended install uses `curl \| bash`; download and read it first |
| [Blue-B/php2shell-guard](https://github.com/Blue-B/php2shell-guard) | Blue-B | MIT | Scan, interim web-server blocking rules and hunting for many web servers, including Cloudflare and HAProxy | A program, and some of its rules block all multipart POSTs, which breaks uploads. Read before applying |
| [Swordsec/php2shell-guard](https://github.com/Swordsec/php2shell-guard) | Swordsec | MIT | Scanner, interim mitigation and hunting tool, standard library only. States no exploit code; the remote mode is a banner check with an optional inert WAF probe | A program that can apply changes (`protect --apply`). Review before running |
| [0xAllow/PHP2Shell-Defense](https://github.com/0xAllow/PHP2Shell-Defense) | 0xAllow | MIT | Local Python toolkit (preflight, version scan, read-only triage, opt-in partial configuration mitigation with backups) plus two Sentinel queries and a generic webshell YARA | Marked "requires production validation" by the author. Its rules duplicate what is already bundled |
| [HOSTED-POWER/php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard) | HOSTED-POWER (GitHub owner) | MIT | Native PHP extension that detaches the upload-progress handler (the CVE-2026-115560 mitigation) and covers further PHP issues | Compiled code that loads into PHP. We did not build or test it. Not a substitute for patching |
| [syhunt/php2shell-protection](https://github.com/syhunt/php2shell-protection) | syhunt (GitHub owner) | MIT | `.htaccess` test kit that rejects multipart POSTs while allowing URL-encoded POSTs | The author is explicit that it is not a complete mitigation |
| [WeaveHubHQ/cf-waf-bypass-check](https://github.com/WeaveHubHQ/cf-waf-bypass-check) | WeaveHubHQ | MIT | Read-only audit of Cloudflare WAF rules that skip, disable or downgrade the Managed Rules that cover PHP2Shell | A program, needs a read-only API token. Complements the Cloudflare caveats in our [baseline](advisory-baseline.md) |
| [completetech-security/php2shell-check](https://github.com/completetech-security/php2shell-check) | completetech-security (GitHub owner) | AGPL-3.0 or commercial | Passive header-based exposure checker, no exploit payloads | Copyleft: listed only |
| [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell) | NCSC-NL | EUPL-1.2 | TLP:CLEAR operational information: status, recommended actions, a cPanel mitigation script, a software list of products that embed PHP | Copyleft: listed only. The software list is the useful part for appliances and embedded PHP |
| [elastic/detection-rules: Potential PHP2Shell Exploitation Attempt](https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/initial_access_potential_php2shell_exploitation_attempt.toml) | Elastic | Elastic License 2.0 | Production-maturity rule on the PHP out-of-memory fatal error with location "Unknown on line 0" in Apache/nginx error logs | Source-available licence: not copied. Our own rule `php_memory_exhaustion` covers the same log signal |

## Primary sources and vendor trackers

Not code, listed for orientation. See also [sources.md](sources.md).

| Source | What it gives you |
|---|---|
| [PHP security advisories GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | Root causes and affected configurations |
| [php.net 2026 news archive](https://www.php.net/archive/2026.php) | Fixed releases, temporary mitigations, the 23 October follow-up |
| Official PHP source backports: branches `PHP-8.1-CVE-2026-109618-109619`, `PHP-8.0-CVE-2026-109618-109619`, `PHP-7.4-CVE-2026-109618-109619` in [php/php-src](https://github.com/php/php-src) | The PHP project's own minimal backports for end-of-life branches. We do not link unofficial rebuilds, RPMs, Docker images or patch sets, because they are a supply-chain risk |
| [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618), [Ubuntu](https://ubuntu.com/security/CVE-2026-109618), [Red Hat bulletin RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013) | Fixed package versions per distribution. Distributions backport without changing the upstream version number |
| [Wiz](https://www.wiz.io/blog/php2shell-php-rce), [Calif](https://calif.io/php2shell/), [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) | Technical research and WAF coverage notes |

## What we left out

Of 1,072 repositories screened by keyword and README review, about 315 are exploit PoCs, labs, "frameworks" or scanners that send crafted or crash-inducing requests (some come from well-known vendors). They are not copied or linked. About 110 more are unofficial PHP rebuilds, backport packages or patch sets; we do not link those either. SigmaHQ/sigma and Neo23x0/signature-base had no PHP2Shell content on 24 October 2026. The rest are duplicates of the projects above, empty repositories or unrelated results. The long tail was sorted by keywords and README text, not read line by line.

## Using third-party content

- Keep each project's LICENSE next to its files; see [NOTICE](../NOTICE).
- Third-party rules have different field names. Map them with the [field contract](telemetry.md) before use.
- Sigma files in `third_party/` are not loaded by our tests of `rules/sigma/` or compiled by `tools/build_splunk.py`. They are only checked for parsing.
- If a licence or a rule is wrong or has changed upstream, remove the folder and tell us through [SECURITY.md](../SECURITY.md).
