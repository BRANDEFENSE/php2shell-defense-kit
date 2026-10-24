# Source

- Upstream: https://github.com/corelight/php2shell-detect
- Author: Corelight, Inc.
- Licence: BSD-3-Clause (see LICENSE in this folder; GitHub API reports BSD-3-Clause)
- Commit fetched: 4d5131c7f7812d7b84a85cb61c64837c125920fe
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 10; last push 2026-10-21

What this is: Zeek package (HTTP body/header analysis, session correlation, PHP version inventory) and 3 Suricata rules for PHP2Shell indicators. Zeek scripts are detection logic that runs inside Zeek; they send nothing.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- README.md
- scripts/__load__.zeek
- scripts/body_inspect.zeek
- scripts/cluster.zeek
- scripts/config.zeek
- scripts/headers.zeek
- scripts/http_body_analysis.zeek
- scripts/patterns.zeek
- scripts/sessions.zeek
- scripts/versions.zeek
- suricata/php2shell.rules
