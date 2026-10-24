# Source

- Upstream: https://github.com/mym0us3r/PHP2Shell-Detection-with-Wazuh
- Author: Kislley Rodrigues (mym0us3r)
- Licence: MIT (see LICENSE in this folder; GitHub API reports MIT)
- Commit fetched: 17253b3185380956e4fc0aade158f8001793e2c5
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 1; last push 2026-10-23

What this is: Wazuh rules, decoders, Apache LogFormat and an SCA policy for Apache mod_php hosts.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- README.md
- apache/php2shell-logformat.conf
- decoders/php2shell_decoders.xml
- rules/php2shell_rules.xml
- sca/php2shell_cve_2026_109618_109619.yml
