# Source

- Upstream: https://github.com/aplite-de/php2shell-detection-rules
- Author: Aplite
- Licence: MIT (see LICENSE in this folder; GitHub API reports MIT)
- Commit fetched: 5c4052213552c21273dac717dd25018e073ede4b
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 0; last push 2026-10-22

What this is: Hourly detection queries for Microsoft Sentinel (KQL), Elastic (ES|QL) and Splunk (SPL), plus the web log formats they expect. The upstream lab is NOT bundled.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- README.md
- elastic/01-suspicious-form-posts.esql
- elastic/02-memory-errors-and-worker-crashes.esql
- elastic/03-php-starting-a-shell.esql
- log-formats/apache.conf
- log-formats/nginx.conf
- sentinel/01-suspicious-form-posts.kql
- sentinel/02-memory-errors-and-worker-crashes.kql
- sentinel/03-php-starting-a-shell.kql
- splunk/01-suspicious-form-posts.spl
- splunk/02-memory-errors-and-worker-crashes.spl
- splunk/03-php-starting-a-shell.spl
