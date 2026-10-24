# Source

- Upstream: https://github.com/orbitron-ai/php2shell-response-kit
- Author: ORBITRON
- Licence: MIT (see LICENSE in this folder; GitHub API reports MIT)
- Commit fetched: 3250dee3b5264071b360b57de641ae7efc80193b
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 1; last push 2026-10-21

What this is: Detection rules only (the upstream inventory scripts are NOT bundled): Sigma, Splunk SPL, QRadar AQL, CrowdStrike LogScale, SentinelOne, Wazuh, YARA hunting rules and a log-only ModSecurity file, plus the upstream BUILD_REPORT.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- README.md
- rules/BUILD_REPORT.md
- rules/crowdstrike/lnx_php2shell_webserver_spawns_shell_or_lolbin.logscale
- rules/crowdstrike/lnx_php2shell_webserver_suspicious_cmdline.logscale
- rules/crowdstrike/php2shell_php_fpm_worker_exit_code70.logscale
- rules/crowdstrike/php2shell_php_oom_during_request_parsing.logscale
- rules/crowdstrike/php2shell_php_worker_crash.logscale
- rules/crowdstrike/win_php2shell_webserver_spawns_shell_or_lolbin.logscale
- rules/modsecurity/php2shell-upload-progress.conf
- rules/qradar/lnx_php2shell_php_file_written_to_webroot.aql
- rules/qradar/lnx_php2shell_php_file_written_to_webroot.payload.aql
- rules/qradar/lnx_php2shell_webserver_spawns_shell_or_lolbin.aql
- rules/qradar/lnx_php2shell_webserver_spawns_shell_or_lolbin.payload.aql
- rules/qradar/lnx_php2shell_webserver_suspicious_cmdline.aql
- rules/qradar/lnx_php2shell_webserver_suspicious_cmdline.payload.aql
- rules/qradar/php2shell_php_fpm_worker_exit_code70.payload.aql
- rules/qradar/php2shell_php_oom_during_request_parsing.payload.aql
- rules/qradar/php2shell_php_worker_crash.payload.aql
- rules/qradar/win_php2shell_php_file_written_to_webroot.aql
- rules/qradar/win_php2shell_php_file_written_to_webroot.payload.aql
- rules/qradar/win_php2shell_webserver_spawns_shell_or_lolbin.aql
- rules/qradar/win_php2shell_webserver_spawns_shell_or_lolbin.payload.aql
- rules/sentinelone/lnx_php2shell_php_file_written_to_webroot.dv
- rules/sentinelone/lnx_php2shell_php_file_written_to_webroot.pq
- rules/sentinelone/lnx_php2shell_webserver_spawns_shell_or_lolbin.dv
- rules/sentinelone/lnx_php2shell_webserver_spawns_shell_or_lolbin.pq
- rules/sentinelone/lnx_php2shell_webserver_suspicious_cmdline.dv
- rules/sentinelone/lnx_php2shell_webserver_suspicious_cmdline.pq
- rules/sentinelone/win_php2shell_php_file_written_to_webroot.dv
- rules/sentinelone/win_php2shell_php_file_written_to_webroot.pq
- rules/sentinelone/win_php2shell_webserver_spawns_shell_or_lolbin.dv
- rules/sentinelone/win_php2shell_webserver_spawns_shell_or_lolbin.pq
- rules/sigma/lnx_php2shell_php_file_written_to_webroot.yml
- rules/sigma/lnx_php2shell_webserver_spawns_shell_or_lolbin.yml
- rules/sigma/lnx_php2shell_webserver_suspicious_cmdline.yml
- rules/sigma/php2shell_php_fpm_worker_exit_code70.yml
- rules/sigma/php2shell_php_oom_during_request_parsing.yml
- rules/sigma/php2shell_php_worker_crash.yml
- rules/sigma/win_php2shell_php_file_written_to_webroot.yml
- rules/sigma/win_php2shell_webserver_spawns_shell_or_lolbin.yml
- rules/splunk/lnx_php2shell_php_file_written_to_webroot.spl
- rules/splunk/lnx_php2shell_webserver_spawns_shell_or_lolbin.cim.spl
- rules/splunk/lnx_php2shell_webserver_spawns_shell_or_lolbin.spl
- rules/splunk/lnx_php2shell_webserver_suspicious_cmdline.cim.spl
- rules/splunk/lnx_php2shell_webserver_suspicious_cmdline.spl
- rules/splunk/php2shell_php_fpm_worker_exit_code70.spl
- rules/splunk/php2shell_php_oom_during_request_parsing.spl
- rules/splunk/php2shell_php_worker_crash.spl
- rules/splunk/win_php2shell_php_file_written_to_webroot.cim.spl
- rules/splunk/win_php2shell_php_file_written_to_webroot.spl
- rules/splunk/win_php2shell_webserver_spawns_shell_or_lolbin.cim.spl
- rules/splunk/win_php2shell_webserver_spawns_shell_or_lolbin.spl
- rules/wazuh/0910-orbitron-php2shell_rules.xml
- rules/wazuh/auditd-php2shell.rules
- rules/wazuh/ossec-agent-snippet.xml
- rules/yara/php2shell_hunting.yar
