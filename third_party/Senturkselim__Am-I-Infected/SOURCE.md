# Source

- Upstream: https://github.com/Senturkselim/Am-I-Infected
- Author: Senturkselim
- Licence: MIT (see LICENSE in this folder; GitHub API reports MIT)
- Commit fetched: 3a1d08ce346b011e46a0ad74ede2f3ca4f7e65fe
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 0; last push 2026-10-23

What this is: Six Sigma rules (oversized PHPSESSID, PHP worker child process, reverse-shell command line, public PoC user-agent, upload-progress marker, worker crash/OOM). The upstream Python script is NOT bundled.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- sigma/php2shell_oversized_phpsessid.yml
- sigma/php2shell_php_worker_child_process.yml
- sigma/php2shell_php_worker_reverse_shell.yml
- sigma/php2shell_poc_user_agent.yml
- sigma/php2shell_upload_progress_marker.yml
- sigma/php2shell_worker_crash_or_oom.yml
