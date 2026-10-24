# Source

- Upstream: https://github.com/karlisl/php2shell-rules
- Author: karlisl
- Licence: CC0-1.0 (see LICENSE in this folder; GitHub API reports CC0-1.0)
- Commit fetched: ff27362919b54484ec5511f4623d877e1f758998
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 0; last push 2026-10-22

What this is: Data file of fixed PHP versions and vendor package versions (Ubuntu, Debian, RHEL) as of 2026-10-22. Brandefense spot-checked the Debian and Ubuntu rows against the vendor trackers on 2026-10-24; RHEL rows were not verified. Treat as a dated snapshot.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- README.md
- rules.json
