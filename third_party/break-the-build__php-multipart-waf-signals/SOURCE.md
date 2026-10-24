# Source

- Upstream: https://github.com/break-the-build/php-multipart-waf-signals
- Author: break-the-build
- Licence: MIT (see LICENSE in this folder; GitHub API reports MIT)
- Commit fetched: 8b7d37f288c16afcec4f64e51367e3f9f7280713
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 5; last push 2026-10-21

What this is: Observation-only Suricata rules and ModSecurity rules for selected multipart request shapes. Alert/log only. Upstream states Suricata 7.0.10 syntax check passed; traffic replay pending.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- README.md
- TUNING.md
- modsecurity/php-multipart-signals.conf
- suricata/php-multipart-signals.rules
- suricata/syntax-check-suricata7.txt
