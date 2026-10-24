# Source

- Upstream: https://github.com/deathbydata/php2shell-exposurehunt
- Author: deathbydata
- Licence: MIT (see LICENSE in this folder; GitHub API reports MIT)
- Commit fetched: 68a4e63f7bc3d4592f90898a851c17732f84f538
- Fetched: 2026-10-24 through the GitHub raw-content URL for that commit, no git clone, nothing executed
- Stars at fetch time: 3; last push 2026-10-23

What this is: Defender XDR Advanced Hunting (KQL) exposure hunts for Linux and Windows. The upstream LICENSE file keeps the placeholder '[COPYRIGHT HOLDER]'; the MIT permission text is complete. The upstream lint tests are NOT bundled.

Files are copied unchanged from the commit above. They are third-party material,
not written or endorsed by Brandefense (see NOTICE). Brandefense checked only that
Sigma files parse with pySigma and YARA files compile with yara-python. Suricata, Zeek and
ModSecurity files were later run offline in the Brandefense lab (see docs/lab-validation.md); other
formats (Wazuh, CrowdSec, KQL, SPL, AQL, LogScale, SentinelOne) were read but not run in an engine. Test in detect/log mode before any blocking use.

Files:
- LICENSE
- README.md
- queries/linux/01-any-php.kql
- queries/linux/02-evidence-breakout.kql
- queries/linux/03-safety-net.kql
- queries/linux/04-defender-cve-check.kql
- queries/windows/01-any-php.kql
- queries/windows/02-evidence-breakout.kql
- queries/windows/03-safety-net.kql
- queries/windows/04-defender-cve-check.kql
