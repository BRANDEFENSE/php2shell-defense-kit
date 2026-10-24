# php2shell-rules

Fixed PHP versions and fixed distribution packages for PHP2Shell
(CVE-2026-109618, CVE-2026-109619), as one JSON file: [`rules.json`](rules.json).

This is the data the [php2shell.fyi](https://php2shell.fyi/) checker uses. The same table, in plain words, is at
[php2shell.fyi/linux](https://php2shell.fyi/linux).

Unofficial. Not affiliated with the PHP project or php2shell.com.

## Why this exists

Ubuntu, Debian and RHEL ship the fix without changing the PHP version number. A fixed Ubuntu 24.04
server still reports PHP 8.3.6. The fix is in package `8.3.6-0ubuntu0.24.04.13` (USN-8948-1).
A check that compares only the version number gets these servers wrong. This file lists the full
fixed package version for each release, with the vendor notice for each row.

A version header is a hint, not proof. The sure check is on the server: the installed package
version, and a restart of PHP-FPM, Apache and any long-running PHP workers after the update.

## Schema

Top-level keys of `rules.json`:

| Key | Type | Meaning |
| --- | --- | --- |
| `rulesVersion` | string (date) | Date of the last data change. |
| `name`, `description` | string | What the file is. |
| `checker`, `research` | URL | The checker, and the original research (php2shell.com). |
| `advisory` | `{title, url}` | The php.net security advisory of 2026-10-21. |
| `cves` | array | One entry per CVE: `id`, `ghsa`, `url` (GHSA advisory), `summary`, `cvss` (`version`, `score`, `severity`, `vector`). |
| `fixed` | object | Branch to first fixed upstream release, for example `"8.3": "8.3.36"`. A higher patch release in the same branch also has the fix. |
| `securitySupportEnds`, `securitySupportSource` | object, URL | End of upstream security support per branch, from php.net. |
| `sourceBackportsOnly` | array | Branches with no new release (7.4, 8.0, 8.1): `branch`, `supportEnded`, `patches` (php-src branch with the source backport). |
| `sourceBackportsNote` | string | What to do on those branches. |
| `preRelease` | object | Which 8.6 pre-release has the fix: `version`, `note`, `source`. |
| `vendorPackages` | object | `note`, `checked` (date), then one key per vendor (`ubuntu`, `debian`, `rhel`). |
| `guides` | object | Links to the human-readable pages. |

Each vendor entry in `vendorPackages` has:

- `sources`: the vendor tracker and notice URLs.
- `packages`: an array of `{release, package, fixed, notice | advisory}`.
  `fixed` is the first fixed package version. Compare it with the installed package version using
  the vendor's own version rules (`dpkg --compare-versions`, `rpmdev-vercmp`), not as a string.

Only fixed packages that the vendor trackers list appear in the file. A missing release means
"not listed yet", not "not affected".

## Sources

- php.net advisory, 2026-10-21: https://www.php.net/archive/2026.php#2026-10-21-5
- GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp on github.com/php/php-src
- Original research: https://www.php2shell.com/
- Ubuntu: https://ubuntu.com/security/CVE-2026-109618 (USN-8948-1, USN-8948-2)
- Debian: https://security-tracker.debian.org/tracker/CVE-2026-109618
- Red Hat: https://access.redhat.com/security/vulnerabilities/RHSB-2026-013 and the RHSA advisory named in each row

## Update cadence

The vendor trackers are checked daily while vendors still publish fixes for PHP2Shell. This repo
mirrors https://php2shell.fyi/rules.json after each data change, and `rulesVersion` shows the date
of the last change. Corrections are welcome as issues, with a link to the vendor notice.

## License

CC0 1.0 Universal. See [LICENSE](LICENSE). No attribution needed, but a link back helps others find
updates.

## Contact

security@php2shell.fyi
