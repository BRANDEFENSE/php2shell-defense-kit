# Advisory baseline — 24 October 2026

This is a dated snapshot, not a live advisory feed. Refresh the original sources before publication or operational use.

| Item | Established by original source | Operational meaning |
|---|---|---|
| CVE-2026-109618 | OOM can interrupt partially initialized state; shutdown can consume it | Patch the runtime; request size controls are partial |
| CVE-2026-109619 | Request-owned state can outlive its heap and be consumed on another request | Patch; audit early initialization and worker lifecycle |
| Initial fixed releases | PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 | Newer vendor-approved releases or documented backports may contain the fix |
| Legacy branches | PHP project supplied minimal source backports for 7.4, 8.0, 8.1; regular upstream support differs | Source backport availability is not an installed fixed package |
| CVE-2026-115560, October 23 related advisory | Unusual serializer switch at runtime plus enabled session upload progress | Follow the specific conditions; do not generalize to every patched application |

For the related October 23 path, PHP describes a configured `php_binary` or `php_serialize` handler being switched to `php` with `ini_set()` before `session_start()`, while upload progress is enabled. PHP recommends disabling upload progress pending the next regular fix. Code that never changes that handler at runtime does not meet this described condition. This is not a newly discovered finding of this kit.

Cloudflare separately documents that its relevant known-attempt WAF coverage uses the default upload-progress field name; customized `session.upload_progress.name` needs specific coverage review. That caveat belongs to the stated rule/path, not a claim that all Cloudflare protections fail.

The OOM advisory distinguishes mod_php's startup-failure cleanup from FPM's child termination. Do not infer FPM immunity: the stale-global-state advisory describes FPM as only conditionally exposed (for example a frontend that passes `PHP_VALUE`/`PHP_ADMIN_VALUE` and triggers an early diagnostic), while the application-dependent FPM paths (`session_start`, `unserialize`, `maybe_unserialize`) come from independent research by Calif, not from the advisory. The different CVEs must not be conflated.

Sources: [PHP release and follow-up](https://www.php.net/archive/2026.php), [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [stale state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), [Calif research](https://calif.io/php2shell/), [Cloudflare update](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/).
