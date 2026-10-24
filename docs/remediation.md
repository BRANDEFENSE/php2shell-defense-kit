# Remediation evidence and temporary controls

## Complete the original two-CVE fix

1. Identify every web-serving runtime, embedded build and container image.
2. Install a supported fixed PHP release or a vendor package with explicit evidence for **both** original CVEs. PHP 8.2.35/8.3.36/8.4.27/8.5.12 are the initial upstream fixes.
3. Preserve incident evidence first on suspicious hosts, then restart/redeploy every affected worker/module/container through the operational change process.
4. Verify the actual HTTP-serving build and effective configuration. CLI evidence alone is insufficient.
5. Confirm every replica/tenant/pool and the separate October 23 advisory status. Complete the patch tracker; do not close unknown assets.

There is no automatic remediation in this kit. An old version string can contain a vendor backport, and a new on-disk package can coexist with an old running process.

## Partial controls when updating is delayed

| Control | Intended scope | Residual issue / operational check |
|---|---|---|
| `session.upload_progress.enabled=0` at startup | Confirmed session upload-progress paths | Not all stale-state paths; restart all workers and verify effective value |
| PHP 8.5 `fatal_error_backtraces=0` | Confirmed fatal-backtrace path | Other state remains; version-specific setting |
| Administratively enforced `memory_limit=-1` | Predictable PHP-limit OOM trigger | Underlying allocation failure can remain; unbounded resource consumption must be contained |
| Conservative `post_max_size` and frontend size limits | Input pressure | Wire size differs from decoded/internal memory use |
| Limits on multipart parts, per-part headers and input nesting | Work amplification | Not a runtime memory-safety patch |
| Restrict network access or isolate service | Exposure reduction | Check every direct-origin and alternate route |
| Vendor WAF rules in block mode | Known covered HTTP paths | Inspect exclusions, actual configuration, alternate origin access and response-rule behavior |

Do not blindly deploy `memory_limit=-1`. This is a conditional temporary measure from the PHP advisory, not a default recommended configuration for patched servers. Do not replace PHP limits with `RLIMIT_AS`/`RLIMIT_DATA`: the PHP advisory warns that allocation failures can lead back to the vulnerable path. The advisory states that a cgroup limit such as `memory.max` does not guarantee allocation failure and is not a complete mitigation. Treat container and worker memory limits as blast-radius controls only, and test in your own setup what a memory kill takes down (workers, master, neighbouring services); this kit has not measured that.

Apply early controls before request parsing using startup/server/pool configuration. Application `ini_set()` and FPM `.user.ini` are too late for the described session mitigation. Remove invalid/deprecated per-request directives that emit early diagnostics; hiding their display is not the same as eliminating the diagnostic.

## October 23 related path

Assess CVE-2026-115560 against its exact described serializer-transition preconditions. PHP recommends keeping upload progress disabled until the regular fix where applicable. Record this separately from proof that the October 21 patches are installed. Check the current PHP advisory again before publication; this is a dated baseline.

## Things that are not closure evidence

- Upgrading WordPress or a plugin without fixing PHP.
- No `X-Powered-By` banner or `expose_php=Off`.
- Hiding errors or disabling shell functions as a substitute for fixing memory safety.
- A failed public PoC on one configuration.
- A WAF alert with no proof of its action or origin routing.
- No webshell when an in-process memory-disclosure path is possible.

References: [PHP](https://www.php.net/archive/2026.php), [OOM mitigation details](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [stale-state mitigations](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
