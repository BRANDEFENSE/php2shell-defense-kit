# Telemetry contract and field mapping

Sigma logsource metadata is a deployment contract, not a filter automatically added by every backend. The included SPL is backend-generated **selection logic only**. Apply an index/sourcetype scope for the exact logsource and map fields before deployment. Do not paste unscoped selections into all logs and call the result validated.

## Required fields

| Family | Fields used | Sources and caveats |
|---|---|---|
| Process creation | `Image`, `ParentImage`, optional `CommandLine` | EDR, Sysmon, audit pipeline or endpoint agent. Normalize full executable paths; PID ancestry is stronger than a parent name alone |
| File events | `Image`, `TargetFilename` | File creation/write sensor. Sysmon coverage differs from file content monitoring; in-place modifications may not be logged |
| PHP errors | `Message` | Ingest PHP error logs under `product: php`, `service: error`; these are custom logsource labels |
| Linux worker crashes | `Message` | Normalized syslog/journald events, scoped to the correct logsource |
| HTTP upload-progress | `cs-method`, `BodyParameterNames` | `BodyParameterNames` is a custom field holding a single parameter name per event, or a multivalue array of decoded names. Standard access logs do not include it |
| HTTP request metadata | `PartCount`, `PartHeaderCount`, `sc-status` | Custom fields: multipart part count and total part-header count, and the response status. Metadata only; never store the body |
| FPM master log | `Message`, `PoolName` | php-fpm master log lines (child exited with code 70). The storm rule counts per host and pool |
| nginx error log | `Message` | "client intended to send too large body" lines |
| HTTP response cookie | `ResponseCookieName`, `ResponseCookieValueLength` | Custom per-cookie event. Length is the parsed cookie **value** length in bytes, not the full header length. Never store the session value in this field |

Preserve event timestamp with timezone, host/container identity, request ID when available and PID/worker identity separately. The simple Sigma rules in this release do not perform cross-request correlation. A PID can be reused; include process start time in a richer correlation pipeline.

## Normalization examples (synthetic)

```json
{"cs-method":"POST","BodyParameterNames":["file","PHP_SESSION_UPLOAD_PROGRESS"],"RequestId":"synthetic-1"}
```

```json
{"ResponseCookieName":"PHPSESSID","ResponseCookieValueLength":5000,"RequestId":"synthetic-2"}
```

`PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` are defaults. Custom names require local rule adaptation. The cookie threshold of 4096 is an initial hunting threshold, not a demonstrated exploit boundary. Multiple cookies in one response should become separate normalized records.

## Network visibility

Inspect HTTP at a point with plaintext visibility after TLS termination or approved decryption. An encrypted packet feed alone cannot evaluate body parameter names or response cookie lengths. Frontend normalization, decompression and parser behavior need validation; simply enabling a WAF is not proof those fields exist.

Do not enable indiscriminate full-body or cookie logging for this kit. Metadata extraction is sufficient for these rules. Existing incident evidence is handled under the organization's separate retention/access policy.

## Rule logic semantics

Sigma ordinary strings are case-insensitive by default; regex modifiers are case-sensitive unless explicitly flagged. The Linux parent regex expects normal lower-case process filenames and canonical path separators. Windows rules use backslash paths. Paths seen through wrappers, containers, renamed binaries or a shell grandparent can fall outside those selections.

The custom `php` and HTTP logs need a local SIEM pipeline. MDE examples use native `DeviceProcessEvents`/`DeviceFileEvents` fields instead; they do not require pretending Sigma names already exist in MDE.
