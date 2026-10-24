# Detection coverage and tuning

## Rule families

| Family | Files | Meaning |
|---|---|---|
| Linux web process behavior | `linux_web_shell`, `linux_web_downloader`, `linux_web_interpreter`, `linux_web_secret_command`, `linux_web_persistence_command`, `linux_web_temp_child` | Generic direct-child behavior, not proof of a specific CVE |
| File writes | `linux_webroot_php_write`, `windows_webroot_php_write` | Candidate script writes in selected web roots; CMS changes can match |
| Windows process behavior | `windows_web_shell`, `windows_web_transfer` | Includes IIS workers that can host non-PHP applications |
| HTTP signals | `http_upload_progress_field`, `http_large_session_cookie` | Requires explicit custom metadata; default names only |
| Runtime signals | `php_startup_oom_fatal` (`php_memory_exhaustion` is the same match, deprecated), `php_execution_timeout`, `linux_php_worker_crash` | Anomaly leads that can also be entirely benign. Before it was narrowed to the startup signature, `php_memory_exhaustion` fired on 24 of 42 benign lab cases; now 0 |
| Startup memory exhaustion (new, v0.3.0) | `php_startup_oom_fatal`, `php_fpm_child_exit_70_storm`, `nginx_body_too_large`, `http_post_rejected_413` | The PHP fatal "in Unknown on line 0" (before any script ran), a burst of FPM children exiting with code 70 (5 in 5 minutes per pool; set the threshold per pool), and nginx/HTTP 413 on oversize bodies. False positives: a hard `memory_limit` set far too low, big legitimate uploads (413), FPM restarts after deploys |
| Request shape (new, v0.3.0) | `http_upload_progress_with_body_session_id`, `http_multipart_flood` | Upload-progress field next to a body `PHPSESSID`, and multipart with extreme part or part-header counts. Blind spot: the progress field name is configurable (`session.upload_progress.name`); a renamed field is missed until you adapt the rule |

Replay results for every rule on real lab records, including the misses and the benign hits: [lab-validation.md](lab-validation.md).

Consult `rules/catalog.json` for rule IDs and fields. All Sigma rules are `experimental`. Begin in detect mode and tune per application/pool/host. Level is triage priority, not a measured confidence score. Do not auto-block on low-confidence runtime or YARA signals.

## Practical tuning

1. Establish known child processes, CMS deployment windows, maintenance accounts and application upload patterns.
2. Prefer narrowly defined exceptions tied to an application identity and verified behavior. An allowlist for every `php-fpm` child would suppress the signal itself.
3. Extend web-root lists to actual tenant roots, app paths and Windows handler configurations.
4. Build grandparent/process-tree coverage where shell-mediated execution means the immediate parent is `/bin/sh`. Direct-child rules alone miss that case.
5. Verify renamed/bundled runtimes, version-suffixed binaries, wrappers and container path normalization.
6. Re-test positive, negative, missing-field and known-benign events after every field mapping change.

## YARA interpretation

| Rule | Intended use | Important false positives / blind spots |
|---|---|---|
| `BD_PHP_Direct_Request_Command` | Direct request input into execution functions | Legitimate admin tools can match; variables/wrappers can evade |
| `BD_PHP_Encoded_Eval_Loader` | An eval/decoding chain | Legitimate encoded software can match; many encodings evade |
| `BD_PHP_Request_Driven_File_Write` | Request-related write candidates | Normal uploaders and editors match; there is no dataflow proof |
| `BD_PHP_Socket_And_Process_Primitives` | Socket and process primitives together | Admin/network utilities can match; co-occurrence is not a reverse-shell proof |
| `BD_PHP_Upload_Progress_Research_Artifact` | Research/tooling text for manual review | Defensive documents, including this kit, intentionally match; this rule is not malware detection |

The four PHP heuristics require a `<?php` marker within the first 4096 bytes and files under 2 MiB. The research-artifact rule is under 5 MiB. Short-open-tag code, long preambles, other encodings, archives and pure in-memory activity may be missed. No broad-corpus false-positive rate has been measured. Use copied content offline; do not execute findings or automatically delete files.

## Attribution and closure

A web process launching a shell can result from many vulnerabilities or legitimate workflows. A memory error is not an exploitation verdict. No matches can mean absent telemetry, custom names, an uncovered path or an attacker who never spawned a process. The absence of a webshell is not evidence against a memory-only disclosure.

Useful existing third-party content, not copied into this kit: [Elastic's post-exploitation detections](https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection). Corelight's Zeek/Suricata work ([blog](https://corelight.com/blog/php2shell-detection-before-disclosure)) is bundled unchanged in `third_party/corelight__php2shell-detect/`. Preserve their original licenses and coverage statements when separately adopting them.
