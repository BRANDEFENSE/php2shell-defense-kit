# PHP2Shell incident investigation playbook

## Establish scope and preserve evidence

- Identify the affected asset, owner, exact runtime/SAPI, exposure paths and earliest available logs. Distinguish a vulnerable build from a proven intrusion.
- Preserve authorized volatile evidence before restarts on suspicious hosts where operationally feasible. This kit does not collect memory dumps, secrets or process environments.
- Export relevant web/WAF, PHP, process/file, network, identity and cloud audit events using the organization's evidence procedures. Retain timestamps/timezones, collection times and hashes.
- AWS reported an October 17 exploitation attempt before the October 21 public release. Use at least that date when relevant and logs exist; earlier retained telemetry can still matter. An attempt and a successful compromise are different findings.

## Investigate three layers

1. **HTTP and runtime:** unusual multipart traffic, upload-progress signals, abnormal session responses, memory exhaustion, execution timeouts, worker crashes and initialization diagnostics. Correlate by host, process lifetime and request context where available.
2. **Host activity:** new or changed PHP files, unusual children/grandchildren of web workers, unexpected outbound connections, persistence changes and unexplained service/user changes. Compare deployment records and application baselines.
3. **Identity and downstream access:** review use of the identities and secrets the affected process could access, including databases, cloud roles and API integrations. Do not infer those were stolen solely from a vulnerable version.

## Contain and recover

- Restrict affected services through approved network controls, preserving the ability to investigate.
- Patch/redeploy the actual runtime, restart all relevant workers and confirm the active build and replicas.
- For confirmed or credibly suspected access to secrets, invalidate/rotate the affected credentials and session material using a dependency-aware plan. Revoke active tokens where required; changing a password alone may not revoke an existing session.
- If compromise is confirmed, restore/rebuild from a trusted baseline and verify persistence/identity cleanup; replacing PHP alone does not remove an intruder.
- Confirm logging and detections work after recovery, and record remaining unknowns.

## Reported network observations

The dated indicator file under `intel/` reproduces public AWS observations as investigation pivots only. Shared anonymization infrastructure is not unique to PHP2Shell. An IP match is neither attribution nor a reason for permanent blocking. No IP-based rule is enabled automatically.

## Closure criteria

The owner has documented the running fixed build, vendor backport proof where applicable, restart/rollout completion, effective mitigation/configuration state, October 23 related-path review, incident investigation disposition and unresolved logging gaps. All assets in the tracker are resolved or explicitly accepted by their owner; unknowns are not silently marked clean.

Source: [AWS MadPot observations and uncertainty](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/).
