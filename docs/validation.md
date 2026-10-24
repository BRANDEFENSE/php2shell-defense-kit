# Validation plan: detection logic versus protection

## Tests included in this release

Run `python -m pytest -q`. The suite parses Sigma with pySigma, evaluates its parsed condition tree on synthetic normalized events, compiles selections with the pySigma Splunk backend, compiles YARA with warnings treated as errors, matches inert synthetic strings and tests conservative inventory behavior. The lab corpus (`tests/lab-corpus/`, see `lab-validation.md`) is replayed through the same evaluator against real lab records. This is not a SIEM execution engine; field mappings and live event delivery remain separate.

Fixtures include expected non-matches, missing-field checks, custom-field/default-name limitations, credential-output redaction, quoted settings, a vendor-backport-looking version, a prerelease, symlink skips, deleted mapped modules and a loopback HEAD/redirect test. No external hosts receive test requests.

## Validation that must occur locally before production use

- Execute the Windows collector on supported PowerShell/Windows versions and review IIS mappings.
- Execute osquery pack queries against installed table schemas and permissions.
- Validate MDE queries in Advanced Hunting and tune process names, paths and event sources.
- Map Sigma fields, scope log sources and run converted SPL in the target Splunk deployment.
- Measure rule false positives on representative legitimate traffic and application workflows.

## Optional controlled defense research

No exploit is included or run. If your authorized research team separately performs prevention testing, use an isolated local environment with no external connectivity and only synthetic data. Record exact source commits, image digests, compiler/build flags, SAPI, extensions, memory controls, frontend versions and effective startup configuration.

The experiment should distinguish at least these outcomes:

| Observation | What it establishes | What it does not establish |
|---|---|---|
| Request blocked before origin | Tested input rejected at that point | All exploit paths covered |
| Origin response blocked | Tested response not delivered | Origin memory was not corrupted |
| Worker terminated | Containment/failure behavior | No earlier exposure or other affected worker |
| Rule alert fired | That telemetry and condition matched | Exploit prevention |
| Expected synthetic disclosure absent | One test did not observe the marker | General runtime safety |
| Fixed running build verified | Patch evidence for that build | No historical compromise |

Use a separately established vulnerable reference if testing exploit prevention; a failed or incompatible PoC cannot establish protection. Keep real exploit payloads, customer data and live secrets out of the public fixture suite. Submit new vulnerability findings through responsible private reporting before publication.

The template at `templates/defense-validation.csv` deliberately says `not_run`; no prevention result is invented.
