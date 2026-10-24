# Security reporting

Do not include live session cookies, credentials, customer data, internal host inventories or memory dumps in public issues.

For a suspected new PHP vulnerability, use the PHP project's current private security reporting process. For a kit defect, use GitHub's private vulnerability reporting on this repository (Security tab, Report a vulnerability). This kit does not publish a separate reporting email address.

Collectors are intended for infrastructure you administer. Normal HTTP header probes are opt-in and explicitly scoped. Review script provenance and permissions before running on production systems. No automatic remediation or exploitation is performed.

## Data handling

Local inventory includes hostnames, paths, process identifiers, package names and optional image references. Those can be confidential even though credentials are excluded. Keep output private. Python reports are created with mode `0600` where supported; the Windows collector requires an operator-selected NTFS ACL. Reports are ignored by the included Git configuration.

Do not export raw request bodies or response cookie values into a new SIEM pipeline just to enable these rules. Extract metadata such as parameter names and cookie length at the trusted inspection point. Use your established evidence handling process if sensitive raw data is independently required for an incident.
