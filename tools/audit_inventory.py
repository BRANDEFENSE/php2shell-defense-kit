#!/usr/bin/env python3
"""Offline triage of inventory evidence; never emits a clean/not-vulnerable verdict."""
import argparse
import json
from pathlib import Path
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # keeps `python3 -I` working
from common import write_report


def audit(report):
    findings = []
    for package in report.get("packages", []):
        findings.append({"kind": "package_patch_verification", "asset": package["name"], "version": package["version"], "status": package.get("status", "unknown"), "action": "Match exact vendor package release to both CVEs; prove the web worker uses it"})
    for process in report.get("processes", []):
        if process.get("restart_review_required"):
            findings.append({"kind": "old_mapped_binary_or_module", "pid": process["pid"], "action": "Review mapped artifact and restart plan after preserving incident evidence"})
    for file in report.get("configurations", []):
        for item in file.get("settings", []):
            key, value = item["setting"], item["value"].lower()
            base = {"path": file["path"], "line": item["line"], "setting": key, "value": value, "scope": "static_candidate_effective_value_unknown"}
            if key == "session.upload_progress.enabled" and value not in {"0", "off", "false", "no"}:
                findings.append({**base, "kind": "upload_progress_enabled_candidate", "action": "Confirm startup-effective value and assess Oct 23 advisory"})
            elif key == "session.upload_progress.name" and value != "php_session_upload_progress":
                findings.append({**base, "kind": "custom_upload_progress_field", "action": "Verify vendor WAF coverage for this exact field; do not assume default-name rules cover it"})
            elif key == "session.serialize_handler" and value in {"php_binary", "php_serialize"}:
                findings.append({**base, "kind": "serializer_review", "action": "Review source for runtime switch to php before session_start; setting alone is not CVE-2026-115560 proof"})
            elif key == "memory_limit" and value == "-1":
                findings.append({**base, "kind": "unbounded_php_heap_review", "action": "Temporary partial mitigation only; validate independent resource containment and patch"})
            elif key == "fatal_error_backtraces" and value not in {"0", "off", "false", "no"}:
                findings.append({**base, "kind": "fatal_backtrace_review", "action": "Relevant to PHP 8.5; establish runtime version before applying mitigation"})
    return {"scope": "triage_only_not_effective_runtime_or_vulnerability_proof", "findings": findings, "coverage_gaps": report.get("coverage_gaps", []), "unresolved": ["web runtime build and restart", "vendor backport verification", "effective configuration and precedence", "CVE-2026-115560 application preconditions", "historical compromise"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inventory")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    write_report(a.output, audit(json.loads(Path(a.inventory).read_text())))


if __name__ == "__main__":
    main()
