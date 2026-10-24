#!/usr/bin/env python3
"""Static PHP source candidates for serializer transitions and lifecycle callbacks."""
import argparse
import json
from pathlib import Path
import re
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # keeps `python3 -I` working
from common import read_small, utcnow, walk_files, write_report

PATTERNS = {
    "serializer_setting_reference": r"session\.serialize_handler",
    "ini_mutation": r"\bini_(?:set|alter)\s*\(",
    "session_start": r"\bsession_start\s*\(",
    "decode_operation": r"\b(?:unserialize|session_decode|maybe_unserialize)\s*\(",
    "shutdown_callback": r"\b(?:register_shutdown_function|__destruct)\s*\(",
    "custom_session_handler": r"\bsession_set_save_handler\s*\(",
    "time_limit_mutation": r"\bset_time_limit\s*\(",
}


def scan(roots):
    gaps, files = [], []
    for path in walk_files(roots, gaps):
        if path.suffix.lower() not in {".php", ".phtml", ".inc"}:
            continue
        text = read_small(path, gaps)
        if text is None:
            continue
        hits = [{"line": n, "pattern": key} for n, line in enumerate(text.splitlines(), 1) for key, pattern in PATTERNS.items() if re.search(pattern, line, re.I)]
        if hits:
            keys = {x["pattern"] for x in hits}
            files.append({"path": str(path), "hits": hits, "serializer_flow_review_candidate": {"serializer_setting_reference", "ini_mutation", "session_start"} <= keys})
    return {"observed_at": utcnow(), "scope": "lexical_candidates_not_dataflow_or_vulnerability_proof", "files": files, "coverage_gaps": gaps, "limitations": ["Comments and strings may match", "Dynamic calls and cross-file control flow may be missed", "Excluded vendor/node_modules trees need explicit separate roots if required", "No source text or secrets exported", "Does not establish CVE-2026-115560 preconditions"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", nargs="+")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    write_report(a.output, scan(a.root))


if __name__ == "__main__": main()
