#!/usr/bin/env python3
"""Offline bounded YARA scan. Does not execute or delete scanned content."""
import argparse
import json
from pathlib import Path
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # keeps `python3 -I` working
from common import utcnow, walk_files, write_report


def main():
    import yara
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", nargs="+")
    p.add_argument("--rules", default=str(Path(__file__).resolve().parents[1]/'rules/yara/php_triage.yar'))
    p.add_argument("--output", required=True)
    p.add_argument("--max-files", type=int, default=10000)
    a = p.parse_args()
    rules = yara.compile(filepath=a.rules)
    hits, gaps, scanned = [], [], 0
    for path in walk_files(a.root, gaps, a.max_files):
        try:
            if path.stat().st_size >= 5*1024*1024:
                gaps.append({"path": str(path), "reason": "size_limit_skipped"})
                continue
            matched = rules.match(filepath=str(path), timeout=5)
            scanned += 1
            for match in matched:
                hits.append({"path": str(path), "rule": match.rule, "scope": match.meta.get('scope'), "verdict": "manual_review_required"})
        except (OSError, yara.Error):
            gaps.append({"path": str(path), "reason": "unreadable_or_scan_failed"})
    write_report(a.output, {"observed_at": utcnow(), "files_scanned": scanned, "hits": hits, "coverage_gaps": gaps, "limitations": ["Heuristics can match benign uploaders and packed code", "No malware family or CVE attribution", "No memory scanning, archive extraction or content execution", "Known code trees must be allowed as explicit roots; default walker excludes vendor/node_modules"]})


if __name__ == "__main__": main()
