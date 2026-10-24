#!/usr/bin/env python3
"""Offline text log lead extraction. Emits types/line numbers, never raw log text."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # keeps `python3 -I` working
from common import utcnow, write_report

PATTERNS = {
    "php_memory_exhaustion": re.compile(r"Allowed memory size of .{0,200}exhausted", re.I),
    "php_execution_timeout": re.compile(r"Maximum execution time of .{0,100}exceeded", re.I),
    "worker_crash_candidate": re.compile(r"(?:php-fpm|php-cgi|lsphp|frankenphp|apache2|httpd).{0,200}(?:segfault|SIGSEGV|signal 11)", re.I),
    "default_upload_progress_marker": re.compile(r"PHP_SESSION_UPLOAD_PROGRESS"),
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("logs", nargs="+")
    p.add_argument("--output", required=True)
    p.add_argument("--max-line-bytes", type=int, default=1024*1024)
    a = p.parse_args()
    leads, gaps, counts = [], [], Counter()
    for filename in a.logs:
        try:
            with Path(filename).open('rb') as source:
                number = 0
                while True:
                    raw = source.readline(a.max_line_bytes+1)
                    if not raw: break
                    number += 1
                    if len(raw) > a.max_line_bytes:
                        # Drain one logical line without loading its contents.
                        while raw and not raw.endswith(b'\n'): raw = source.readline(a.max_line_bytes+1)
                        gaps.append({"path": filename, "line": number, "reason": "oversized_line_skipped"})
                        continue
                    line = raw.decode('utf-8', 'replace')
                    for key, pattern in PATTERNS.items():
                        if pattern.search(line):
                            counts[key] += 1
                            if len(leads) < 100000: leads.append({"path": filename, "line": number, "type": key})
        except OSError:
            gaps.append({"path": filename, "reason": "unreadable"})
    write_report(a.output, {"observed_at": utcnow(), "scope": "uncorrelated_hunting_leads_not_exploitation_proof", "counts": dict(counts), "leads": leads, "lead_limit": 100000, "coverage_gaps": gaps, "limitations": ["No cross-request/worker correlation performed", "Body markers only appear if source logging retained them", "Custom field names, encoded inputs and in-process activity may be missed", "No matches is not evidence of no compromise"]})


if __name__ == "__main__": main()
