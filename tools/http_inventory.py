#!/usr/bin/env python3
"""Explicit opt-in normal HEAD requests to supplied URLs. No discovery or exploit."""
import argparse
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import re
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # keeps `python3 -I` working
from common import utcnow, version_status, write_report


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def check(url, timeout=5):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return {"url": "rejected", "status": "requires_http_url_without_credentials_query_or_fragment"}
    row = {"url": url, "status": "unknown", "upstream_version": None}
    try:
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Brandefense-PHP-Inventory/1.0"})
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            row["http_status"] = response.status
            for key in ["X-Powered-By", "Server"]:
                match = re.search(r"PHP/(\d+\.\d+\.\d+(?:[A-Za-z][A-Za-z0-9]*)?)", response.headers.get(key, ""), re.I)
                if match:
                    row.update(version_status(match.group(1)))
                    row["version_source"] = key
                    break
            if not row["upstream_version"]:
                row["status"] = "no_version_evidence_not_proof_of_absence"
            if 300 <= response.status < 400:
                row["redirect"] = "not_followed"
    except (OSError, ValueError, urllib.error.URLError):
        row["status"] = "request_failed_tls_network_or_timeout"
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--urls", required=True, help="One authorized URL per line, max 500; no wildcards")
    p.add_argument("--output", required=True)
    a = p.parse_args()
    urls = [x.strip() for x in Path(a.urls).read_text().splitlines() if x.strip() and not x.lstrip().startswith('#')]
    if len(urls) > 500: p.error("At most 500 explicit URLs per invocation")
    result = {"observed_at": utcnow(), "scope": "HEAD_header_evidence_only", "results": [check(u) for u in urls], "limitations": ["No redirects followed; no body, cookies or full headers retained", "HEAD unsupported or header-hidden services remain unknown", "Vendor backports require independent verification", "No GET fallback, content probing or PHP/FastCGI interaction"]}
    write_report(a.output, result)


if __name__ == "__main__": main()
