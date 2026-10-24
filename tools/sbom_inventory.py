#!/usr/bin/env python3
"""Offline CycloneDX/SPDX JSON PHP component inventory. No registry or network calls."""
import argparse
import json
from pathlib import Path
import re
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))  # keeps `python3 -I` working
from common import utcnow, version_status, write_report


def php_component(name, purl):
    return bool(re.search(r"(?:^|[/_-])(?:php(?:[0-9.]*)?(?:$|[/_-])|lsphp[0-9.]*|libphp[0-9.]*|frankenphp|sw-engine)", name or '', re.I) or re.search(r"pkg:(?:deb|rpm|apk|generic)/[^?]*\b(?:php|lsphp|frankenphp)", purl or '', re.I))


def collect(document):
    results=[]
    def visit(components):
        for item in components:
            name=str(item.get('name') or '')
            purl=str(item.get('purl') or '')
            if php_component(name,purl):
                results.append({'name':name,'version':str(item.get('version') or ''),'purl':purl,'evidence':'sbom_component_not_running_build',**version_status(str(item.get('version') or ''))})
            visit(item.get('components') or [])
    if document.get('bomFormat')=='CycloneDX':
        visit(document.get('components') or [])
        if document.get('metadata',{}).get('component'): visit([document['metadata']['component']])
    elif str(document.get('spdxVersion','')).startswith('SPDX-'):
        for package in document.get('packages') or []:
            purls=[r.get('referenceLocator','') for r in package.get('externalRefs',[]) if r.get('referenceType')=='purl']
            name=package.get('name','')
            if php_component(name,' '.join(purls)):
                version=package.get('versionInfo','')
                results.append({'name':name,'version':version,'purl':purls,'evidence':'sbom_component_not_running_build',**version_status(version)})
    else:
        raise ValueError('Expected CycloneDX JSON or SPDX JSON')
    return results


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('sbom',nargs='+')
    p.add_argument('--output',required=True)
    a=p.parse_args()
    results,gaps=[],[]
    for filename in a.sbom:
        path=Path(filename)
        try:
            if path.stat().st_size>50*1024*1024:
                gaps.append({'path':filename,'reason':'sbom_over_50MiB_skipped'});continue
            components=collect(json.loads(path.read_text()))
            results.append({'path':filename,'components':components})
        except (OSError,ValueError,TypeError,AttributeError,RecursionError):
            gaps.append({'path':filename,'reason':'unreadable_invalid_or_unsupported_sbom'})
    write_report(a.output,{'observed_at':utcnow(),'results':results,'coverage_gaps':gaps,'limitations':['An SBOM is producer-supplied inventory, not proof of the running artifact','No matches is not proof of no PHP; SBOM completeness is unknown','Vendor backports require exact release verification','Only JSON CycloneDX/SPDX supported; external references not fetched','Application components with PHP-like names can be candidates rather than runtime packages']})


if __name__=='__main__':main()
