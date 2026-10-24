#!/usr/bin/env python3
"""Compile Sigma selections to Splunk SPL. Fields and logsource routing need local mapping."""
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

ROOT=Path(__file__).resolve().parents[1]
def main():
    output=ROOT/'queries/splunk'
    output.mkdir(parents=True,exist_ok=True)
    for path in sorted((ROOT/'rules/sigma').glob('*.yml')):
        collection=SigmaCollection.from_yaml(path.read_text())
        queries=SplunkBackend().convert(collection)
        (output/(path.stem+'.spl')).write_text('\n\n'.join(queries)+'\n')
    print('Compiled selection queries; add index/sourcetype routing and field mapping before deployment.')
if __name__=='__main__': main()
