"""Synthetic semantics and tool regressions. These are not exploit-effectiveness tests."""
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import yara
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression
from sigma.types import SigmaString, SigmaRegularExpression, SigmaCompareExpression, SigmaNumber

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from common import version_status, extract_settings, walk_files
from audit_inventory import audit
from inventory_linux import processes, repositories
from source_audit import scan
from http_inventory import check
from sbom_inventory import collect
from common import write_report


def evaluate(node,event):
    if isinstance(node,ConditionAND): return all(evaluate(x,event) for x in node.args)
    if isinstance(node,ConditionOR): return any(evaluate(x,event) for x in node.args)
    if isinstance(node,ConditionNOT): return not evaluate(node.args[0],event)
    if not isinstance(node,ConditionFieldEqualsValueExpression): raise AssertionError(f'Unsupported AST: {type(node)}')
    if node.field not in event: return False
    values=event[node.field] if isinstance(event[node.field],list) else [event[node.field]]
    expected=node.value
    for actual in values:
        if isinstance(expected,SigmaRegularExpression) and re.search(str(expected.regexp),str(actual)): return True
        if isinstance(expected,SigmaString) and re.fullmatch(str(expected.to_regex().regexp),str(actual),re.I): return True
        if isinstance(expected,SigmaCompareExpression):
            number=float(expected.number.number)
            op=expected.op.name
            if {'GTE':lambda:float(actual)>=number,'GT':lambda:float(actual)>number,'LTE':lambda:float(actual)<=number,'LT':lambda:float(actual)<number}[op](): return True
        if isinstance(expected,SigmaNumber) and actual==expected.number: return True
    return False


EVENTS=json.loads((ROOT/'tests/fixtures/sigma_events.json').read_text())
@pytest.mark.parametrize('sample',EVENTS,ids=[f"{i}-{x['rule']}-{x['expected']}" for i,x in enumerate(EVENTS)])
def test_sigma_fixture(sample):
    collection=SigmaCollection.from_yaml((ROOT/'rules/sigma'/f"{sample['rule']}.yml").read_text())
    assert evaluate(collection.rules[0].detection.parsed_condition[0].parsed,sample['event']) is sample['expected']


@pytest.mark.parametrize('path',list((ROOT/'rules/sigma').glob('*.yml')),ids=lambda p:p.stem)
def test_sigma_parse_and_compile(path):
    c=SigmaCollection.from_yaml(path.read_text())
    assert len(c.rules)==(2 if 'correlation:' in path.read_text() else 1) and not c.errors
    query=SplunkBackend().convert(c)
    assert query and all(isinstance(x,str) and x for x in query)
    # Missing all required telemetry cannot produce a match.
    assert not evaluate(c.rules[0].detection.parsed_condition[0].parsed,{})


@pytest.fixture(scope='session')
def yara_rules(): return yara.compile(filepath=str(ROOT/'rules/yara/php_triage.yar'),error_on_warning=True)


@pytest.mark.parametrize('sample',json.loads((ROOT/'tests/fixtures/yara_samples.json').read_text()))
def test_yara_fixture(sample,yara_rules):
    names={x.rule for x in yara_rules.match(data=sample['text'].encode())}
    assert (sample['rule'] in names) is sample['expected']


@pytest.mark.parametrize('version,status',[
 ('8.2.34','older_version_requires_vendor_verification'),('8.2.35','upstream_fix_version_candidate'),
 ('8.3.36','upstream_fix_version_candidate'),('8.4.26','older_version_requires_vendor_verification'),
 ('8.5.12','upstream_fix_version_candidate'),('8.5.12RC1','prerelease_requires_review'),
 ('1:8.3.6-0ubuntu0.24.04.13','older_version_requires_vendor_verification'),
 ('7.4.33','legacy_requires_vendor_verification_or_upgrade'),('5.3.29','unmapped_branch_requires_review'),
 ('8.6.0','unmapped_branch_requires_review'),('8.3','unknown'),('','unknown')])
def test_version_conservative(version,status): assert version_status(version)['status']==status


def test_static_config_allowlist():
    s=extract_settings(';memory_limit=32M\nmemory_limit=128M\nsession.upload_progress.enabled = Off\npassword=SECRET\n')
    assert len(s)==2 and 'SECRET' not in json.dumps(s)


def test_quoted_settings():
    assert extract_settings('session.serialize_handler = "php_serialize"')[0]['value']=='php_serialize'


def test_apache_and_fpm_settings():
    s=extract_settings('php_admin_value[memory_limit] = 128M\nphp_admin_flag session.upload_progress.enabled Off')
    assert [x['value'] for x in s]==['128M','Off']


def test_audit_does_not_claim_clean():
    result=audit({'processes':[], 'packages':[], 'configurations':[], 'coverage_gaps':[{'reason':'permission_denied'}]})
    assert result['unresolved'] and result['coverage_gaps']
    assert 'not_effective_runtime' in result['scope']


def test_audit_serializer_is_only_candidate():
    report={'configurations':[{'path':'php.ini','settings':[{'line':1,'setting':'session.serialize_handler','value':'php_serialize'}]}]}
    assert 'not CVE-2026-115560 proof' in audit(report)['findings'][0]['action']


def test_process_deleted_mapping(tmp_path):
    process=tmp_path/'123';process.mkdir()
    (process/'comm').write_text('apache2\n')
    (process/'exe').symlink_to('/usr/sbin/apache2')
    (process/'maps').write_text('000-fff r-xp 000 0:0 1 /usr/lib/apache2/modules/libphp8.3.so (deleted)\n')
    gaps=[];result=processes(tmp_path,gaps)
    assert result[0]['restart_review_required'] and result[0]['maps_visible']
    assert result[0]['running_version']=='unknown'


def test_no_symlink_traversal(tmp_path):
    root=tmp_path/'root';root.mkdir();outside=tmp_path/'outside';outside.mkdir()
    (outside/'secret.ini').write_text('secret=value')
    (root/'linked').symlink_to(outside,target_is_directory=True)
    (root/'linked.ini').symlink_to(outside/'secret.ini')
    gaps=[]
    assert not list(walk_files([root],gaps))
    assert gaps  # Skipped symlinks must not silently imply complete coverage.


def test_source_audit_outputs_no_source_text(tmp_path):
    (tmp_path/'app.php').write_text("<?php ini_set('session.serialize_handler','php'); session_start(); // PRIVATE_VALUE")
    report=scan([tmp_path])
    assert report['files'][0]['serializer_flow_review_candidate']
    assert 'PRIVATE_VALUE' not in json.dumps(report)


def test_repository_tag_candidate(tmp_path):
    (tmp_path/'Dockerfile').write_text('FROM php:8.4.26-fpm\n# deployment hint php-fpm\n')
    rows=repositories([tmp_path],[])
    assert rows[0]['status']=='older_version_requires_vendor_verification'


def test_http_rejects_sensitive_or_nonhttp_urls():
    assert check('https://user:secret@example.test/')['url']=='rejected'
    assert check('https://example.test/?token=secret')['url']=='rejected'
    assert check('file:///etc/passwd')['url']=='rejected'


def test_http_head_no_body_no_redirect():
    calls=[]
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            calls.append(self.path)
            self.send_response(302 if self.path=='/redirect' else 200)
            self.send_header('Location','/destination')
            self.send_header('X-Powered-By','PHP/8.4.26')
            self.send_header('Set-Cookie','PHPSESSID=SECRET_SESSION')
            self.end_headers()
        def log_message(self,*args): pass
    server=HTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        result=check(f'http://127.0.0.1:{server.server_port}/redirect')
        assert result['redirect']=='not_followed' and calls==['/redirect']
        assert result['upstream_version']=='8.4.26' and 'SECRET_SESSION' not in json.dumps(result)
    finally:
        server.shutdown();server.server_close();thread.join()


def test_unique_rule_ids():
    catalog=json.loads((ROOT/'rules/catalog.json').read_text())
    assert len({x['id'] for x in catalog})==len(catalog)


def test_osquery_sql_shape():
    pack=json.loads((ROOT/'queries/osquery/php_inventory.json').read_text())
    db=sqlite3.connect(':memory:')
    db.executescript('CREATE TABLE processes(pid INTEGER,parent INTEGER,name TEXT,path TEXT,uid INTEGER);CREATE TABLE listening_ports(pid INTEGER,port INTEGER,address TEXT,protocol INTEGER);CREATE TABLE process_open_sockets(pid INTEGER,remote_address TEXT,remote_port INTEGER,local_address TEXT,local_port INTEGER);')
    for item in pack['queries'].values(): db.execute(item['query']).fetchall()


def test_log_triage_redacts_content(tmp_path):
    file=tmp_path/'error.log';file.write_text('PHP Fatal error: Allowed memory size of 128 bytes exhausted token=PRIVATE_VALUE\nnormal\n')
    output=tmp_path/'leads.json'
    subprocess.run([sys.executable,str(ROOT/'tools/triage_logs.py'),str(file),'--output',str(output)],check=True)
    result=output.read_text()
    assert 'PRIVATE_VALUE' not in result and json.loads(result)['counts']['php_memory_exhaustion']==1


def test_inventory_cli_no_optional_commands(tmp_path):
    output=tmp_path/'inventory.json'
    subprocess.run([sys.executable,str(ROOT/'tools/inventory_linux.py'),'--config-root',str(tmp_path),'--output',str(output)],check=True)
    report=json.loads(output.read_text())
    assert report['containers']==[] and report['kubernetes']==[] and report['binary_probes']==[]
    assert 'coverage_gaps' in report and 'limitations' in report


def test_sbom_nested_cyclonedx():
    rows=collect({'bomFormat':'CycloneDX','components':[{'name':'base','components':[{'name':'php8.3-fpm','version':'8.3.6','purl':'pkg:deb/ubuntu/php8.3-fpm@8.3.6'}]}]})
    assert len(rows)==1 and rows[0]['status']=='older_version_requires_vendor_verification'


def test_sbom_spdx():
    rows=collect({'spdxVersion':'SPDX-2.3','packages':[{'name':'php-fpm','versionInfo':'8.4.27'},{'name':'openssl','versionInfo':'3.0.0'}]})
    assert len(rows)==1 and rows[0]['status']=='upstream_fix_version_candidate'


def test_sbom_rejects_unknown_schema():
    with pytest.raises(ValueError): collect({'components':[]})


def test_report_private_mode(tmp_path):
    path=tmp_path/'report.json';path.write_text('old');path.chmod(0o644)
    write_report(path,{'test':'private'})
    assert path.stat().st_mode & 0o777 == 0o600


def test_report_refuses_symlink(tmp_path):
    target=tmp_path/'target';target.write_text('unchanged')
    link=tmp_path/'link';link.symlink_to(target)
    with pytest.raises(OSError): write_report(link,{'test':'should_not_write'})
    assert target.read_text()=='unchanged'


def test_yara_cli_scans_inert_file(tmp_path):
    root=tmp_path/'copied';root.mkdir()
    (root/'inert.txt').write_text("<?php /* inert text fixture: fsockopen( proc_open( */")
    output=tmp_path/'yara.json'
    subprocess.run([sys.executable,str(ROOT/'tools/scan_yara.py'),str(root),'--output',str(output)],check=True)
    result=json.loads(output.read_text())
    assert result['files_scanned']==1
    assert any(x['rule']=='BD_PHP_Socket_And_Process_Primitives' for x in result['hits'])


def test_sbom_cli_outputs_only_selected_components(tmp_path):
    path=tmp_path/'sbom.json';path.write_text(json.dumps({'bomFormat':'CycloneDX','metadata':{'secret':'PRIVATE_VALUE'},'components':[{'name':'php','version':'8.4.27'}]}))
    output=tmp_path/'sbom-report.json'
    subprocess.run([sys.executable,str(ROOT/'tools/sbom_inventory.py'),str(path),'--output',str(output)],check=True)
    text=output.read_text()
    assert 'PRIVATE_VALUE' not in text
    assert len(json.loads(text)['results'][0]['components'])==1


def test_log_oversized_line_is_drained(tmp_path):
    path=tmp_path/'input.log';path.write_text('X'*2048+'\nAllowed memory size of 128 exhausted\n')
    output=tmp_path/'leads.json'
    subprocess.run([sys.executable,str(ROOT/'tools/triage_logs.py'),str(path),'--max-line-bytes','1024','--output',str(output)],check=True)
    report=json.loads(output.read_text())
    assert report['coverage_gaps'][0]['line']==1
    assert report['leads'][0]['line']==2


def test_audit_cli_keeps_unknowns(tmp_path):
    path=tmp_path/'inventory.json';path.write_text(json.dumps({'packages':[{'name':'php-fpm','version':'8.3.6','status':'older_version_requires_vendor_verification'}]}))
    output=tmp_path/'audit.json'
    subprocess.run([sys.executable,str(ROOT/'tools/audit_inventory.py'),str(path),'--output',str(output)],check=True)
    report=json.loads(output.read_text())
    assert report['unresolved'] and report['findings'][0]['status']=='older_version_requires_vendor_verification'


@pytest.mark.parametrize('tool',['audit_inventory','http_inventory','inventory_linux','sbom_inventory','scan_yara','source_audit','triage_logs'])
def test_tools_run_in_isolated_mode(tool):
    # python3 -I drops the script folder from sys.path; the tools must still import their helper.
    result=subprocess.run([sys.executable,'-I',str(ROOT/'tools'/f'{tool}.py'),'--help'],capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
