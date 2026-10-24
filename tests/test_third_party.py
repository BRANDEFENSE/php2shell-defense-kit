"""Checks that bundled third-party content is intact, licensed and syntactically valid.
These are syntax and provenance checks only; they say nothing about detection quality."""
import hashlib
import json
from pathlib import Path

import pytest
import yara
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]
TP = ROOT / 'third_party'
CATALOG = json.loads((TP / 'catalog.json').read_text())


def test_every_folder_has_license_and_source():
    folders = [p for p in TP.iterdir() if p.is_dir()]
    assert folders
    for folder in folders:
        assert (folder / 'LICENSE').is_file(), folder.name
        source = (folder / 'SOURCE.md').read_text()
        assert 'Commit fetched:' in source and 'Licence:' in source, folder.name


def test_catalog_matches_disk_and_files_unchanged():
    on_disk = {p.relative_to(ROOT).as_posix() for p in TP.rglob('*') if p.is_file() and p.name not in ('SOURCE.md', 'catalog.json')}
    assert on_disk == {x['file'] for x in CATALOG}
    for item in CATALOG:
        assert hashlib.sha256((ROOT / item['file']).read_bytes()).hexdigest() == item['sha256'], item['file']


def test_only_permissive_licences():
    assert {x['licence'] for x in CATALOG} <= {'MIT', 'BSD-3-Clause', 'CC0-1.0'}


@pytest.mark.parametrize('item', [x for x in CATALOG if x['format'] == 'sigma'], ids=lambda x: x['file'])
def test_third_party_sigma_parses(item):
    collection = SigmaCollection.from_yaml((ROOT / item['file']).read_text())
    assert len(collection.rules) == 1 and not collection.errors


@pytest.mark.parametrize('item', [x for x in CATALOG if x['format'] == 'yara'], ids=lambda x: x['file'])
def test_third_party_yara_compiles(item):
    yara.compile(filepath=str(ROOT / item['file']))


def test_third_party_sigma_ids_do_not_collide_with_ours():
    ours = {x['id'] for x in json.loads((ROOT / 'rules/catalog.json').read_text())}
    theirs = {x['sigma_id'] for x in CATALOG if x['format'] == 'sigma'}
    assert not ours & theirs
