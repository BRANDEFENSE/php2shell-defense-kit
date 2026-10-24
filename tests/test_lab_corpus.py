"""Replay the labelled lab corpus (tests/lab-corpus/) through the Sigma rules.

These tests check rule LOGIC against real lab records and keep the published numbers (docs/lab-validation.md) from drifting.
They do not prove SIEM field mappings, production false-positive rates or exploit coverage."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "lab-corpus"
sys.path.insert(0, str(CORPUS))
import replay  # noqa: E402

LABELS = {"attack-oom", "attack-leak", "benign", "patched-graceful"}


@pytest.fixture(scope="module")
def corpus():
    return replay.load_corpus()


@pytest.fixture(scope="module")
def results():
    r = replay.run_all()
    return {x["rule"]: x for x in r["own"] + r["third_party"]}


def test_corpus_labels_and_links(corpus):
    cases, reqs, logs = corpus
    ids = {c["case"] for c in cases}
    for rows in (cases, reqs, logs):
        assert rows and all(r["label"] in LABELS for r in rows)
    assert all(r["case"] in ids for r in reqs + logs)
    for lab in LABELS:
        assert any(r["label"] == lab for r in reqs), lab
        assert any(r["label"] == lab for r in logs), lab


def test_corpus_has_no_payload_bodies(corpus):
    _, reqs, logs = corpus
    for r in reqs:
        assert "body" not in r and "payload" not in r
        assert all(len(str(v)) < 400 for v in r.values()), r["id"]
        assert len(r["field_names"]) <= 22
    assert max(len(r["line"]) for r in logs) < 600
    text = (CORPUS / "requests.jsonl").read_text() + (CORPUS / "logs.jsonl").read_text()
    assert "LAB-MARKER" not in text      # not even the synthetic marker value is stored


def test_attack_shapes_are_recorded_exactly(corpus):
    _, reqs, _ = corpus
    flood = [r for r in reqs if r["step"].startswith("GHSA-f883-007")]
    assert flood and all(r["part_header_count"] == 600001 and r["body_bytes"] == 3000063 for r in flood)
    leak = [r for r in reqs if r["scenario"] == "leak" and r["method"] == "POST"]
    assert leak and all({"PHP_SESSION_UPLOAD_PROGRESS", "PHPSESSID"} <= set(r["field_names"]) for r in leak)
    legit = [r for r in reqs if r.get("note", "").startswith("legitimate upload-progress")]
    assert legit and all("PHPSESSID" not in r["field_names"] and r["cookie_names"] == ["PHPSESSID"] for r in legit)


def test_patched_builds_still_log_the_startup_oom(results):
    s = results["php_startup_oom_fatal"]["summary"]
    assert s["attack-oom"]["occurred_cases_hit"] == s["attack-oom"]["occurred_cases"] > 0
    assert s["patched-graceful"]["cases_hit"] > 0           # documented false positive: patched builds log it too
    assert s["benign"]["events_hit"] == 0                    # the script-level OOM in the benign set has a file and line


def test_generic_memory_rule_is_narrowed_to_startup(results):
    g, s = results["php_memory_exhaustion"]["summary"], results["php_startup_oom_fatal"]["summary"]
    assert g["benign"]["events_hit"] == 0                    # was 24 of 42 benign cases before the v0.3.0 narrowing
    assert g["attack-oom"]["occurred_cases_hit"] == g["attack-oom"]["occurred_cases"] > 0
    assert g["attack-oom"]["cases_hit"] == s["attack-oom"]["cases_hit"]


def test_every_attack_oom_miss_is_a_run_without_a_memory_error(corpus, results):
    cases, _, _ = corpus
    s = results["php_startup_oom_fatal"]["summary"]["attack-oom"]
    assert s["cases_total"] - s["cases_hit"] == 46
    assert s["occurred_cases_hit"] == s["occurred_cases"]    # no rule gap: all 72 runs that logged the fatal were caught
    missed = [c for c in cases if c["label"] == "attack-oom" and c["outcome"].startswith("no-memory-error")]
    assert len(missed) == 46


def test_fpm_exit70_storm_threshold(results):
    r = results["php_fpm_child_exit_70_storm"]
    assert r["correlation"].startswith("event_count >= 5")
    s = r["summary"]
    assert s["attack-oom"]["occurred_cases_hit"] > 0
    assert s["benign"]["cases_hit"] == 0
    assert s["attack-oom"]["by_sapi"]["apache"]["hit"] == 0   # Apache workers keep running: no exit lines


def test_body_session_id_rule_is_cleaner_than_the_field_rule(results):
    a = results["http_upload_progress_field"]["summary"]
    b = results["http_upload_progress_with_body_session_id"]["summary"]
    assert a["benign"]["events_hit"] > 0                    # legitimate progress forms match the plain field rule
    levels = {x["rule"]: x["level"] for x in replay.run_all()["own"]}
    assert levels["http_upload_progress_field"] == "informational"   # hunting only, not an alert
    assert b["benign"]["events_hit"] == 0
    assert b["attack-leak"]["occurred_cases_hit"] == b["attack-leak"]["occurred_cases"] > 0


def test_multipart_flood_rule(results):
    s = results["http_multipart_flood"]["summary"]
    assert s["benign"]["events_hit"] == 0
    assert 0 < s["attack-oom"]["occurred_cases_hit"] < s["attack-oom"]["occurred_cases"]   # multipart triggers only; urlencoded ones are not covered


def test_rules_that_need_missing_telemetry_say_not_tested(results):
    for name in ("linux_web_shell", "windows_web_shell", "linux_webroot_php_write", "http_large_session_cookie", "php2shell_oversized_phpsessid"):
        assert results[name]["status"] == "not tested", name


def test_published_results_file_matches_a_fresh_replay(results):
    on_disk = json.loads((CORPUS / "sigma-replay-results.json").read_text())
    fresh = {x["rule"]: x for x in on_disk["own"] + on_disk["third_party"]}
    assert set(fresh) == set(results)
    for k, v in results.items():
        assert fresh[k] == v, k


def test_engine_result_files_exist_and_have_the_headline_numbers():
    modsec = json.loads((CORPUS / "engine-modsec-results.json").read_text())["summary"]
    assert modsec["rule id 9109623"]["attack-oom"] == {"hit": 11, "total": 11}
    assert modsec["rule id 9109623"]["benign"]["hit"] == 0
    suri = json.loads((CORPUS / "engine-suricata-results.json").read_text())["summary"]
    assert suri["sid 20260001 PHP upload progress field with body session id"]["benign"]["hit"] == 0
    zeek = json.loads((CORPUS / "engine-zeek-results.json").read_text())["notices"]
    assert sum(zeek["PHP2SHELL::Potentially_Affected_PHP_Version"].values()) == 4
    assert sum(zeek["PHP2SHELL::Multipart_Header_Flood"].values()) == 0
    yl = json.loads((CORPUS / "yara-lab-results.json").read_text())
    assert all(v.get("hits") == [] for v in yl.values())
