"""Attribute network-engine alerts (Suricata, Zeek, ModSecurity) to labelled lab requests.
MIT License, Copyright (c) 2026 Brandefense.
Developer/provenance tool (needs the lab folder). usage: python3 -I engine_map.py <lab-dir> <engine: suricata|zeek|modsec>
The lab pcaps hold one HTTP request per TCP connection, sent one after another, so the Nth connection (by time) is the
Nth request of the scenario list below. Alignment is checked against method and path before any label is assigned."""
import json, sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
SC = {"stock": ["hdr600k", "leak", "benign", "health"], "oom": ["hdrcount", "reqparse", "progress", "nextreq"]}
PCAPS = [(s, v, p) for s in ("fpm", "apache") for v in ("8.3.35", "8.3.36") for p in ("stock", "oom")]


def expected(reqs, sapi, ver, prof):
    seq = []
    for sc in SC[prof]:
        case = "%s-%s-none_fresh_capture_run-%s-capture" % (sapi, ver, sc)
        rs = sorted((r for r in reqs if r["case"] == case), key=lambda r: int(r["id"].rsplit("#", 1)[1]))
        for r in rs:
            seq.append(dict(method=r["method"], path=r["path"], label=r["label"], step=r["step"], scenario=sc))
        seq.append(dict(method="GET", path="/target.php", label="benign", step="health after scenario", scenario=sc))
    return seq


def load_reqs():
    return [json.loads(x) for x in (HERE / "requests.jsonl").read_text().splitlines()]


def summarize(hits_by_pcap, reqs):
    """hits_by_pcap: {(sapi,ver,prof): {rule: set(seq_index)}} -> {rule: {label: {hit, total}}}"""
    out = defaultdict(lambda: defaultdict(lambda: {"hit": 0, "total": 0}))
    rules = {r for h in hits_by_pcap.values() for r in h}
    for key, h in hits_by_pcap.items():
        seq = expected(reqs, *key)
        for rule in rules:
            for i, e in enumerate(seq):
                lab = e["label"]
                out[rule][lab]["total"] += 1
                out[rule][lab]["hit"] += int(i in h.get(rule, ()))
    return {r: dict(v) for r, v in out.items()}


def suricata_hits(lab):
    hits = {}
    for key in PCAPS:
        sapi, ver, prof = key
        d = lab / "results/engines/suri" / ("out-%s-%s-%s" % key)
        ev = [json.loads(x) for x in (d / "eve.json").read_text().splitlines() if x.strip()]
        start = {e["flow_id"]: e["flow"]["start"] for e in ev if e["event_type"] == "flow"}
        http = sorted((e for e in ev if e["event_type"] == "http"), key=lambda e: start[e["flow_id"]])
        seq = expected(load_reqs(), *key)
        assert len(http) == len(seq), (key, len(http), len(seq))
        idx = {}
        for i, (h, e) in enumerate(zip(http, seq)):
            assert h["http"]["http_method"] == e["method"] and h["http"]["url"].split("?")[0] == e["path"], (key, i)
            idx[h["flow_id"]] = i
        h = defaultdict(set)
        for e in ev:
            if e["event_type"] == "alert":
                a = e["alert"]
                h["sid %s %s" % (a["signature_id"], a["signature"][:90])].add(idx[e["flow_id"]])
        hits[key] = h
    return hits


def modsec_summary(lab):
    reqs = load_reqs()
    seq = expected(reqs, "fpm", "8.3.35", "stock") + expected(reqs, "fpm", "8.3.35", "oom")
    plan = json.loads((lab / "results/engines/modsec/plan.json").read_text())
    assert len(plan) == len(seq)
    for p, e in zip(plan, seq):
        assert p["method"] == e["method"] and p["path"] == e["path"], (p, e)
    hits = defaultdict(set)
    for l in (lab / "results/engines/modsec/out/audit.json").read_text().splitlines():
        t = json.loads(l)["transaction"]
        i = int(t["request"]["headers"]["X-Lab-Seq"])
        for m in t.get("messages", []):
            hits["rule id %s" % m["details"]["ruleId"]].add(i)
    res = {}
    for rid in ("20260001", "20260004", "20260006", "20260007", "20260008", "9109618", "9109619", "9109621", "9109622", "9109623"):
        hits.setdefault("rule id " + rid, set())     # the 10 rules that were loaded
    for rule, idx in hits.items():
        d = {}
        for i, e in enumerate(seq):
            x = d.setdefault(e["label"], {"hit": 0, "total": 0})
            x["total"] += 1
            x["hit"] += int(i in idx)
        res[rule] = d
    return res


if __name__ == "__main__":
    lab = Path(sys.argv[1]).resolve()
    eng = sys.argv[2]
    if eng == "modsec":
        res = modsec_summary(lab)
        (HERE / "engine-modsec-results.json").write_text(json.dumps(dict(
            engine="modsec", summary=res, note="one pass of the request sequence through ModSecurity v3.0.17 (DetectionOnly); patched requests were not separable in this pass, so no patched column is reported (see docs/lab-validation.md)"), indent=1) + "\n")
        for rule, v in sorted(res.items()):
            print(rule, {l: "%d/%d" % (x["hit"], x["total"]) for l, x in sorted(v.items())})
        sys.exit(0)
    reqs = load_reqs()
    hits = {"suricata": suricata_hits}[eng](lab)
    res = summarize(hits, reqs)
    detail = {}
    for key, h in hits.items():
        seq = expected(reqs, *key)
        for rule, idxs in h.items():
            for i in sorted(idxs):
                detail.setdefault(rule, []).append("%s-%s-%s #%d %s [%s] %s" % (*key, i, seq[i]["scenario"], seq[i]["label"], seq[i]["step"][:50]))
    out = HERE / ("engine-%s-results.json" % eng)
    out.write_text(json.dumps(dict(engine=eng, summary=res, hits=detail), indent=1) + "\n")
    for rule, v in res.items():
        print(rule, {l: "%d/%d" % (x["hit"], x["total"]) for l, x in sorted(v.items())})


def zeek_notices(lab):
    """notice type -> {pcap: count}. The Corelight package is one Zeek package, so per-notice-type counts per capture are reported (not per request)."""
    out = defaultdict(dict)
    for sapi, ver, prof in PCAPS:
        d = lab / "results/engines/zeek" / ("out-%s-%s-%s" % (sapi, ver, prof))
        n = d / "notice.log"
        types = defaultdict(int)
        if n.exists():
            rows = [l.split("\t") for l in n.read_text().splitlines() if l and not l.startswith("#")]
            for r in rows:
                types[r[10]] += 1
        for t in ("PHP2SHELL::Potentially_Affected_PHP_Version", "PHP2SHELL::Multipart_Header_Flood", "PHP2SHELL::Large_Form_Key",
                  "PHP2SHELL::PHP_Crash_Sequence", "PHP2SHELL::Serialized_Integer_Overflow"):
            out[t]["%s-%s-%s" % (sapi, ver, prof)] = types.get(t, 0)
    return out
