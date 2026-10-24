"""Replay the labelled lab corpus through Sigma rules with a small local matcher (no SIEM involved).

MIT License, Copyright (c) 2026 Brandefense.

Matcher: pySigma parses each rule; the parsed condition tree is evaluated against one event dict at a time.
Supported: field equals/contains/startswith/endswith/all/re/numeric compare, keyword lists (substring, any field),
and/or/not, plus event_count correlation rules (fixed to the 5-minute window used in this kit).
A rule is "not tested" when the fields it needs do not exist in the lab telemetry of its log source.
This checks rule LOGIC against REAL lab records; it does not prove a SIEM's field mapping.
"""
import datetime as dt
import json
import re
from collections import defaultdict
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression,
                              ConditionValueExpression)
from sigma.types import SigmaString, SigmaRegularExpression, SigmaCompareExpression, SigmaNumber

HERE = Path(__file__).resolve().parent
KIT = HERE.parents[1]
LABELS = ("attack-oom", "attack-leak", "benign", "patched-graceful")

LOG_KINDS_ERRORISH = ("php_error", "fpm_master", "apache_error", "nginx_error", "fpm_worker")
ACCESS = re.compile(r'"(?P<m>[A-Z]+) (?P<p>\S+)(?: HTTP/[\d.]+)?"\s+(?P<s>\d{3})')
FPM_TS = re.compile(r"^\[(\d\d-\w{3}-\d{4} [\d:]+)\]")
POOL = re.compile(r"\[pool ([^\]]+)\]")


def load_corpus():
    rd = lambda n: [json.loads(x) for x in (HERE / n).read_text().splitlines() if x.strip()]
    return rd("cases.jsonl"), rd("requests.jsonl"), rd("logs.jsonl")


def log_event(r):
    line = r["line"]
    ev = {"Message": line, "message": line, "_raw": line, "_kind": r["kind"], "host": r["case"]}
    m = POOL.search(line)
    if m:
        ev["PoolName"] = m.group(1)
    t = FPM_TS.match(line)
    if t:
        ev["_time"] = dt.datetime.strptime(t.group(1), "%d-%b-%Y %H:%M:%S")
    if r["kind"] in ("nginx_access", "apache_access"):
        a = ACCESS.search(line)
        if a:
            ev["cs-method"], ev["cs-uri-stem"], ev["sc-status"] = a["m"], a["p"], int(a["s"])
    return ev


def request_event(r):
    names = list(r.get("field_names", []))
    ev = {"cs-method": r["method"], "cs-uri-stem": r["path"], "sc-status": r.get("status"), "BodyBytes": r["body_bytes"],
          "cs-content-type": r.get("content_type"), "host": r["case"]}
    if r.get("content_type") == "multipart/form-data":
        ev["BodyParameterNames"] = names
        ev["PartHeaderCount"] = r.get("part_header_count", 0)
        ev["PartCount"] = r.get("part_count", 0)
    ev["_raw"] = "%s %s %s %s bytes=%s fields=%s" % (r["method"], r["path"], r.get("status"), r.get("content_type"), r["body_bytes"], ",".join(names))
    return ev


def build_pools(cases, reqs, logs):
    pools = defaultdict(list)  # name -> list of (case_id, label, event)
    for r in reqs:
        pools["request_records"].append((r["case"], r["label"], request_event(r)))
    for r in logs:
        ev = log_event(r)
        k = r["kind"]
        item = (r["case"], r["label"], ev)
        if k in LOG_KINDS_ERRORISH:
            pools["error_logs"].append(item)
        if k == "php_error":
            pools["php_error"].append(item)
        if k == "fpm_master":
            pools["fpm_master"].append(item)
        if k == "nginx_error":
            pools["nginx_error"].append(item)
        if k in ("nginx_access", "apache_access"):
            pools["access_lines"].append(item)
    return pools


def pool_for(rule):
    ls = rule.logsource
    prod, svc, cat = (ls.product or "").lower(), (ls.service or "").lower(), (ls.category or "").lower()
    if cat == "webserver":
        return "request_records_or_access"
    if prod == "php" and svc == "error":
        return "php_error"
    if prod == "php" and svc == "fpm":
        return "fpm_master"
    if prod == "nginx" and svc == "error":
        return "nginx_error"
    if prod in ("linux", "php") and svc in ("syslog", "php-fpm", "apache", "nginx"):
        return "error_logs"
    return None  # process_creation, file_event, windows ... : no such telemetry in the lab


NOT_TESTED = {
    "php2shell_poc_user_agent": "matches the user-agent names of public PoC tools; the lab ran no third-party PoC and its clients send no user agent",
}


# ---------------------------------------------------------------- matcher
class Unsupported(Exception):
    pass


def _vals(ev, field):
    v = ev.get(field)
    return [] if v is None else (v if isinstance(v, list) else [v])


def evaluate(node, ev):
    if isinstance(node, ConditionAND):
        return all(evaluate(x, ev) for x in node.args)
    if isinstance(node, ConditionOR):
        return any(evaluate(x, ev) for x in node.args)
    if isinstance(node, ConditionNOT):
        return not evaluate(node.args[0], ev)
    if isinstance(node, ConditionValueExpression):  # keyword
        raw = ev.get("_raw", "")
        v = node.value
        if isinstance(v, SigmaString):
            return str(v).lower() in raw.lower()
        raise Unsupported(type(v))
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        raise Unsupported(type(node))
    exp = node.value
    for a in _vals(ev, node.field):
        if isinstance(exp, SigmaRegularExpression) and re.search(str(exp.regexp), str(a)):
            return True
        if isinstance(exp, SigmaString) and re.fullmatch(str(exp.to_regex().regexp), str(a), re.I):
            return True
        if isinstance(exp, SigmaCompareExpression):
            try:
                n, f = float(exp.number.number), float(a)
            except (TypeError, ValueError):
                continue
            if {"GTE": f >= n, "GT": f > n, "LTE": f <= n, "LT": f < n}[exp.op.name]:
                return True
        if isinstance(exp, SigmaNumber) and a == exp.number:
            return True
    return False


def rule_fields(rule):
    """field names the rule needs; keyword rules need none (they read the raw text)."""
    out = set()

    def walk(n):
        if isinstance(n, ConditionFieldEqualsValueExpression):
            out.add(n.field)
        for a in getattr(n, "args", []) or []:
            walk(a)

    for p in rule.detection.parsed_condition:
        walk(p.parsed)
    return out


def load_rules(path):
    """-> (base_rule, correlation_doc or None). Our correlation files hold one base rule plus one event_count correlation."""
    text = Path(path).read_text()
    docs = [d for d in yaml.safe_load_all(text) if d]
    corr = [d for d in docs if "correlation" in d]
    base_docs = [d for d in docs if "correlation" not in d]
    coll = SigmaCollection.from_yaml("\n---\n".join(yaml.safe_dump(d) for d in base_docs))
    return coll.rules[0], (corr[0] if corr else None)


def run_rule(path, pools, cases):
    rule, corr = load_rules(path)
    pool = pool_for(rule)
    res = dict(rule=Path(path).stem, title=rule.title, source=str(Path(path).relative_to(KIT)), level=str(rule.level.name.lower()) if rule.level else None)
    if pool is None:
        res.update(status="not tested", reason="needs process or file telemetry; the lab produced none (no remote code execution reproduced)")
        return res
    if pool == "request_records_or_access":
        pool = "request_records"
    if Path(path).stem in NOT_TESTED:
        res.update(status="not tested", reason=NOT_TESTED[Path(path).stem])
        return res
    events = pools.get(pool, [])
    avail = set()
    for _, _, e in events:
        avail |= {k for k in e if not k.startswith("_")}
    fields = rule_fields(rule)
    missing = {f for f in fields if f not in avail and f not in ("Message",)}
    if missing:
        res.update(status="not tested", reason="field(s) not present in lab telemetry: " + ", ".join(sorted(missing)))
        return res
    cond = rule.detection.parsed_condition[0].parsed
    try:
        hits = [(c, l, e, evaluate(cond, e)) for c, l, e in events]
    except Unsupported as ex:
        res.update(status="not tested", reason="matcher does not support " + str(ex))
        return res
    if corr:
        window = dt.timedelta(minutes=5)
        thr = corr["correlation"]["condition"]["gte"]
        by = defaultdict(list)
        for c, l, e, h in hits:
            if h:
                by[(c, e.get("PoolName", ""))].append(e.get("_time"))
        fired_cases = set()
        for (c, _), ts in by.items():
            ts = sorted(t for t in ts if t)
            for i in range(len(ts)):
                if len([t for t in ts[i:] if t - ts[i] <= window]) >= thr:
                    fired_cases.add(c)
        res["correlation"] = "event_count >= %d in 5m per case and pool" % thr
        fired = fired_cases
        case_hit = lambda c: c in fired_cases
        ev_hit = None
    else:
        fired = {c for c, l, e, h in hits if h}
        case_hit = lambda c: c in fired
        ev_hit = True
    res["pool"] = pool
    res["fields"] = sorted(fields)
    summary = {}
    byc = {c["case"]: c for c in cases}
    for lab in LABELS:
        lc = [c for c in cases if c["label"] == lab]
        occurred = lc
        if lab == "attack-oom":
            occurred = [c for c in lc if c["outcome"] == "oom-fatal-logged"]
        if lab == "attack-leak":
            occurred = [c for c in lc if c["outcome"] == "marker-leaked"]
        ev_total = sum(1 for c, l, e, h in hits if l == lab)
        ev_h = sum(1 for c, l, e, h in hits if l == lab and h)
        s = dict(cases_total=len(lc), cases_hit=sum(1 for c in lc if case_hit(c["case"])),
                 events_total=ev_total, events_hit=ev_h if ev_hit else None)
        if lab in ("attack-oom", "attack-leak"):
            s["occurred_cases"] = len(occurred)
            s["occurred_cases_hit"] = sum(1 for c in occurred if case_hit(c["case"]))
        s["by_sapi"] = {}
        for sp in ("fpm", "apache"):
            oc = [c for c in occurred if c["sapi"] == sp]
            s["by_sapi"][sp] = dict(cases=len(oc), hit=sum(1 for c in oc if case_hit(c["case"])))
        if lab in ("attack-oom", "attack-leak"):
            bl = [c for c in lc if "blocked-at-frontend" in c["outcome"]]
            s["blocked_at_frontend_cases"] = len(bl)
            s["blocked_at_frontend_hit"] = sum(1 for c in bl if case_hit(c["case"]))
        summary[lab] = s
    res.update(status="tested", summary=summary)
    return res


def all_sigma_files():
    own = sorted((KIT / "rules/sigma").glob("*.yml"))
    third = sorted(p for p in (KIT / "third_party").rglob("*.yml") if "sigma" in p.parts and "sca" not in p.parts)
    return own, third


def run_all():
    cases, reqs, logs = load_corpus()
    pools = build_pools(cases, reqs, logs)
    own, third = all_sigma_files()
    out = dict(own=[run_rule(p, pools, cases) for p in own], third_party=[run_rule(p, pools, cases) for p in third],
               corpus=dict(cases={l: sum(1 for c in cases if c["label"] == l) for l in LABELS},
                           requests={l: sum(1 for r in reqs if r["label"] == l) for l in LABELS},
                           log_lines={l: sum(1 for r in logs if r["label"] == l) for l in LABELS}))
    return out


if __name__ == "__main__":
    import sys
    r = run_all()
    (HERE / "sigma-replay-results.json").write_text(json.dumps(r, indent=1) + "\n")
    print(json.dumps(r["corpus"]))
    for grp in ("own", "third_party"):
        for x in r[grp]:
            if x["status"] != "tested":
                print(grp, x["rule"], "NOT TESTED:", x["reason"][:80])
                continue
            s = x["summary"]
            f = lambda l: "%s/%s" % (s[l].get("occurred_cases_hit", s[l]["cases_hit"]), s[l].get("occurred_cases", s[l]["cases_total"]))
            print(grp, x["rule"], "oom", f("attack-oom"), "leak", f("attack-leak"), "patched", f("patched-graceful"),
                  "benign ev", s["benign"]["events_hit"], "/", s["benign"]["events_total"], "cases", s["benign"]["cases_hit"])
