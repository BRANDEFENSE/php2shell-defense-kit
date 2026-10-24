#!/usr/bin/env python3
"""Build the labelled lab corpus from the Brandefense PHP2Shell lab results.

MIT License, Copyright (c) 2026 Brandefense.

Developer/provenance tool: it needs the lab folder (not shipped in the kit). The committed outputs
(cases.jsonl, requests.jsonl, logs.jsonl, pcap-manifest.json) are what the tests and rules use.

usage: python3 -I build_corpus.py <path-to-lab-dir>

Request records hold METADATA ONLY (method, path, content type, body size, part and header counts,
field names). No request body is stored. Metadata is computed by running the lab's own body generators
(lab/http/drive.py) with the network call replaced by a recorder, so the values are exact.
"""
import hashlib, importlib.util, io, json, os, re, sys, types
from pathlib import Path

OUT = Path(__file__).resolve().parent
PATCHED = {"8.3.36", "8.4.27", "8.5.12"}
SPECIAL = ("PHP_SESSION_UPLOAD_PROGRESS", "PHPSESSID")
ATTACK_SCEN = {"hdr600k": "oom", "hdrcount": "oom", "reqparse": "oom", "progress": "oom", "nextreq": "oom", "leak": "leak"}


def load_drive(lab):
    spec = importlib.util.spec_from_file_location("labdrive", lab / "http" / "drive.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def record_requests(drive):
    """scenario -> ordered list of (method, path, body, headers, label), without sending anything."""
    rec = []

    def fake_req(method, path, body=None, headers=None, timeout=180, label=""):
        rec.append((method, path, body, dict(headers or {}), label))
        return {"label": label, "status": 200, "head": "", "_txt": "Foo Bar"}

    drive.req = fake_req
    drive.open = lambda *a, **k: io.StringIO()
    drive.os = types.SimpleNamespace(makedirs=lambda *a, **k: None, chmod=lambda *a: None, environ=os.environ, listdir=os.listdir, path=os.path)
    out = {}
    for name, fn in drive.SCEN.items():
        rec.clear()
        fn()
        out[name] = list(rec)
    return out


def meta(method, path, body, headers):
    ct = headers.get("Content-Type", "")
    base = ct.split(";")[0].strip().lower()
    r = {"method": method, "path": path.split("?")[0], "query_present": "?" in path, "content_type": base or None,
         "body_bytes": len(body) if body else 0,
         "cookie_names": sorted({c.split("=")[0].strip() for c in headers.get("Cookie", "").split(";") if "=" in c})}
    names, special = [], []
    if body and base == "multipart/form-data":
        b = re.search(r"boundary=(\S+)", ct).group(1).encode()
        parts = body.split(b"--" + b)[1:-1]
        total_hdr, maxhdr, files, seen = 0, 0, 0, set()
        for p in parts:
            head = p.split(b"\r\n\r\n", 1)[0]
            lines = [x for x in head.split(b"\r\n") if x]
            total_hdr += len(lines)
            maxhdr = max(maxhdr, len(lines))
            m = re.search(rb'name="([^"]*)"', head)
            if m:
                n = m.group(1).decode("latin1")[:60]
                if n in SPECIAL and n not in special:
                    special.append(n)
                elif n not in seen and n not in SPECIAL:
                    seen.add(n); names.append(n)
            if b"filename=" in head:
                files += 1
        r.update(multipart_boundary_len=len(b), part_count=len(parts), part_header_count=total_hdr,
                 max_headers_in_one_part=maxhdr, file_part_count=files, field_name_count=len(seen) + len(special))
    elif body and base == "application/x-www-form-urlencoded":
        pairs = body.split(b"&")
        seen, maxval, depth = set(), 0, 0
        for p in pairs:
            k, _, v = p.partition(b"=")
            maxval = max(maxval, len(v))
            depth = max(depth, k.count(b"["))
            n = k.decode("latin1")[:40]
            if len(seen) < 20:
                seen.add(n)
        names = sorted(seen)
        r.update(var_count=len(pairs), max_value_bytes=maxval, max_name_bracket_depth=depth, field_name_count=len(pairs))
    r["field_names"] = special + names[:20]
    r["field_names_truncated"] = r.get("field_name_count", 0) > len(r["field_names"])
    return r


def file_kind(line, sapi=None):
    if re.match(r"^\[\d\d-\w{3}-\d{4} [\d:]+ UTC\] PHP ", line):
        return "php_error"
    if re.match(r"^\[\d\d-\w{3}-\d{4} [\d:]+\] (NOTICE|WARNING|ERROR): ", line):
        return "fpm_master"
    if re.match(r"^\d{4}/\d\d/\d\d [\d:]+ \[", line):
        return "nginx_error"
    if sapi == "fpm" and line.startswith("mmap()"):
        return "fpm_worker"  # FPM worker stderr, not an Apache line
    if re.match(r"^\[\w{3} \w{3} \d+ [\d:.]+ \d{4}\] \[", line) or line.startswith("AH") or line.startswith("mmap()"):
        return "apache_error"
    if re.match(r"^127\.0\.0\.1 - +\d\d/", line):
        return "nginx_access"
    if re.match(r"^\S+ - - \[", line):
        return "apache_access"
    return "other"


BENIGN_LINE = re.compile(r"ready to handle connections|Command line:|resuming normal operations|apr_sockaddr_info_get|AH00558|fpm is running|"
                         r"\"GET /target\.php|exited with code 0 after|GET /leak\.php|GET /next\.php|GET /shutdown\.php")


def label_case(sapi, ver, scen):
    if scen in ATTACK_SCEN:
        return "patched-graceful" if ver in PATCHED else ("attack-leak" if ATTACK_SCEN[scen] == "leak" else "attack-oom")
    return "benign"


def main(lab):
    lab = Path(lab).resolve()
    drive = load_drive(lab)
    recorded = record_requests(drive)
    cases, reqs, logs = [], [], []
    sources = []
    for d in sorted((lab / "results" / "http").iterdir()):
        m = re.match(r"(apache|fpm)-([\d.]+)-(.*)", d.name)
        if m:
            sources.append((d, m.group(1), m.group(2), m.group(3), "http"))
    for d in sorted((lab / "results" / "capture").iterdir()):
        m = re.match(r"(apache|fpm)-([\d.]+)$", d.name)
        if m:
            sources.append((d, m.group(1), m.group(2), "none (fresh capture run)", "capture"))
    for d, sapi, ver, control, run in sources:
        for jf in sorted(d.glob("*.json")):
            scen = jf.stem.split("-", 1)[-1] if run == "capture" else jf.stem
            if scen not in recorded or jf.name.startswith("start-failed"):
                continue
            prof = jf.stem.split("-", 1)[0] if run == "capture" else ("oom" if scen in ("hdrcount", "reqparse", "progress", "nextreq", "shutdown") else "stock")
            j = json.loads(jf.read_text())
            if j.get("driver_failed"):
                continue
            cid = "%s-%s-%s-%s" % (sapi, ver, re.sub(r"[^A-Za-z0-9=.-]+", "_", control).strip("_"), scen)
            if run == "capture":
                cid += "-capture"
            case_label = label_case(sapi, ver, scen)
            php_lines = [l for l in j.get("php_error_log_new", []) if not l.startswith("...")]
            memerr = any("Allowed memory size" in l for l in php_lines)
            if run == "http":
                srv = (d / (scen + ".server.log")).read_text().splitlines() if (d / (scen + ".server.log")).exists() else []
            else:
                srv = j.get("server_log_new", [])
            srv = [l for l in srv if l.strip()]
            leaked = any(r.get("marker_in_body") for r in j["requests"]) or any("marker_in_response\":true" in r.get("head", "") for r in j["requests"])
            outcome = ("oom-fatal-logged" if memerr else "no-memory-error") if ATTACK_SCEN.get(scen) == "oom" else \
                      (("marker-leaked" if leaked else "no-leak") if scen == "leak" else "n/a")
            body_seen = " ".join(r.get("head", "") for r in j["requests"])
            if scen == "leak" and "session_global_exists" in body_seen:
                outcome = "marker-leaked" if "marker_in_response\":true" in body_seen else "no-leak"
            if any(r.get("status") == 413 for r in j["requests"]):
                outcome += "+blocked-at-frontend"
            cases.append(dict(case=cid, php_version=ver, patched=ver in PATCHED, sapi=sapi, control=control, scenario=scen,
                              profile=prof, run=run, label=case_label, outcome=outcome,
                              memory_limit="128M" if prof == "stock" else "8M"))
            # request records
            rl = recorded[scen]
            for i, rr in enumerate(j["requests"]):
                if i >= len(rl):
                    break
                method, path, body, headers, label = rl[i]
                mt = meta(method, path, body, headers)
                is_attack_shape = scen in ATTACK_SCEN and method == "POST"
                lab_ = case_label if is_attack_shape else "benign"
                note = ""
                if scen == "shutdown":
                    note = "application-level OOM inside a script (shutdown function), not request startup"
                if label.startswith("benign legitimate upload-progress"):
                    note = "legitimate upload-progress use (own session cookie, no PHPSESSID body field)"
                reqs.append(dict(id="%s#%d" % (cid, i), case=cid, label=lab_, php_version=ver, sapi=sapi, control=control,
                                 scenario=scen, step=label[:70], **mt, status=rr.get("status"), response_bytes=rr.get("resp_bytes"),
                                 seconds=rr.get("secs"), **({"note": note} if note else {})))
            # log lines
            exited = False
            seq = []
            for l in php_lines:
                seq.append(("php_error", l))
            for l in srv:
                seq.append((file_kind(l, sapi), l))
            sizes = {str(len(x[2])) for x in recorded[scen] if x[2]}
            CONSEQ = re.compile(r"exited (with code [1-9]|on signal)|too large body|readv\(\)|recv\(\)|mmap\(\)|buffered to a temporary file|Segmentation|child \d+ started|MaxRequestWorkers|exit signal")
            kept = []
            for kind, l in seq:
                m2 = re.search(r"too large body: (\d+) bytes", l)
                if m2 and m2.group(1) not in sizes:
                    continue            # late line of the previous scenario (known harness bleed)
                if (case_label == "benign" or scen == "leak") and CONSEQ.search(l) and not (scen == "leak" and "POST /leak" in l):
                    continue            # a benign case or the silent leak case has no consequence lines; anything like that is bleed
                kept.append((kind, l))
            seq = kept
            for k, (kind, l) in enumerate(seq):
                if kind == "other" and not re.search(r"Segmentation|Cannot allocate", l):
                    continue
                lab_ = case_label
                if BENIGN_LINE.search(l):
                    lab_ = "benign"
                elif kind == "php_error" and (scen == "shutdown" or "next.php" in l or "Warning" in l):
                    lab_ = "benign"
                elif "child" in l and re.search(r"child \d+ started", l):
                    lab_ = case_label if exited else "benign"
                elif case_label == "benign":
                    lab_ = "benign"
                if re.search(r"exited (with code [1-9]|on signal)", l):
                    exited = True
                row = dict(id="%s@%d" % (cid, k), case=cid, label=lab_, kind=kind, php_version=ver, sapi=sapi, control=control,
                           scenario=scen, line=l)
                if scen == "shutdown" and kind == "php_error":
                    row["note"] = "application-level OOM inside a script, not request startup"
                logs.append(row)
    for name, rows in (("cases", cases), ("requests", reqs), ("logs", logs)):
        with open(OUT / (name + ".jsonl"), "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
    pc = []
    pdir = lab / "results" / "pcap"
    if pdir.exists():
        for p in sorted(pdir.glob("*.pcap")):
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            pc.append(dict(file=p.name, bytes=p.stat().st_size, sha256=h))
    (OUT / "pcap-manifest.json").write_text(json.dumps(
        dict(note="Loopback captures taken inside the lab containers (--network none) with tcpdump. They contain the attack request bodies (synthetic data) "
                  "and stay in the lab folder, not in the kit.", pcaps=pc), indent=1) + "\n")
    from collections import Counter
    print("cases", len(cases), "requests", Counter(r["label"] for r in reqs), "logs", Counter(r["label"] for r in logs))


if __name__ == "__main__":
    main(sys.argv[1])
