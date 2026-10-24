"""Run the kit's YARA rules (and bundled third-party YARA) over the lab's own benign PHP application files.
MIT License, Copyright (c) 2026 Brandefense.
usage: python3 -I yara_lab.py <lab-app-dir>      The lab has no web shell or exploit artifact (no RCE reproduced),
so this measures false positives only; recall is not tested."""
import json, sys
from pathlib import Path
import yara
KIT = Path(__file__).resolve().parents[2]
files = sorted(p for p in Path(sys.argv[1]).rglob("*") if p.is_file())
out = {}
for rp in [KIT / "rules/yara/php_triage.yar"] + sorted((KIT / "third_party").rglob("*.yar")):
    try:
        r = yara.compile(filepath=str(rp))
    except yara.Error as e:
        out[str(rp.relative_to(KIT))] = {"error": str(e)[:120]}; continue
    hits = [{"file": f.name, "rule": m.rule} for f in files for m in r.match(str(f))]
    out[str(rp.relative_to(KIT))] = {"files_scanned": len(files), "hits": hits}
(Path(__file__).parent / "yara-lab-results.json").write_text(json.dumps(out, indent=1) + "\n")
print(json.dumps(out))
