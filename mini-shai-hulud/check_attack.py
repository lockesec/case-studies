"""Check the report's ATT&CK mapping against MITRE's own data, not against what we remember.

    python3 check_attack.py enterprise-attack.json [report.md]

For every technique id in the report's "ATT&CK mapping" section, MITRE's bundle must hold a
`uses` relationship from S9043 (Mini Shai-Hulud) to it; and the group the report names must
use S9043. The bundle is MITRE's STIX file from the attack-stix-data repository; nothing is
bundled here, so the check is against whatever version you download, and that version is
printed. Exit 0: every id holds. Exit 1: an id MITRE does not record. Exit 2: the bundle
could not be read or does not contain S9043, so nothing was checked.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SOFTWARE, GROUP = "S9043", "G1056"


def ext_id(obj: dict) -> str | None:
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def main(argv: list) -> int:
    if not argv:
        print(__doc__)
        return 64
    report = Path(argv[1] if len(argv) > 1 else Path(__file__).with_name("report.md"))
    try:
        bundle = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        objs = bundle["objects"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"NOT EVALUABLE: {argv[0]} is not a readable ATT&CK bundle ({e.__class__.__name__})")
        return 2
    by_stix = {o["id"]: o for o in objs if "id" in o}
    by_ext = {ext_id(o): o for o in objs if ext_id(o) and not o.get("revoked")}
    version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), "?")
    sw = by_ext.get(SOFTWARE)
    if sw is None:
        print(f"NOT EVALUABLE: ATT&CK {version} has no {SOFTWARE}; it was added in July 2026")
        return 2
    used, users = set(), set()
    for o in objs:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        if o.get("source_ref") == sw["id"] and o.get("target_ref") in by_stix:
            used.add(ext_id(by_stix[o["target_ref"]]))
        if o.get("target_ref") == sw["id"] and o.get("source_ref") in by_stix:
            users.add(ext_id(by_stix[o["source_ref"]]))
    text = report.read_text(encoding="utf-8")
    section = text.split("## ATT&CK mapping", 1)[-1].split("\n## ", 1)[0]
    ids = list(dict.fromkeys(re.findall(r"(?<![\w.])T\d{4}(?:\.\d{3})?\b", section)))
    if not ids:
        print(f"NOT EVALUABLE: no technique ids found in the ATT&CK mapping section of {report.name}")
        return 2
    bad = 0
    print(f"ATT&CK {version}: {SOFTWARE} {sw.get('name')} uses {len(used)} technique(s)")
    for t in ids:
        ok = t in used
        bad += not ok
        name = by_ext.get(t, {}).get("name", "not in this version")
        print(f"  {'ok ' if ok else 'NO '} {t} {name}" + ("" if ok else f" (not recorded as used by {SOFTWARE})"))
    g = GROUP in users
    bad += not g
    print(f"  {'ok ' if g else 'NO '} {GROUP} {by_ext.get(GROUP, {}).get('name', '?')} uses {SOFTWARE}")
    print(f"{len(ids) + 1 - bad} of {len(ids) + 1} mapping claim(s) hold")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
