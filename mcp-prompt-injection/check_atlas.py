"""Check the report's ATLAS mapping against MITRE's ATLAS data, not against memory.

    python3 check_atlas.py ATLAS.yaml [report.md]

ATLAS.yaml is a release file from the mitre-atlas/atlas-data repository (for example
ATLAS-2026.09.yaml from its releases page; the format-6 layout). Every `AML.T...` id in the
report's "ATLAS mapping" section must exist in that release, and the line must carry its
name as ATLAS gives it. Under a `###` heading that names an ATLAS case study (`AML.CS....`),
every id must also be one MITRE records that case study as employing. Needs PyYAML.

Exit 0: every claim holds. 1: one does not (named). 2: the file could not be read, is not
format 6, or the section holds no ids; nothing was checked.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def main(argv: list) -> int:
    if not argv:
        print(__doc__)
        return 64
    try:
        import yaml
    except ImportError:
        print("NOT EVALUABLE: PyYAML is not installed (pip install pyyaml)")
        return 2
    report = Path(argv[1] if len(argv) > 1 else Path(__file__).with_name("report.md"))
    try:
        data = yaml.safe_load(Path(argv[0]).read_text(encoding="utf-8"))
        techniques, cases, rels = data["techniques"], data["case-studies"], data["relationships"]
        version = data["collection"]["version"]
        if not isinstance(techniques, dict):
            raise TypeError("techniques is not keyed by id")
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as e:
        print(f"NOT EVALUABLE: {argv[0]} is not a format-6 ATLAS release file ({e.__class__.__name__})")
        return 2
    text = report.read_text(encoding="utf-8")
    section = text.split("## ATLAS mapping", 1)[-1].split("\n## ", 1)[0]
    case, checked, bad = None, 0, 0
    print(f"ATLAS {version}")
    for line in section.splitlines():
        if line.startswith("### "):
            m = re.search(r"AML\.CS\d{4}", line)
            case = m.group(0) if m else None
            if case and case not in cases:
                print(f"  NO  {case} is not an ATLAS case study in this release")
                bad += 1
                case = None
            elif case:
                print(f"  under {case} {cases[case]['name']}:")
            continue
        for tid in dict.fromkeys(re.findall(r"AML\.T\d{4}(?:\.\d{3})?", line)):
            checked += 1
            t = techniques.get(tid)
            if t is None:
                print(f"  NO  {tid}: not in ATLAS {version}")
                bad += 1
                continue
            problems = []
            if t["name"] not in line:
                problems.append(f"the line does not name it '{t['name']}'")
            if case:
                employed = {e["target"] for e in rels.get(case, {}).get("employs", [])}
                if tid not in employed:
                    problems.append(f"{case} does not employ it")
            bad += bool(problems)
            print(f"  {'NO ' if problems else 'ok '} {tid} {t['name']}" + (f" ({'; '.join(problems)})" if problems else ""))
    if not checked:
        print(f"NOT EVALUABLE: no ATLAS technique ids in the ATLAS mapping section of {report.name}")
        return 2
    print(f"{checked - bad} of {checked} mapping claim(s) hold")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
