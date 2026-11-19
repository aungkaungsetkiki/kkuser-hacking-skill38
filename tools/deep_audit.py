#!/usr/bin/env python3
"""Deep semantic audit of the skill repository.

Goes beyond the contract linter: checks field *types*, heading hierarchy, duplicated
skills, severity-ceiling consistency against the CVSS values each skill actually
claims, trailing whitespace, CRLF, missing final newline, and the presence of the
shared-policy block. Prints every finding; exits non-zero when anything is wrong.
"""
import collections
import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(ROOT, "skills")

CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
VEC = (r"(?:CVSS:3\.1/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]"
       r"/C:[NLH]/I:[NLH]/A:[NLH]")
VEC_RE = re.compile(VEC)
SEV_ORDER = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def score(vector):
    m = dict(p.split(":") for p in vector.replace("CVSS:3.1/", "").split("/"))
    s = m["S"]
    iss = 1 - ((1 - CVSS_W["CIA"][m["C"]]) * (1 - CVSS_W["CIA"][m["I"]])
               * (1 - CVSS_W["CIA"][m["A"]]))
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    pr = (CVSS_W["PR_U"] if s == "U" else CVSS_W["PR_C"])[m["PR"]]
    exp = 8.22 * CVSS_W["AV"][m["AV"]] * CVSS_W["AC"][m["AC"]] * pr * CVSS_W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    base = min(impact + exp, 10) if s == "U" else min(1.08 * (impact + exp), 10)
    return math.ceil(base * 10) / 10


def label(x):
    return "None" if x == 0 else "Low" if x < 4 else "Medium" if x < 7 else "High" if x < 9 else "Critical"


def main():
    try:
        import yaml
    except ImportError:
        print("PyYAML required: pip install pyyaml")
        return 2

    problems = collections.defaultdict(list)
    files = []
    for dp, dn, fn in os.walk(SKILLS):
        if "_shared" in dp or "SKILL.md" not in fn:
            continue
        files.append(os.path.join(dp, fn[0] if False else "SKILL.md"))
    files.sort()

    names = collections.Counter()
    bodies = {}
    desc_lengths = []

    for p in files:
        rel = os.path.relpath(p, ROOT)
        raw = open(p, "rb").read()
        text = raw.decode("utf-8", errors="replace")
        fm = yaml.safe_load(text.split("---", 2)[1])

        # --- field types ---
        for key in ("tags", "requires", "tools", "owasp"):
            if key in fm and not isinstance(fm[key], list):
                problems["field_type"].append(f"{rel}: {key} is {type(fm[key]).__name__}, expected list")
        if not isinstance(fm.get("description"), str):
            problems["field_type"].append(f"{rel}: description is not a string")
        names[fm["name"]] += 1
        bodies[fm["name"]] = text
        desc_lengths.append((len(fm["description"]), fm["name"]))

        # --- line hygiene ---
        if b"\r\n" in raw:
            problems["crlf"].append(rel)
        if text and not text.endswith("\n"):
            problems["no_final_newline"].append(rel)
        if "\t" in text:
            problems["tab_char"].append(rel)
        trailing = [i + 1 for i, ln in enumerate(text.split("\n")) if ln != ln.rstrip()]
        if trailing:
            problems["trailing_ws"].append(f"{rel} lines {trailing[:5]}")

        # --- heading hierarchy (code fences removed: '# comment' is not a heading) ---
        stripped = re.sub(r"^```.*?^```", "", text, flags=re.M | re.S)
        levels = [(len(m.group(1)), m.group(2))
                  for m in re.finditer(r"^(#{1,6})\s+(.+)$", stripped, flags=re.M)]
        h1 = [t for lv, t in levels if lv == 1]
        if len(h1) > 1:
            problems["multiple_h1"].append(f"{rel}: {h1}")
        prev = 0
        for lv, t in levels:
            if prev and lv > prev + 1:
                problems["heading_skip"].append(f"{rel}: '{t}' h{lv} after h{prev}")
                break
            prev = lv

        # --- shared policy block ---
        if "structure: workflow" not in text and "_shared/evidence-policy.md" not in text:
            problems["no_policy_block"].append(rel)

        # --- severity ceiling vs claimed CVSS ---
        ceiling = fm.get("severity_ceiling", "high")
        claimed = [score(v) for v in VEC_RE.findall(text)]
        if claimed:
            top = max(claimed)
            if SEV_ORDER[label(top).lower()] > SEV_ORDER[ceiling]:
                problems["ceiling_too_low"].append(
                    f"{rel}: ceiling={ceiling} but skill claims {top} ({label(top)})")

    # --- duplicates ---
    for n, c in names.items():
        if c > 1:
            problems["dup_name"].append(f"{n} appears {c}x")

    # --- near-duplicate bodies (first 1500 chars equal) ---
    seen = {}
    for n, t in bodies.items():
        key = t.split("---", 2)[2][:1500]
        if key in seen:
            problems["near_dup"].append(f"{seen[key]} ~ {n}")
        seen[key] = n

    # --- report ---
    print(f"skills scanned: {len(files)}")
    desc_lengths.sort(reverse=True)
    print(f"description length: max={desc_lengths[0][0]} ({desc_lengths[0][1]}), "
          f"min={desc_lengths[-1][0]} ({desc_lengths[-1][1]})")
    print()
    total = 0
    for k in ("field_type", "dup_name", "near_dup", "multiple_h1", "heading_skip",
              "no_policy_block", "ceiling_too_low", "crlf", "no_final_newline",
              "tab_char", "trailing_ws"):
        v = problems.get(k, [])
        total += len(v)
        print(f"{k:18} : {len(v)}")
        for item in v[:12]:
            print(f"    - {item}")
    print(f"\nTOTAL PROBLEMS: {total}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
