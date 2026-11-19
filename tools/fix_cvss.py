#!/usr/bin/env python3
"""Recompute every CVSS 3.1 base score in the repository from its own vector.

Hand-written scores drift. This tool parses each vector, computes the score with the
CVSS 3.1 base formula (FIRST specification, including the Scope-Changed weighting and
the roundup function), then rewrites the stated score and severity label when they
disagree. It also fixes the `**Severity:** <Label> (CVSS 3.1: <n> — <vector>)` line.

Idempotent: a correct file is left byte-identical.
"""
import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(ROOT, "skills")

W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
W_AC = {"L": 0.77, "H": 0.44}
W_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
W_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
W_UI = {"N": 0.85, "R": 0.62}
W_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

VECTOR = (r"(?:CVSS:3\.1/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]"
          r"/C:[NLH]/I:[NLH]/A:[NLH]")


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def compute(vector: str) -> float:
    m = dict(p.split(":") for p in vector.replace("CVSS:3.1/", "").split("/"))
    s = m["S"]
    iss = 1 - ((1 - W_CIA[m["C"]]) * (1 - W_CIA[m["I"]]) * (1 - W_CIA[m["A"]]))
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    pr = (W_PR_U if s == "U" else W_PR_C)[m["PR"]]
    exploit = 8.22 * W_AV[m["AV"]] * W_AC[m["AC"]] * pr * W_UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if s == "U":
        base = min(impact + exploit, 10)
    else:
        base = min(1.08 * (impact + exploit), 10)
    return math.ceil(base * 10) / 10


def fmt(x: float) -> str:
    return f"{x:.1f}"


# "CVSS:3.1/AV:... = 9.3 (High)"   and bare "AV:... = 3.1"
SCORED = re.compile(r"(" + VECTOR + r")(\s*=\s*)([0-9]+(?:\.[0-9])?)(\s*\(?\s*([A-Za-z]+)?\s*\)?)")
# "**Severity:** High (CVSS 3.1: 9.3 — AV:...)"
SEVLINE = re.compile(r"(\*\*Severity:\*\*\s*)([A-Za-z]+)(\s*\(CVSS 3\.1:\s*)([0-9]+(?:\.[0-9])?)(\s*—\s*)(" + VECTOR + r")")


def process(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    original = text
    notes = []

    def repl_scored(m):
        vector, eq, stated, tail, label = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        want = compute(vector)
        if abs(want - float(stated)) <= 0.049:
            return m.group(0)
        notes.append(f"score {stated} -> {fmt(want)}  {vector}")
        new_tail = tail
        if label and label.lower() in ("none", "low", "medium", "high", "critical"):
            new_tail = tail.replace(label, severity(want), 1)
        return f"{vector}{eq}{fmt(want)}{new_tail}"

    text = SCORED.sub(repl_scored, text)

    def repl_sev(m):
        head, label, mid, stated, dash, vector = m.groups()
        want = compute(vector)
        new_label = severity(want)
        if abs(want - float(stated)) <= 0.049 and label == new_label:
            return m.group(0)
        notes.append(f"severity line {label} {stated} -> {new_label} {fmt(want)}")
        return f"{head}{new_label}{mid}{fmt(want)}{dash}{vector}"

    text = SEVLINE.sub(repl_sev, text)

    if text != original:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return notes


def main():
    files = 0
    changes = 0
    for dirpath, dirnames, filenames in os.walk(SKILLS):
        if "_shared" in dirpath or "SKILL.md" not in filenames:
            continue
        files += 1
        p = os.path.join(dirpath, "SKILL.md")
        notes = process(p)
        if notes:
            changes += len(notes)
            print(f"{os.path.relpath(p, ROOT)}")
            for n in notes:
                print(f"    {n}")
    print(f"\nscanned {files} skills, corrected {changes} values")
    return 0


if __name__ == "__main__":
    sys.exit(main())
