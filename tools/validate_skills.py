#!/usr/bin/env python3
"""Validate every SKILL.md against the repository contract in skills/_shared/SKILL-FORMAT.md."""
import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fence_report import analyze_text  # noqa: E402

# ROOT defaults to this repository; pass a directory as argv[1] to lint another tree
# (used by the self-test that proves the linter actually fails on broken input).
ROOT = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
        else os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SKILLS = os.path.join(ROOT, "skills")

REQUIRED_FM = [
    "name", "description", "category", "track", "tags", "severity_ceiling",
    "requires", "tools", "version", "author", "source",
]
# A playbook skill must carry the eleven-section contract.
# A workflow skill (methodology, reporting, engineering) is free-form prose by design.
PLAYBOOK_TRACKS = {
    "01-recon", "02-vuln-class", "03-platform", "04-framework", "05-protocol",
    "06-post-exploitation", "07-supply-chain", "08-ai-llm",
}
VALID_CATEGORY = {
    "orchestration", "reconnaissance", "vulnerabilities", "platform", "framework",
    "protocol", "post-exploitation", "supply-chain", "ai-llm", "reporting",
    "opsec", "engineering",
}
VALID_SEV = {"info", "low", "medium", "high", "critical"}
SECTIONS = [
    "1. Preconditions", "2. Gate", "3. Enumeration", "4. Test Matrix", "5. Proof",
    "6. Counterevidence", "7. Impact", "8. CVSS 3.1", "9. Report", "10. Remediation",
    "11. References",
]
SKIP_DIRS = {"_shared"}
VALID_TRACKS = PLAYBOOK_TRACKS | {"00-orchestration", "09-reporting",
                                 "10-opsec", "99-engineering"}


def parse(path):
    """Parse frontmatter with a real YAML parser.

    An unquoted value containing ': ' (e.g. "Triggers: IDOR") makes YAML read the
    string as a nested mapping. That defect shipped once; the linter now fails on
    it instead of silently accepting a broker that OpenCode cannot read.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if not text.startswith("---"):
        return None, text, "no frontmatter"
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None, text, "unterminated frontmatter"
    raw = parts[1]
    try:
        import yaml
        loaded = yaml.safe_load(raw)
    except ImportError:
        loaded = None
    except Exception as exc:
        return None, parts[2], f"YAML parse error: {str(exc).splitlines()[0]}"
    if loaded is not None:
        if not isinstance(loaded, dict):
            return None, parts[2], "frontmatter is not a YAML mapping"
        fm = {str(k): ("" if v is None else str(v)) for k, v in loaded.items()}
        return fm, parts[2], None
    # fallback when PyYAML is unavailable
    fm = {}
    for line in raw.splitlines():
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line.rstrip())
        if m:
            fm[m.group(1)] = m.group(2).strip()
    return fm, parts[2], None


CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
VECTOR_RE = re.compile(
    r"(?:CVSS:3\.1/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]")
SCORED_RE = re.compile("(" + VECTOR_RE.pattern + r")\s*=\s*([0-9]+(?:\.[0-9])?)")
CONTROL_CHARS = {7, 8, 12, 0xFEFF} | set(range(0, 7)) | {11} | set(range(14, 32))


def cvss_score(vector):
    m = dict(p.split(":") for p in vector.replace("CVSS:3.1/", "").split("/"))
    s = m["S"]
    iss = 1 - ((1 - CVSS_W["CIA"][m["C"]]) * (1 - CVSS_W["CIA"][m["I"]]) * (1 - CVSS_W["CIA"][m["A"]]))
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    pr = (CVSS_W["PR_U"] if s == "U" else CVSS_W["PR_C"])[m["PR"]]
    exploit = 8.22 * CVSS_W["AV"][m["AV"]] * CVSS_W["AC"][m["AC"]] * pr * CVSS_W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    base = min(impact + exploit, 10) if s == "U" else min(1.08 * (impact + exploit), 10)
    return math.ceil(base * 10) / 10


def check_encoding_and_layout(path, text, body):
    errs = []
    for ch in text:
        if ord(ch) in CONTROL_CHARS:
            errs.append(f"control character U+{ord(ch):04X} present")
            break
    if "\ufffd" in text:
        errs.append("replacement character U+FFFD (encoding damage)")
    # cp1252-misread-as-latin-1 signatures, written as escapes so this file does not
    # itself contain the byte sequences it looks for.
    for seq in ("\u00c3\u00a9", "\u00c3\u00a8", "\u00e2\u20ac\u2122",
                "\u00e2\u20ac\u0153", "\u00e2\u20ac\u009d", "\u00e2\u20ac\u201c",
                "\u00e2\u20ac\u201d", "\u00e2\u2020\u2019", "\u00e2\u0153\u201c",
                "\u00e2\u0153\u2026"):
        if seq in text:
            errs.append(f"double-encoded text fragment '{seq}'")
            break
    # a BOM-prefixed frontmatter block left inside the body
    if re.search(r"\ufeff---\s*\nname:", body):
        errs.append("left-over frontmatter block inside the body")
    # broken fence nesting: a fence carrying an info string cannot close a block,
    # so seeing one inside an open block means everything after it renders wrong
    for number, description in analyze_text(text):
        errs.append(f"fence structure: line {number}: {description}")
    # trailing whitespace and final newline
    for number, line in enumerate(text.split("\n"), start=1):
        if line != line.rstrip():
            errs.append(f"trailing whitespace on line {number}")
            break
    if not text.endswith("\n"):
        errs.append("file does not end with a newline")
    # table rows that do not match the header column count (escaped pipes excluded)
    lines = text.split("\n")
    for i in range(len(lines) - 1):
        if lines[i].lstrip().startswith("|") and re.match(r"^\s*\|[\s:\-|]+\|\s*$", lines[i + 1]):
            ncol = len(re.findall(r"(?<!\\)\|", lines[i])) - 1
            j = i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                got = len(re.findall(r"(?<!\\)\|", lines[j])) - 1
                if got != ncol:
                    errs.append(f"table row {j + 1} has {got} columns, header has {ncol}")
                j += 1
    # CVSS arithmetic
    for m in SCORED_RE.finditer(text):
        vector, stated = m.group(1), float(m.group(2))
        want = cvss_score(vector)
        if abs(want - stated) > 0.049:
            errs.append(f"CVSS score {stated} does not match vector ({want}): {vector}")
    return errs


def ceiling_errors(text, ceiling):
    """The frontmatter ceiling must not be lower than the skill's own CVSS claim."""
    top = 0.0
    for m in SCORED_RE.finditer(text):
        top = max(top, float(m.group(2)))
    if top == 0.0:
        return []
    label = ("None" if top == 0 else "Low" if top < 4 else "Medium" if top < 7
             else "High" if top < 9 else "Critical")
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if order.get(ceiling, 0) < order[label.lower()]:
        return [f"severity_ceiling '{ceiling}' is below the skill's own {top} ({label}) claim"]
    return []


def check(path):
    errs = []
    fm, body, err = parse(path)
    if err:
        return [err]
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    errs.extend(check_encoding_and_layout(path, raw, body))
    d = os.path.basename(os.path.dirname(path))
    for key in REQUIRED_FM:
        if key not in fm or fm[key] == "":
            errs.append(f"missing frontmatter field: {key}")
    if fm.get("name") and fm["name"] != d:
        errs.append(f"name '{fm['name']}' != directory '{d}'")
    if fm.get("category") and fm["category"] not in VALID_CATEGORY:
        errs.append(f"invalid category: {fm['category']}")
    if fm.get("severity_ceiling") and fm["severity_ceiling"] not in VALID_SEV:
        errs.append(f"invalid severity_ceiling: {fm['severity_ceiling']}")
    elif fm.get("severity_ceiling"):
        errs.extend(ceiling_errors(raw, fm["severity_ceiling"]))
    track = fm.get("track", "")
    if track and track not in VALID_TRACKS:
        errs.append(f"invalid track: {track}")
    desc = fm.get("description", "")
    if desc.count(". ") > 2:
        errs.append("description longer than 3 sentences")
    if not re.search(r"[\u1000-\u109f]", desc):
        errs.append("description has no Burmese trigger (recommended)")
    if "Triggers:" not in desc:
        errs.append("description missing 'Triggers:' block")
    lines = len(body.splitlines())
    if lines < 40:
        errs.append(f"body too short: {lines} lines (min 40)")
    structure = fm.get("structure", "playbook")
    if structure not in ("playbook", "workflow"):
        errs.append(f"invalid structure: {structure}")
    if structure == "playbook" and track in PLAYBOOK_TRACKS:
        for s in SECTIONS:
            if f"## {s}" not in body:
                errs.append(f"missing section: ## {s}")
    # every _shared reference must resolve from this file's own directory
    here = os.path.dirname(path)
    for ref in re.findall(r"`(\.\./[^`]*_shared/[^`]+)`", body):
        if not os.path.exists(os.path.normpath(os.path.join(here, ref))):
            errs.append(f"broken _shared reference: {ref}")
    return errs


def main():
    files, failed = [], 0
    for dirpath, dirnames, filenames in os.walk(SKILLS):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if "SKILL.md" in filenames:
            files.append(os.path.join(dirpath, "SKILL.md"))
    files.sort()
    for path in files:
        errs = check(path)
        rel = os.path.relpath(path, ROOT)
        if errs:
            failed += 1
            print(f"FAIL {rel}")
            for e in errs:
                print(f"     - {e}")
        else:
            print(f"ok   {rel}")
    print(f"\n{len(files)} skills, {len(files) - failed} ok, {failed} failing")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
