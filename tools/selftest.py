#!/usr/bin/env python3
"""Prove the validator actually fails on broken input.

A linter that has never been shown to fail is not evidence of anything, so each
defect class this repository has ever shipped is reproduced in a temporary
fixture and the validator must reject it. The clean copy must pass, otherwise
the fixture itself is wrong.

The fixture source is discovered, not hardcoded, so the self-test survives a
change in which skills are shipped. It picks a playbook skill (no
``structure: workflow``) that carries the eleven-section contract, a critical
ceiling, and at least one scored CVSS vector.

Usage:
  python3 tools/selftest.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

TOOLS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLS)
SKILLS = os.path.join(ROOT, "skills")

VEC = re.compile(r"(?:CVSS:3\.1/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]")
SCORED = re.compile("(" + VEC.pattern + r")\s*=\s*([0-9]+(?:\.[0-9])?)")

sys.path.insert(0, TOOLS)
from validate_skills import cvss_score  # noqa: E402


def pick_source():
    """Return (path, relative path, text) for a usable playbook skill.

    The fixture must claim a *Critical* score, otherwise the
    ``ceiling-below-cvss`` case cannot fire: lowering the ceiling to `medium`
    is only a defect when the body itself claims 9.0 or above.
    """
    candidates = []
    for dirpath, dirnames, filenames in os.walk(SKILLS):
        dirnames[:] = [d for d in dirnames if d != "_shared"]
        if "SKILL.md" not in filenames:
            continue
        path = os.path.join(dirpath, "SKILL.md")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if "structure: workflow" in text:
            continue
        if "## 8. CVSS 3.1" not in text or "## 9. Report" not in text:
            continue
        if "severity_ceiling: critical" not in text:
            continue
        scores = [cvss_score(m.group(1)) for m in SCORED.finditer(text)]
        if not scores or max(scores) < 9.0:
            continue
        candidates.append((path, text))
    if not candidates:
        raise SystemExit("no playbook skill satisfies the self-test preconditions")
    path, text = candidates[0]
    return path, os.path.relpath(path, ROOT), text


SOURCE, REL, SOURCE_TEXT = pick_source()
FIRST_SCORED = SCORED.search(SOURCE_TEXT)
FIRST_VECTOR, FIRST_SCORE = FIRST_SCORED.group(1), float(FIRST_SCORED.group(2))
WRONG_SCORE = "7.5" if abs(FIRST_SCORE - 7.5) > 0.2 else "5.3"
WRONG_SCORED = f"{FIRST_VECTOR} = {WRONG_SCORE}"


def swap_score(t: str) -> str:
    """Replace the first scored vector with a deliberately wrong score."""
    exact = f"{FIRST_VECTOR} = {FIRST_SCORED.group(2)}"
    if exact in t:
        return t.replace(exact, WRONG_SCORED, 1)
    return SCORED.sub(WRONG_SCORED, t, count=1)


CASES = [
    (
        "fence-nesting",
        lambda t: t.replace(
            "## 8. CVSS 3.1\n",
            "## 8. CVSS 3.1\n\n```markdown\nprose\n```bash\ncurl x\n```\n",
            1,
        ),
        "fence structure:",
    ),
    ("trailing-whitespace", lambda t: t.replace("\n## 9. Report", "   \n## 9. Report", 1), "trailing whitespace"),
    ("no-final-newline", lambda t: t.rstrip("\n"), "does not end with a newline"),
    (
        "ceiling-below-cvss",
        lambda t: t.replace("severity_ceiling: critical", "severity_ceiling: medium", 1),
        "is below the skill's own",
    ),
    ("wrong-cvss-score", swap_score, "does not match vector"),
    (
        "unparseable-yaml",
        lambda t: t.replace("description: '", "description: Triggers: ", 1),
        "YAML parse error",
    ),
]


def run_validator(root: str) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "validate_skills.py"), root],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout


def build_fixture(tmp: str, mutate) -> None:
    dest = os.path.join(tmp, REL)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(SOURCE, encoding="utf-8") as fh:
        text = fh.read()
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(mutate(text))
    # _shared references are resolved relative to each skill, so mirror the real tree
    shared = os.path.join(tmp, "skills", "_shared")
    if not os.path.exists(shared):
        os.symlink(os.path.join(ROOT, "skills", "_shared"), shared)


def main() -> int:
    failures = 0
    print(f"fixture: {REL}")

    with tempfile.TemporaryDirectory() as tmp:
        build_fixture(tmp, lambda t: t)
        code, out = run_validator(tmp)
        if code != 0:
            print("FAIL control: the unmodified skill does not pass")
            print(out)
            failures += 1
        else:
            print("ok   control: unmodified skill passes")

    for name, mutate, needle in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            build_fixture(tmp, mutate)
            code, out = run_validator(tmp)
            if code == 0:
                print(f"FAIL {name}: validator accepted broken input")
                failures += 1
            elif needle not in out:
                print(f"FAIL {name}: rejected, but not for the expected reason")
                print(out)
                failures += 1
            else:
                print(f"ok   {name}: rejected as expected")

    print(f"\n{len(CASES) + 1} checks, {failures} failing")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
