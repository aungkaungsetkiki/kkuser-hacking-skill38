#!/usr/bin/env python3
"""Normalise trailing whitespace and final newlines in SKILL.md files.

Safety: before writing, the tool parses the file, applies the change in memory,
and re-parses. It refuses to write if the token stream shape changed, so a
meaningful Markdown hard-break cannot be silently destroyed.

Usage:
  python3 tools/normalize_whitespace.py [skills_dir] [--dry-run]
"""
from __future__ import annotations

import sys
from pathlib import Path

from markdown_it import MarkdownIt

md = MarkdownIt("commonmark")


def _lines(value: str) -> str:
    return "\n".join(line.rstrip() for line in value.split("\n"))


def shape(text: str) -> list[tuple]:
    """A comparison key that ignores trailing spaces but nothing else.

    Inline children are included so that losing a Markdown hard break (two
    trailing spaces) still registers as a change, because it removes a
    'hardbreak' child from the inline node.
    """
    key: list[tuple] = []
    for token in md.parse(text):
        children = tuple(c.type for c in (token.children or []))
        key.append((token.type, _lines(token.content or ""), children))
    return key


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "skills")
    dry_run = "--dry-run" in sys.argv
    scanned = changed = refused = 0

    for path in sorted(root.rglob("SKILL.md")):
        scanned += 1
        original = path.read_text(encoding="utf-8")
        stripped = "\n".join(line.rstrip() for line in original.split("\n"))
        if not stripped.endswith("\n"):
            stripped = stripped.rstrip("\n") + "\n"

        if stripped == original:
            continue

        if shape(original) != shape(stripped):
            refused += 1
            print(f"REFUSED (parse changed): {path}")
            continue

        changed += 1
        print(f"{'would fix' if dry_run else 'fixed'}: {path}")
        if not dry_run:
            path.write_text(stripped, encoding="utf-8")

    print(f"\n{scanned} scanned, {changed} normalised, {refused} refused")
    return 1 if refused else 0


if __name__ == "__main__":
    raise SystemExit(main())
