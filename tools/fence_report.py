#!/usr/bin/env python3
"""Detect broken code-fence nesting in Markdown.

The only objective defect this checks for is lexical: under CommonMark a
closing fence may not carry an info string. So if a line such as ```bash is
seen while a block is already open, that line cannot close the block and the
author's intended nesting is broken. Everything after it lands in the wrong
state (parity shift): prose becomes code, headings get swallowed, and stray
fence markers leak into the rendered output.

Shell comments that start with '#' are NOT treated as headings, so this check
does not produce the false positives a heading heuristic would.

Usage:
  python3 tools/fence_report.py [skills_dir]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# ```lang  or  ~~~lang   (an opening fence: marker followed by an info string)
OPEN_FENCE = re.compile(r"^(?P<marker>`{3,}|~{3,})(?P<info>[^\s`~][^\n]*)$")
# ```   or  ~~~   (a bare closing fence)
BARE_FENCE = re.compile(r"^(?P<marker>`{3,}|~{3,})\s*$")


def analyze(path: Path) -> list[tuple[int, str]]:
    """Return (line_number, description) for every lexical fence defect."""
    return analyze_text(path.read_text(encoding="utf-8"))


def analyze_text(text: str) -> list[tuple[int, str]]:
    """Return (line_number, description) for every lexical fence defect."""
    lines = text.splitlines()
    defects: list[tuple[int, str]] = []

    open_char: str | None = None
    open_len = 0
    open_line = 0

    for number, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if open_char is None:
            opener = OPEN_FENCE.match(stripped)
            bare = BARE_FENCE.match(stripped)
            if opener:
                open_char = opener.group("marker")[0]
                open_len = len(opener.group("marker"))
                open_line = number
            elif bare:
                open_char = bare.group("marker")[0]
                open_len = len(bare.group("marker"))
                open_line = number
            continue

        # Inside a block: only a bare fence of the same char, at least as long,
        # can close it.
        closer = BARE_FENCE.match(stripped)
        if closer and closer.group("marker")[0] == open_char and len(closer.group("marker")) >= open_len:
            open_char = None
            continue

        nested = OPEN_FENCE.match(stripped)
        if (
            nested
            and nested.group("marker")[0] == open_char
            and len(nested.group("marker")) >= open_len
        ):
            defects.append(
                (
                    number,
                    f"'{stripped[:40]}' opens a nested block while the block from "
                    f"line {open_line} is still open (closing fences cannot carry "
                    f"an info string)",
                )
            )

    if open_char is not None:
        defects.append((len(lines), f"block opened at line {open_line} is never closed"))

    return defects


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "skills")
    files = sorted(root.rglob("SKILL.md"))
    total = 0
    for path in files:
        defects = analyze(path)
        if defects:
            total += len(defects)
            print(f"\n{path}")
            for number, description in defects:
                print(f"  line {number}: {description}")
    print(f"\n{len(files)} files scanned, {total} defects in {len(files)} files")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(main())
