#!/usr/bin/env python3
"""Independent structural verification of rendered Markdown.

Prints the heading outline the CommonMark parser actually produces, and flags
any line that renders as a literal fence marker inside a paragraph or heading
(which is how a beta-broken fence shows up to a reader).

Usage:
  python3 tools/render_check.py FILE [--outline]
"""
from __future__ import annotations

import sys
from pathlib import Path

from markdown_it import MarkdownIt


def main() -> int:
    path = Path(sys.argv[1])
    show_outline = "--outline" in sys.argv
    text = path.read_text(encoding="utf-8")
    tokens = md.parse(text)

    headings: list[str] = []
    badges: list[str] = []
    leaks: list[str] = []
    inline_open = False

    for tok in tokens:
        if tok.type == "heading_open":
            inline_open = True
        elif tok.type == "heading_close":
            inline_open = False
        elif tok.type == "inline":
            content = tok.content
            if inline_open:
                headings.append(content)
            if "```" in content:
                leaks.append(content.strip()[:90])

    for content in headings:
        if show_outline:
            print(content)

    print(f"\nheadings: {len(headings)}")
    if leaks:
        print("fence markers leaked into rendered text:")
        for leak in leaks:
            print(f"  - {leak}")
    else:
        print("fence markers in rendered text: none")
    return 0


md = MarkdownIt("commonmark")

if __name__ == "__main__":
    raise SystemExit(main())
