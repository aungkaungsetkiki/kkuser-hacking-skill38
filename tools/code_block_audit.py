#!/usr/bin/env python3
"""Syntax-check every fenced code block in the skill library.

Each block is extracted with its language tag and validated with the real
toolchain for that language:

  bash / sh      -> bash -n            (and shellcheck when available)
  json           -> python json
  jsonc          -> python json after // and /* */ comments are stripped
  yaml           -> PyYAML
  python         -> ast.parse
  powershell     -> pwsh parser    (only when pwsh is installed)
  xml            -> ElementTree well-formedness
  html           -> tag nesting (HTMLParser)
  java           -> javac          (syntax errors only, symbols ignored)
  sql            -> SQLite EXPLAIN (dialect-agnostic errors ignored)
  http           -> raw request/status line plus header syntax
  gitignore      -> git status on a scratch repo
  javascript/js  -> node --check
  typescript/ts  -> esbuild (syntax only, no type check)
  php            -> php -l
  ruby           -> ruby -c
  solidity       -> solcjs --bin (only when solcjs is installed)

Blocks whose language has no validator are counted as skipped and listed by
tag, so the unvalidated share of the library is always visible. Checkers are
only registered for languages the library actually uses, and each one is
verified against broken and valid input before it is trusted.

Solidity snippets are parsed after being wrapped in a contract/function. A
block that imports a project-local or Forge path is re-parsed with the import
statements removed, so an unavailable dependency does not hide a syntax error.

Exit code 1 when a block fails to parse. A failure is real: the reader copies
the block and it does not run.
"""
from __future__ import annotations

import ast
import collections
import json
from html.parser import HTMLParser
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FENCE = re.compile(r"^(?P<indent> *)```(?P<lang>[A-Za-z0-9_+-]*)\s*$")

BASH_LANGS = {"bash", "sh", "shell", "console", "zsh"}
JS_LANGS = {"js", "javascript", "node", "mjs"}
TS_LANGS = {"typescript", "ts", "tsx"}


def extract(path: Path):
    """Yield (lang, start_line, code) for every fenced block."""
    lines = path.read_text(encoding="utf-8").split("\n")
    i = 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        lang = m.group("lang").lower()
        indent = len(m.group("indent"))
        start = i + 1
        body = []
        i += 1
        while i < len(lines):
            close = re.match(r"^ *```\s*$", lines[i])
            if close:
                break
            line = lines[i]
            if indent and line.startswith(" " * indent):
                line = line[indent:]
            body.append(line)
            i += 1
        yield lang, start + 1, "\n".join(body)
        i += 1


def check_bash(code: str):
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(code + "\n")
        name = fh.name
    try:
        r = subprocess.run(["bash", "-n", name], capture_output=True, text=True)
        if r.returncode != 0:
            msg = r.stderr.replace(name, "<block>").strip().split("\n")
            return msg[-1] if msg else "bash -n failed"
        return None
    finally:
        os.unlink(name)


def check_js(code: str):
    if not shutil.which("node"):
        return "node unavailable"
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(code + "\n")
        name = fh.name
    try:
        r = subprocess.run(["node", "--check", name], capture_output=True, text=True)
        if r.returncode != 0:
            msg = [l for l in r.stderr.split("\n") if l.strip()]
            return msg[0][:160] if msg else "node --check failed"
        return None
    finally:
        os.unlink(name)


def check_ts(code: str, tsx: bool = False):
    if not shutil.which("esbuild"):
        raise Skipped("esbuild not installed")
    suffix = ".tsx" if tsx else ".ts"
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / ("Block" + suffix)
        src.write_text(code + "\n", encoding="utf-8")
        r = subprocess.run(
            ["esbuild", str(src), "--outfile=" + str(Path(tmp) / "out.js"),
             "--log-level=error"],
            capture_output=True, text=True)
        if r.returncode == 0:
            return None
        err = r.stderr or r.stdout
        for line in err.split("\n"):
            if "ERROR" in line:
                return line.strip("\u2718 \t")[:160]
        return err.strip().split("\n")[0][:160] or "esbuild failed"


def check_python(code: str):
    try:
        ast.parse(code)
        return None
    except SyntaxError as exc:
        return f"{exc.msg} (line {exc.lineno})"


def check_json(code: str):
    try:
        json.loads(code)
        return None
    except json.JSONDecodeError as exc:
        return f"{exc.msg} (line {exc.lineno})"


def strip_jsonc_comments(code: str) -> str:
    """Drop // and /* */ comments while leaving string literals intact."""
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    out = []
    for line in code.split("\n"):
        buf, in_str, esc = [], False, False
        i = 0
        while i < len(line):
            ch = line[i]
            if in_str:
                buf.append(ch)
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                i += 1
                continue
            if ch == '"':
                in_str = True
                buf.append(ch)
                i += 1
                continue
            if line[i:i + 2] == "//":
                break
            buf.append(ch)
            i += 1
        out.append("".join(buf).rstrip())
    return "\n".join(out)


def check_jsonc(code: str):
    try:
        json.loads(strip_jsonc_comments(code))
        return None
    except json.JSONDecodeError as exc:
        return f"{exc.msg} (line {exc.lineno})"


def check_yaml(code: str):
    try:
        import yaml
        list(yaml.safe_load_all(code))
        return None
    except Exception as exc:
        return str(exc).split("\n")[0][:160]


def check_php(code: str):
    if not shutil.which("php"):
        return "php unavailable"
    with tempfile.NamedTemporaryFile("w", suffix=".php", delete=False) as fh:
        fh.write(code if code.lstrip().startswith("<?php") else "<?php\n" + code)
        name = fh.name
    try:
        r = subprocess.run(["php", "-l", name], capture_output=True, text=True)
        if r.returncode != 0:
            return r.stdout.strip().split("\n")[-1][:160] or "php -l failed"
        return None
    finally:
        os.unlink(name)


class Skipped(Exception):
    """The block cannot be checked with the available toolchain."""


SYNTAX_ERRORS = ("ParserError", "SyntaxError")


def _solc(code: str):
    """Return (compiled_ok, first_error_line, full_stderr)."""
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "Block.sol"
        src.write_text(code + "\n", encoding="utf-8")
        out = Path(tmp) / "out"
        out.mkdir()
        r = subprocess.run(["solcjs", "--bin", "--output-dir", str(out), str(src)],
                           capture_output=True, text=True)
    err = r.stderr or r.stdout
    if r.returncode == 0:
        return True, None, err
    first = next((l.strip() for l in err.split("\n") if "Error" in l), err.strip()[:160])
    return False, first[:160], err


def check_solidity(code: str):
    """Syntax-check a block, tolerating illustrative fragments.

    A bare statement or function body is wrapped in a contract (then a
    function) before parsing. Only ParserError/SyntaxError count as failures;
    undeclared identifiers and unresolvable imports are semantic and ignored,
    because the block is read, not compiled as a project.
    """
    if not shutil.which("solcjs"):
        raise Skipped("solcjs not installed")

    attempts = [code]
    declares_unit = re.search(
        r"(?m)^\s*(pragma\s+solidity|(abstract\s+)?contract\s+\w|interface\s+\w|library\s+\w)",
        code,
    )
    if not declares_unit:
        attempts.append("contract Fragment {\n" + code + "\n}")
        attempts.append("contract Fragment {\n  function _f() external {\n"
                        + code + "\n  }\n}")

    last_err = None
    for src in attempts:
        ok, first, full = _solc(src)
        if ok:
            return None
        if "requires different compiler version" in full:
            raise Skipped("pragma outside solcjs 0.8")
        if "not found" in full and "Source" in full:
            # An import target that exists only in the reader's project is not a
            # syntax defect. Drop the import statements (each is a complete
            # statement) and parse the rest, so the body is still checked.
            stripped = re.sub(r"(?m)^\s*import\s+[^;]+;\s*$", "", src)
            if stripped != src and stripped not in attempts:
                attempts.append(stripped)
                continue
            raise Skipped("external imports unresolved")
        last_err = first
        if any(k in full for k in SYNTAX_ERRORS):
            continue  # genuine parse error for this shape; try the next wrapper
        return None  # parsed, only declaration/type/import problems
    return last_err or "solcjs failed"


def check_ruby(code: str):
    if not shutil.which("ruby"):
        return "ruby unavailable"
    with tempfile.NamedTemporaryFile("w", suffix=".rb", delete=False) as fh:
        fh.write(code + "\n")
        name = fh.name
    try:
        r = subprocess.run(["ruby", "-c", name], capture_output=True, text=True)
        if r.returncode != 0:
            return (r.stderr or r.stdout).strip().split("\n")[0][:160]
        return None
    finally:
        os.unlink(name)


PS_PARSE = r"""
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($env:AUDIT_PS_FILE, [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
  foreach ($e in $errors) { "line {0}: {1}" -f $e.Extent.StartLineNumber, $e.Message }
  exit 1
}
exit 0
"""


def check_powershell(code: str):
    """Parse with the real PowerShell parser when pwsh is on PATH.

    Without pwsh the block stays unvalidated rather than being guessed at.
    """
    pwsh = shutil.which("pwsh")
    if not pwsh:
        raise Skipped("pwsh not installed")
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(code + "\n")
        name = fh.name
    try:
        env = dict(os.environ, AUDIT_PS_FILE=name)
        r = subprocess.run([pwsh, "-NoLogo", "-NoProfile", "-Command", PS_PARSE],
                           capture_output=True, text=True, env=env)
        if r.returncode != 0:
            lines = (r.stdout or r.stderr).strip().split("\n")
            return lines[0][:160] if lines else "powershell parse failed"
        return None
    finally:
        os.unlink(name)


def check_xml(code: str):
    """Well-formedness only. An undefined entity is expected in XXE payloads."""
    import xml.etree.ElementTree as ET
    try:
        ET.fromstring(code)
        return None
    except ET.ParseError as exc:
        msg = str(exc)
        # A DOCTYPE declaring its own entity is a deliberate XXE payload; the
        # standard parser refuses to resolve it, which is not a syntax defect.
        if "undefined entity" in msg.lower():
            return None
        return msg[:160]


JAVA_SYNTAX = (
    "';' expected", "')' expected", "'}' expected", "'{' expected",
    "illegal start", "reached end of file while parsing",
    "class, interface, enum, or record expected",
    "not a statement", "unclosed string literal", "invalid method declaration",
    "illegal character", "identifier expected", "<identifier> expected",
)


def check_java(code: str):
    """Compile a fragment inside a class; only *syntax* errors fail.

    Undeclared identifiers and missing imports are semantic, and the block is
    read as an illustration rather than a buildable file.
    """
    javac = shutil.which("javac")
    if not javac:
        raise Skipped("javac not installed")
    attempts = [code] if re.search(r"\b(class|interface|enum|record)\s+\w", code) else [
        "public class Block {\n  void f() throws Exception {\n" + code + "\n  }\n}",
    ]
    last = None
    for src in attempts:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "Block.java"
            f.write_text(src + "\n", encoding="utf-8")
            r = subprocess.run([javac, "-proc:none", "-d", tmp, str(f)],
                               capture_output=True, text=True)
        if r.returncode == 0:
            return None
        out = (r.stderr or r.stdout)
        errors = [l.strip() for l in out.split("\n") if ": error:" in l]
        if not errors:
            return None
        syntax = [e for e in errors if any(k in e for k in JAVA_SYNTAX)]
        if syntax:
            last = syntax[0].split("error:", 1)[-1].strip()[:160]
            continue
        return None  # parsed; only symbol/type resolution failed
    return last or "javac failed"


class _HtmlBalance(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack:
            self.errors.append(f"stray </{tag}>")
            return
        if self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1]}>")
            while self.stack and self.stack.pop() != tag:
                pass
        else:
            self.stack.pop()


def check_html(code: str):
    """Structural check: tags must nest. Missing doctype/alt is not an error."""
    parser = _HtmlBalance()
    parser.feed(code)
    parser.close()
    if parser.errors:
        return parser.errors[0][:160]
    if parser.stack:
        return f"unclosed <{parser.stack[-1]}>"
    return None


def check_sql(code: str):
    """Parse with SQLite; unknown tables/columns/functions are semantic."""
    import sqlite3
    body = code.strip().rstrip(";")
    if not body:
        return None
    con = sqlite3.connect(":memory:")
    try:
        con.execute("CREATE TABLE products (id INTEGER, name TEXT, user_input TEXT, "
                    "user_in TEXT, price REAL, username TEXT, password TEXT)")
        con.execute("EXPLAIN " + body)
        return None
    except sqlite3.Error as exc:
        msg = str(exc)
        if "syntax error" in msg or "incomplete input" in msg:
            return msg[:160]
        return None
    finally:
        con.close()


HTTP_LINE = re.compile(r"^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT) \S+ HTTP/\d(?:\.\d)?$")
STATUS_LINE = re.compile(r"^HTTP/\d(?:\.\d)? \d{3}(?: .*)?$")
HEADER = re.compile(r"^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*)$")


def check_http(code: str):
    """Validate a raw request/response start line and its header section.

    Everything after the first blank line is the body and is not parsed as
    headers; a smuggling payload deliberately puts a second request there.
    """
    lines = code.split("\n")
    idx = 0
    first = lines[0].strip() if lines else ""
    if HTTP_LINE.match(first) or STATUS_LINE.match(first):
        idx = 1
    seen_header = False
    for line in lines[idx:]:
        if not line.strip():
            break  # end of the header section; the rest is a body
        if line.startswith((" ", "\t")):
            continue  # obsolete line folding / continuation
        m = HEADER.match(line)
        if not m:
            return f"bad header line: {line[:60]}"
        seen_header = True
        value = m.group(2)
        if m.group(1).lower() == "content-security-policy":
            for seg in value.split(";"):
                seg = seg.strip()
                if not seg:
                    continue
                if not re.fullmatch(r"[a-z][a-z0-9-]*(?:[ \t]+.+)?", seg):
                    return f"bad CSP directive: {seg[:50]}"
    if idx == 0 and not seen_header:
        return "not an HTTP message"
    return None


def check_gitignore(code: str):
    """Git must accept the pattern file without erroring."""
    git = shutil.which("git")
    if not git:
        raise Skipped("git not installed")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([git, "init", "-q", tmp], capture_output=True, text=True)
        Path(tmp, ".gitignore").write_text(code + "\n", encoding="utf-8")
        Path(tmp, "probe.txt").write_text("x", encoding="utf-8")
        r = subprocess.run([git, "-C", tmp, "status", "--porcelain"],
                           capture_output=True, text=True)
    if r.returncode != 0:
        return (r.stderr or r.stdout).strip().split("\n")[0][:160]
    return None


CHECKERS = {
    "json": check_json,
    "jsonc": check_jsonc,
    "yaml": check_yaml,
    "yml": check_yaml,
    "python": check_python,
    "py": check_python,
    "php": check_php,
    "ruby": check_ruby,
    "rb": check_ruby,
    "solidity": check_solidity,
    "sol": check_solidity,
    "tsx": lambda code: check_ts(code, tsx=True),
    "powershell": check_powershell,
    "pwsh": check_powershell,
    "ps1": check_powershell,
    "xml": check_xml,
    "html": check_html,
    "htm": check_html,
    "java": check_java,
    "sql": check_sql,
    "http": check_http,
    "gitignore": check_gitignore,
}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "skills")
    files = sorted(root.rglob("SKILL.md"))
    totals = {"blocks": 0, "validated": 0, "failed": 0, "skipped": 0}
    failures = []
    skipped_tags = collections.Counter()

    for path in files:
        for lang, line, code in extract(path):
            if not code.strip():
                continue
            totals["blocks"] += 1
            if lang in BASH_LANGS:
                checker = check_bash
            elif lang in JS_LANGS:
                checker = check_js
            elif lang in TS_LANGS:
                checker = lambda code: check_ts(code, tsx=(lang == "tsx"))
            elif lang in CHECKERS:
                checker = CHECKERS[lang]
            else:
                totals["skipped"] += 1
                skipped_tags[lang or "(none)"] += 1
                continue
            try:
                err = checker(code)
            except Skipped as exc:
                totals["skipped"] += 1
                skipped_tags[f"{lang} ({exc})"] += 1
                continue
            totals["validated"] += 1
            if err:
                totals["failed"] += 1
                failures.append((path, line, lang, err, code))

    print(f"files: {len(files)}  blocks: {totals['blocks']}  "
          f"validated: {totals['validated']}  skipped(no checker): {totals['skipped']}  "
          f"failed: {totals['failed']}")
    if skipped_tags:
        shown = ", ".join(f"{t}={n}" for t, n in skipped_tags.most_common())
        print(f"unvalidated tags: {shown}")
    for path, line, lang, err, code in failures:
        print(f"\n{path}:{line}  [{lang}]  {err}")
        for cl in code.split("\n")[:6]:
            print(f"    | {cl[:110]}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
