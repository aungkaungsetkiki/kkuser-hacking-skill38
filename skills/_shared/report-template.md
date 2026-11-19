# Finding Report Template (shared)

Use this skeleton verbatim. Sections may be empty only with an explicit
`Not tested:` / `Not applicable:` line.

```markdown
# <Short imperative title, ≤ 70 chars>

**Severity:** Critical | High | Medium | Low | Info   (CVSS 3.1: X.X — `<vector>`)
**Affected asset:** `host` `METHOD /path` (parameter: `name`)
**Category:** CWE-xxx · OWASP A0x:2025 / APIn:2023
**Status:** Confirmed | Needs validation | Ruled out
**Confidence:** High | Medium | Low — one sentence why

## Summary

Two to four sentences. What the flaw is, where it lives, what an attacker gets.
No background, no theory.

## Prerequisites

- Account/role required: ...
- Network position: ...
- User interaction: yes/no — whose, and what exactly they must do
- Pre-existing conditions: ...

## Steps to reproduce

1. Authenticate as <role> and capture the baseline request:
   ```
   GET /api/v1/orders/1001 HTTP/1.1
   Host: app.example.com
   Cookie: <redacted>
   ```
2. Change the object identifier:
   ```
   GET /api/v1/orders/1002 HTTP/1.1
   Host: app.example.com
   Cookie: <redacted>
   ```
3. Observe ...

## Evidence

```http
<verbatim request(s) and response(s), redacted consistently, with timestamp>
```

Observed result: ...
Contrast with control: ...

## Impact

Demonstrated: what was actually obtained, how much, for whom.
Potential (not demonstrated): clearly labelled.

## Root cause

Inferred unless source was read. If source was read, cite file:line.

## Remediation

Layer-appropriate fix, with a code-shaped example and a regression test.

## Counterevidence considered

- Hypothesis: ... → Tested by: ... → Result: ...

## Severity change conditions

What new evidence would raise or lower this rating.
```

## Writing the evidence block

- Keep request and response together. A lone response is labelled `Response only`.
- Redact `Cookie`, `Authorization`, `Set-Cookie`, `X-Api-Key`, session IDs, and any
  real personal data. Mark the redaction: `<Cookie: redacted>`.
- Note truncation: `[body truncated at 4 KB]`.
- Include the capture timestamp and the tool that produced it.
- If the difference is timing-based, include both timings and the number of samples.

## Forbidden in a report

- "Could potentially allow an attacker to…" in the Impact line.
- A CVSS score without a vector and per-metric justification.
- Screenshots described but not attached.
- Payloads the tester never sent.
- A CVE number that was not verified against a primary source.
