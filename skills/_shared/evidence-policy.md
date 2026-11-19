# Evidence Policy (shared — every skill inherits this)

This file is referenced by every skill in this repository. If a skill's local rules
conflict with this file, this file wins.

## 1. The three states of a claim

Every statement you make to a client or in a report must fit exactly one bucket:

| State | Meaning | Allowed in report? |
|---|---|---|
| **Observed** | Direct tool output or HTTP exchange you captured | Yes — quote it |
| **Inferred** | Reasoned from observed data, mechanism not proven | Yes — labelled as inference |
| **Unverified** | Hypothesis, scanner lead, blog claim, CVE guess | No — keep as a lead |

Never upgrade a bucket silently. "The endpoint is probably using string concatenation"
is an inference, not an observation, even when the injection works.

## 2. The proof gate

A finding is reportable only when all six hold:

1. **Affected asset** — exact host, path, method, parameter.
2. **Reproduction** — a second, independent run reproduces the same state change or disclosure.
3. **Working PoC** — a command, request block, or script that a third party can run.
4. **Demonstrated impact** — what the attacker actually obtained. Not "could lead to".
5. **Prerequisites** — required role, account, network position, user interaction.
6. **Confidence** — high / medium / low with the reason.

If any item is missing, the item is a **lead**, not a finding. Say so plainly.

## 3. Baseline vs exploit pairs (behavioral findings)

Any finding that rests on a *difference* (authorization bypass, filter bypass, cache
behavior, race window, parser differential) needs two saved captures:

- **baseline/control** — same request with the attacker's own authorized resource, or
  the benign value, showing normal behavior.
- **exploit** — the hostile request, showing the divergent behavior.

Save both. Record method, URL, relevant headers, body, status, response headers,
and timestamp. Redact cookies and tokens consistently in the shareable copy.

A response-only capture must be labelled response-only. Never reconstruct a request
you did not send and present it as a raw capture.

## 4. Counterevidence is mandatory

Before writing a finding, actively try to kill it:

- What would a defending engineer say makes this safe?
- Did I test that alternative explanation?
- Is the difference I measured actually caused by my payload, or by caching, timing,
  a different backend node, or my own session state?

Record what you checked and what remains uncertain. A finding with no counterevidence
section is rejected in review.

## 5. Scope and rate discipline

- Stay inside the declared target list. A new host discovered mid-test is a
  **question for the client**, not an automatic extension.
- Bound concurrency and pace requests. On 429/503, back off; do not increase parallelism.
- No destructive payloads (DROP, DELETE, mass-overwrite, real data exfiltration) unless
  the engagement explicitly authorizes them and a restore path exists.
- One proof is enough. Do not dump a whole table to prove SQL injection.

## 6. Severity honesty

- Score the privileges the attacker **must already hold**, not privileges gained
  through another bug in the same chain.
- `User Interaction: Required` whenever a separate human must act.
- `Scope: Changed` only when the demonstrated impact crosses a security authority
  boundary you actually crossed.
- Do not infer High confidentiality/integrity/availability impact from the
  vulnerability class. High is for demonstrated broad or critical consequence.
- Demo, lab, and intentionally-public context lowers severity. Say so.

## 7. Writing rules

- Prose in the report, payloads in code blocks, raw captures in evidence blocks.
- No placeholders in PoC code unless the value is a documented variable.
- No "could", "may", "potentially" in the impact line. Either you demonstrated it or
  you did not.
- Never invent a CVE, a CVSS vector, a screenshot path, or a scan result.
