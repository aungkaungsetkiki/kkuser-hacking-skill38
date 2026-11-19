# SKILL.md Format Specification

Every skill in this repository follows this contract. The linter (`tools/validate_skills.py`)
enforces it; a skill that fails the linter is not merged.

## 1. Frontmatter (required)

```yaml
---
name: idor
description: 'Object-level authorization testing. Use when testing id= parameters, record fetch endpoints, GraphQL node lookups, or any path where one account reads another account''s object. Triggers: IDOR, BOLA, "id ပြောင်း", "သူများရဲ့ data".'
category: vulnerabilities
track: 02-vuln-class
tags: [idor, bola, authz, api, owasp-api1]
severity_ceiling: critical
requires: [two-test-accounts, baseline-http-capture]
tools: [curl, burp, ffuf, arjun]
cwe: CWE-639
owasp: [API1:2023, A01:2025]
version: 1.0.0
author: kkuser
source: original
---
```

### YAML quoting — mandatory

`description` **must be a single-quoted YAML scalar** because it contains `Triggers: ...`
(a colon followed by a space). An unquoted plain scalar containing `: ` is parsed by YAML as a
nested mapping and the whole frontmatter fails to load — the skill then silently never
activates.

```yaml
# WRONG — parses as a mapping, frontmatter is invalid
description: Testing X. Triggers: X, Y.

# RIGHT — single quotes, internal quotes doubled
description: 'Testing X. Triggers: X, Y, "စမ်းကြီ"'
```

Escape an internal single quote by doubling it: `'it''s'`. `tools/validate_skills.py` parses
frontmatter with PyYAML, so a malformed value fails CI instead of shipping.

### Field rules

| Field | Rule |
|---|---|
| `name` | kebab-case, must equal the directory name, ≤ 48 chars, unique across repo |
| `description` | **≤ 3 sentences**, must contain trigger words in English **and** Burmese where natural. This is what the agent reads when deciding to load the skill — it is the most important line in the file. Must be single-quoted in YAML (see above) |
| `structure` | `playbook` (default, requires the eleven sections) or `workflow` (prose methodology). Playbook tracks: 01–08 |
| `category` | one of `orchestration`, `reconnaissance`, `vulnerabilities`, `platform`, `framework`, `protocol`, `post-exploitation`, `supply-chain`, `ai-llm`, `reporting`, `opsec`, `engineering` |
| `track` | one of the twelve track names; groups the catalog. The tree is flat (`skills/<skill-id>/SKILL.md`), so the directory name is the skill id, not the track |
| `tags` | 3–6 lowercase tokens |
| `severity_ceiling` | highest severity this class can legitimately reach: `info`, `low`, `medium`, `high`, `critical` |
| `requires` | hard prerequisites. The agent must not start the technique if these are unmet. Use canonical tokens: `two-test-accounts`, `authenticated-session`, `baseline-http-capture`, `source-code-access`, `oob-listener`, `local-lab`, `write-access` |
| `tools` | tooling the technique assumes. **Not all of it is pre-installed** — skills state the install step in section 1 when a binary may be missing. Only list binaries the body actually invokes |
| `cwe` | a single specific CWE, e.g. `CWE-89`. Omit if genuinely N/A |
| `owasp` | list, e.g. `[A05:2025]` or `[API1:2023]` |
| `author` | `kkuser` |
| `source` | `original` |

## 2. Body — the eleven sections, in this order

```markdown
# <Title>

## 1. Preconditions
What must be true before the first request. Accounts, roles, network position,
captured baseline, tool availability. If unmet → stop and say what is missing.

## 2. Gate
The specific pass/fail check that proves the class is *present* before you invest in
exploitation. Usually a boolean-differential test: benign input vs hostile input must
produce observably different behavior. Write the exact two requests.

## 3. Enumeration
How to find the attack surface: endpoints, parameters, headers, parsers, sinks.
Concrete commands and wordlists, bounded.

## 4. Test Matrix
The table a competent tester fills in. Columns should make false positives impossible
(e.g. for injection: true-case / false-case / control per sink).

## 5. Proof
The minimal payload set that turns "suspicious" into "confirmed", with the exact
expected response marker. Escalation order: harmless marker → data read → state change.

## 6. Counterevidence
The alternative explanations you must rule out, and how. Caching, CDN, load balancer,
your own session, timing jitter, client-side-only filtering, mock data.

## 7. Impact
What the attacker actually gains, written in business terms, and the security boundary
crossed. Separate demonstrated from potential.

## 8. CVSS 3.1
A worked vector for the demonstrated case with one-line justification per metric.

## 9. Report
The finding text skeleton: title, affected asset, summary, steps, evidence block.

## 10. Remediation
Fix at the right layer, with a code-shaped example. Include a regression test.

## 11. References
Primary sources only: vendor advisory, RFC, OWASP page, CWE entry. No content farms.
```

## 3. Style rules

- **Burmese is welcome in `description` triggers and in operator notes.** The technical
  body stays in English so commands and payloads copy cleanly.
- Every command must be runnable as written. No `<your-target>` in a code block without
  also showing the shell variable that sets it.
- Prefer tables over prose for matrices and payload sets.
- Payloads go in fenced code blocks with the correct language tag.
- Do not paste other people's writing. Paraphrase; cite in section 11.
- Length target: **70–160 lines**. Longer is fine only when the payload tables earn it.

## 4. Anti-patterns that fail review

- A skill that lists tools but never states a pass/fail gate.
- A skill that says "test for X" without a payload.
- Severity claims that assume a chain not demonstrated in the same skill.
- Copy-pasted scanner output presented as a finding.
- Trigger words missing from `description` (the agent will never load it).
