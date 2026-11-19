---
name: idor
description: 'Object-level authorization testing (IDOR/BOLA). Use when any request names an object by id, uuid, slug, filename, or GraphQL node and the server decides access by that value. Triggers: IDOR, BOLA, "id ပြောင်း", "သူများရဲ့ data", "object id".'
category: vulnerabilities
track: 02-vuln-class
tags: [idor, bola, authz, api, owasp-api1]
severity_ceiling: critical
requires: [two-test-accounts, baseline-http-capture]
tools: [curl, ffuf, arjun]
cwe: CWE-639
owasp: [API1:2023, A01:2025]
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.
> Report skeleton: `../_shared/report-template.md`.

# IDOR / BOLA — Object-Level Authorization

## 1. Preconditions

- **Two accounts you control**, same privilege level, in the same tenant unless tenant
  isolation is the question. Call them `A` and `B`.
- Each account owns **at least one object you created yourself** with a known id, so the
  control request has an authorized positive case.
- A baseline capture of `A` fetching `A`'s object (200 + expected body).
- A comparison harness. Manual curl is fine; a loop over id ranges is faster.

If you only have one account: you can test *unauthenticated* and *cross-tenant via a
guessed id*, but you cannot prove "another user's data" — say so instead of overclaiming.

## 2. Gate

Two cells must differ. Nothing else counts.

| Cell | Request | Expected on a secure system |
|---|---|---|
| Control | `A` → `/resource/{A_obj}` | 200, A's data |
| Test | `A` → `/resource/{B_obj}` | 403 / 404 / 200 with empty or generic body |

**Pass condition (flaw present):** test cell returns 200 **and** the body contains B's
real data field values (a value only B could know).

**Fail condition (no flaw):** 403/404, or 200 with a placeholder, or 200 with exactly the
same body as the control (the server ignored the id and returned the session's object —
that is a different bug shape).

Record both status and body hash. A status-only comparison produces false positives on
SPAs that return `200 index.html` for every path.

## 3. Enumeration

Find every place an object is named:

```bash
# from proxy history, list parameter names that carry identifiers
grep -oE '[?&][A-Za-z0-9_]+=' proxy.log | sort -u

# mine ids from the app's own API traffic
grep -oE '/(users|orders|invoices|files|messages|accounts)/[A-Za-z0-9_-]{1,40}' proxy.log \
  | sort -u > object_paths.txt
```

Surfaces that carry object references and are often missed:

- JSON body fields: `{"userId": 41}`, `{"account_id": "..."}`
- Headers: `X-User-Id`, `X-Account`, `X-Tenant`
- GraphQL: `node(id: "...")`, nested resolvers, mutations taking an owner id
- Batch endpoints: `?ids=1,2,3` — one authorized id plus one foreign id
- File routes: `/download?file=`, `/export/{reportId}`, `/receipt/{orderId}.pdf`
- WebSocket subscribe frames (see `websocket-security`)
- Indirect: changing `orgId` in a path while keeping your own session

Identifier shapes and what they imply:

| Shape | Test method |
|---|---|
| Sequential int | `curl` a range; watch for 200s |
| UUIDv4 | Cannot brute force — harvest ids from other endpoints, emails, exports, referrers, JS bundles |
| UUIDv1 / ULID / Snowflake | Time-ordered: generate neighbours around a known id |
| Hashids / base64 | Decode; check if the salt is client-visible; try re-encoding a neighbour |
| Slug | Enumerate wordlists; slugs often skip auth checks that id routes enforce |

## 4. Test Matrix

Fill one row per (endpoint, verb, id-location). Attacker is always account `A`.

| # | Endpoint | Verb | Id location | Control (A→A) | Test (A→B) | Body differs? | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | /api/orders/{id} | GET | path | 200 | ? | ? | |
| 2 | /api/orders/{id} | PUT | path | 200 | ? | ? | |
| 3 | /api/users | PATCH | body `id` | 200 | ? | ? | |
| 4 | /api/files/{id}/raw | GET | path | 200 | ? | ? | |
| 5 | /api/orders?ids= | GET | query | 200 | ? | ? | |

Run the matrix for **read, write, and delete** separately. Read-only IDOR is common;
write IDOR is the one that pays. A `PUT` that returns 403 but still mutates is a finding.

## 5. Proof

Escalation order — stop at the first level that succeeds, and do not go further than the
engagement allows:

1. **Existence oracle** — different response for existing vs non-existing id (status,
   length, or timing). This alone is an info leak, not IDOR.
2. **Metadata read** — B's name, email, or object title returned.
3. **Full object read** — B's complete record.
4. **State change** — `A` modifies or deletes B's object, verified by B re-reading it.

Minimal confirmation:

```bash
BASE=https://app.example.com
A_COOKIE='<account A session>'
B_COOKIE='<account B session>'
A_ID=1001
B_ID=1002

# control: A reads A
curl -s -o a.json -w '%{http_code} %{size_download}\n' \
  -H "Cookie: $A_COOKIE" "$BASE/api/orders/$A_ID"

# test: A reads B
curl -s -o b.json -w '%{http_code} %{size_download}\n' \
  -H "Cookie: $A_COOKIE" "$BASE/api/orders/$B_ID"

# ground truth: B reads B, so you can compare field values
curl -s -o b_truth.json -w '%{http_code} %{size_download}\n' \
  -H "Cookie: $B_COOKIE" "$BASE/api/orders/$B_ID"

python3 - <<'PY'
import json
a=json.load(open('b.json')); t=json.load(open('b_truth.json'))
shared=[k for k in a if k in t and a[k]==t[k] and a[k] not in ("", None, 0)]
print("matching fields:", shared)
PY
```

The finding is confirmed when `a.json` and `b_truth.json` agree on identifying fields that
belong to B. Save all three captures.

For write IDOR, verify with the victim account, not with the attacker's response:

```bash
curl -s -X PATCH -H "Cookie: $A_COOKIE" -H 'Content-Type: application/json' \
  -d '{"status":"cancelled"}' "$BASE/api/orders/$B_ID"
curl -s -H "Cookie: $B_COOKIE" "$BASE/api/orders/$B_ID"   # B sees the change
```

## 6. Counterevidence

Rule these out before you write the finding:

| Alternative explanation | How to kill it |
|---|---|
| The "foreign" object is actually public/shared | Fetch it with **no** cookie; if it returns the same body, it is public data, not IDOR |
| The object belongs to A after all (seed data) | Check ownership in B's UI and in the DB if you have access |
| Different backend node with inconsistent state | Repeat 5× against the same URL; require stable behavior |
| The body is a generic template with no B data | Diff against a random nonexistent id; identical body = no disclosure |
| The response is cached from B's earlier request | Add `Cache-Control: no-cache` and a cache-buster query param, retest |
| GraphQL returns a stub object for any id | Query a random ULID and compare; stubs reveal nothing |
| A privileged role you did not notice | Re-test with a fresh lowest-privilege account |

If the difference disappears with a cache-buster, you found caching, not IDOR.

## 7. Impact

Write this as a sentence with numbers: *"Any authenticated user can read the full order
record — including shipping address, phone number, and line items — of any other customer
by iterating the numeric `id`; 4,182 of 5,000 sampled ids returned records belonging to
other accounts."*

Security boundary crossed: horizontal (same role, different principal). If you also
reached an admin-only object, say vertical, and prove it with the admin object's content.

Potential-but-not-demonstrated consequences (mass export, account takeover via email
change) must be labelled as such and are not part of the CVSS you assign.

## 8. CVSS 3.1

Worked example for a read-IDOR over the internet with a normal user account:

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 (Medium)
```

- AV:N — reachable over the public API
- AC:L — sequential integer, no special conditions
- PR:L — attacker needs a free registered account
- UI:N — no victim action
- S:U — same security authority
- C:H — full records of all customers demonstrated
- I:N / A:N — read only

Raise I to H only when a write was demonstrated. Raise S to C only when you crossed into
another tenant's authority boundary with proof.

## 9. Report

```markdown
# IDOR in GET /api/orders/{id} exposes any customer's order record

**Severity:** Medium (CVSS 3.1: 6.5 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Affected asset:** `app.example.com` `GET /api/orders/{id}`
**Category:** CWE-639 · OWASP API1:2023
**Status:** Confirmed   **Confidence:** High — control and test differ on a field only B owns

## Summary
Any authenticated user can retrieve any other customer's order by changing the numeric
identifier. No ownership check is performed on the session's account.

## Steps to reproduce
1. Log in as user A (id 41) and request your own order 1001 → 200.
2. Request order 1002, owned by user B (id 42) → 200 with B's address and phone.
3. Confirm ownership with user B's session.

## Evidence
<three captures: A→A, A→B, B→B>
```

## 10. Remediation

Enforce authorization **at the data layer**, not in the controller, so every path is
covered:

```python
# before: trusts the path parameter
order = db.orders.get(order_id)
return order

# after: scopes every read to the authenticated principal
order = db.orders.get(order_id, tenant_id=session.tenant_id, owner_id=session.user_id)
if order is None:
    raise NotFound()          # 404, not 403 — do not leak existence
return order
```

- Prefer server-derived scope (`WHERE owner_id = :session_user`) over a post-fetch check.
- Return **404** for foreign objects so the endpoint is not an existence oracle.
- Apply the same scope to list, export, batch, and GraphQL node resolvers.
- For genuinely shared objects, model an explicit ACL table and check it.

Regression test:

```python
def test_cannot_read_other_users_order(client, user_a, user_b, order_of_b):
    r = client.get(f"/api/orders/{order_of_b.id}", cookies=user_a.cookies)
    assert r.status_code == 404
```

## 11. References

- OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- OWASP WSTG — Testing for Insecure Direct Object References (WSTG-ATHZ-04)
