---
name: business-logic
description: 'Business logic testing for workflow bypass, state-machine abuse, price and quantity manipulation, and invariant violations in money and entitlement flows. Triggers: business logic, "ငွေရေး", "coupon", "workflow ကျော်", "logic ချိုး".'
category: vulnerabilities
track: 02-vuln-class
tags: [logic, workflow, payment, race, invariant]
severity_ceiling: critical
requires: [two-test-accounts, baseline-http-capture]
tools: [curl, agent-browser]
cwe: CWE-840
owasp: [A06:2025, API6:2023]
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.

# Business Logic

## 1. Preconditions

- The business rule, written down as a testable statement. "A coupon is usable once per
  account." "A refund cannot exceed the captured amount." Without the rule you have no bug.
- Two accounts, so per-account limits can be tested against per-actor assumptions.
- A sandbox/staging environment for money flows where available. If testing production,
  use the smallest possible amounts and never complete a real payout.
- Written confirmation that no real financial loss can occur from your tests.

## 2. Gate

The rule + the violated state, both observed:

| Cell | Action | Expected if correct |
|---|---|---|
| Control | apply the rule-conforming action | accepted once |
| Test | the rule-violating action | rejected |
| Verify | read back the state | unchanged after rejection |

**Pass:** the violating action succeeds **and** the resulting state shows the benefit
(e.g. balance +2× refund). A 200 without a state change is not a finding.

## 3. Enumeration

Write the invariant list before testing. For commerce: price is server-derived; quantity is
positive; coupon is single-use per account; refund ≤ captured; stock never negative;
currency cannot be switched post-quote; shipping cost matches the selected method.

Parameters worth mutating:

- price, amount, total, subtotal, discount, tax, fee
- quantity as `0`, `-1`, `0.0001`, `1e9`, `NaN`, `"1"` vs `1`
- currency, country, locale, shipping_method
- coupon/discount stacked with itself, or applied after the total is computed
- state fields: `status`, `paid`, `verified`, `used`, `attempts`
- ordering: skip a step, replay a step, run steps in reverse

## 4. Test Matrix

| # | Rule | Violation attempt | Observed | Verdict |
|---|---|---|---|---|
| 1 | price server-derived | send `price=0.01` | ? | |
| 2 | qty positive | `quantity=-5` | ? | |
| 3 | coupon once/account | apply twice, second via replayed request | ? | |
| 4 | refund ≤ captured | refund 2× amount | ? | |
| 5 | steps in order | POST /ship before /pay | ? | |
| 6 | currency fixed | `currency=USD` on a MMK order | ? | |
| 7 | coupon + sale | stack both | ? | |
| 8 | integer math | `quantity=0.1` × 3 | ? | |

## 5. Proof

```bash
# price tamper
curl -s -X POST https://app.example.com/api/cart/checkout \
  -H "Cookie: $A" -H 'Content-Type: application/json' \
  -d '{"sku":"X1","quantity":1,"price":0.01}' | tee /tmp/order.json

# verify the server accepted the client price
curl -s -H "Cookie: $A" https://app.example.com/api/orders/last | jq '.total'

# negative quantity
curl -s -X POST https://app.example.com/api/cart/items \
  -H "Cookie: $A" -H 'Content-Type: application/json' \
  -d '{"sku":"X1","quantity":-1}'
curl -s -H "Cookie: $A" https://app.example.com/api/cart | jq '.total'

# coupon replay: send the identical apply request twice
for i in 1 2; do
  curl -s -X POST https://app.example.com/api/coupon/apply \
    -H "Cookie: $A" -H 'Content-Type: application/json' -d '{"code":"WELCOME10"}'
done
curl -s -H "Cookie: $A" https://app.example.com/api/cart | jq '.discount'
```

Stop before any action that would move real money. Screenshot the cart/balance state as
the evidence, plus the API JSON.

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| The UI shows the tampered price but the server recomputes at payment | Complete the flow in a sandbox and check the captured amount |
| The discount is applied but capped later | Read the final order total, not the cart |
| Negative quantity is rejected at a later validation | Check the persisted cart row |
| The coupon "applied twice" only in the UI | Re-read `discount` from the API |
| Test data is mocked | Confirm with a second account and a second SKU |
| It is intended behaviour (documented promo) | Read the terms; if allowed, it is not a bug |

## 7. Impact

Quantify in business units: *"A negative quantity of −1 credits 1,000 MMK per request to the
cart; 50 requests produced a 50,000 MMK negative total, which the payment step accepted."*
If you never completed payment, say so and cap severity accordingly.

## 8. CVSS 3.1

```text
Direct financial loss demonstrated:  CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N = 6.5
Financial loss + data exposure:      CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N = 8.1
Entitlement escalation (free plan -> paid): I:H, C:N = 6.5
Logic gap with no state change:      Info / Low — do not report as High
```

## 9. Report

```markdown
# Negative quantity in cart credits balance, allowing order total manipulation

**Severity:** High (CVSS 3.1: 8.1 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)
**Affected asset:** app.example.com  POST /api/cart/items (body `quantity`)
**Category:** CWE-840 · OWASP A06:2025
```

Show the rule, the violating request, the persisted state, and the financial arithmetic.

## 10. Remediation

- Recompute all money server-side from SKU + quantity + server-side price table; ignore
  client-sent price/amount entirely.
- Validate ranges: `quantity` integer `>= 1` and `<= stock`; reject NaN/Infinity/negatives.
- Enforce state machines server-side with an allowed-transition table.
- Make coupon redemption atomic (unique constraint on `(coupon_id, account_id)`), not a
  read-then-write.
- Use integer minor units (cents) to avoid float drift.

Regression test: `quantity: -1` → 400; `price: 0.01` → server total unchanged.

## 11. References

- OWASP WSTG — Testing for Business Logic (WSTG-BUSL)
- CWE-840: Business Logic Errors
- OWASP API Security — API6:2023 Unrestricted Access to Sensitive Business Flows
