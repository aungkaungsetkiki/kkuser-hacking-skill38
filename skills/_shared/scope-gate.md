# Scope Gate (shared — run before any active request)

Before the first packet leaves your machine, answer these in writing. If you cannot
answer one, you are not ready to start active testing.

## 1. The five questions

1. **Who authorized this?** Named person or written engagement reference.
2. **What exactly is in scope?** Hostnames, IP ranges, ports, API versions, mobile apps,
   repos, cloud accounts. Wildcards must be explicit (`*.example.com` includes apex?).
3. **What is out of scope?** Third-party SaaS, payment processors, shared CDNs,
   subsidiaries, employee personal accounts.
4. **What are the rules of engagement?** Testing window, max request rate, forbidden
   payload classes (destructive SQL, DoS, phishing of real staff), data handling rules.
5. **What is the escalation path?** Who to call on a production outage, on finding
   critical live data exposure, on encountering another tenant's data.

## 2. Hard stops — stop and ask immediately

- You reach data that clearly belongs to a **different tenant or unrelated customer**.
- You find **live credentials or PII** belonging to real people.
- A payload causes **service degradation** or error rates to spike.
- You discover **another attacker's** activity or a pre-existing compromise.
- The target starts returning **500s consistently** on a path you are fuzzing.

## 3. Soft stops — slow down and re-scope

- WAF starts blocking >30% of payloads → reduce rate, switch to a narrower test set.
- Authentication breaks repeatedly → verify credential format and origin before
  concluding the session expired.
- A scan produces thousands of "findings" → the wordlist or matcher is wrong. Fix the
  method before reading the results.

## 4. Environment reality check

- A cloud sandbox without a TUN device cannot join a VPN or reach a private lab.
  Use a host with native networking for those targets.
- Low-level TCP connect success in a cloud sandbox does not prove a target port is open.
  Require expected protocol behavior (HTTP response, TLS handshake, service banner).
- If the target is on localhost or a private LAN, you need a route to it. Do not assume
  the sandbox is on the same network as the operator's laptop.

## 5. Data handling

- Keep raw captures in a task-scoped directory.
- Redact `Cookie`, `Authorization`, `Set-Cookie`, API keys, and session IDs from any
  artifact you hand over or commit.
- Delete disposable brute-force output and downloaded dumps once distilled.
- Never commit a `.env`, a token file, or a client dataset into a repository.
