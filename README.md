# kkuser-hacking-skill38

**OpenCode AI agent အတွက် offensive-security skill ၃၈ ခု။**
Recon ကနေ အားနည်းချက်ရှာ၊ သက်သေပြ၊ ဆိုးကျိုးတိုင်း၊ report ရေးတဲ့အထိ တစ်ခုတည်းသော
folder ထဲမှာ အစအဆုံး ပါတယ်။

| | |
|---|---|
| **Author** | kkuser |
| **Skills** | 38 |
| **Tracks** | 10 |
| **Agents** | 4 |
| **License** | MIT |

> ⚠️ ဒီ skill တွေက **ရေးထားတဲ့ ခွင့်ပြုချက် (written authorization) ရှိတဲ့ စစ်ဆေးမှု** အတွက်ပါ။
> ကိုယ်ပိုင် lab၊ bug-bounty scope၊ engagement contract အတွင်းမှာသာ သုံးပါ။

---

## ၁။ ဒီ repo က ဘာလဲ

OpenCode က `SKILL.md` ဖိုင်တွေကို ဖတ်ပြီး "ဘယ်အလုပ်မှာ ဘယ် skill သုံးရမလဲ" ကို ကိုယ်တိုင်
ဆုံးဖြတ်တယ်။ ဒီ repo က အဲဒီ skill ၃၈ ခုကို စနစ်တကျ စုစည်းထားတာပါ —

- **နည်းစနစ် (methodology)** — engagement တစ်ခု ဘယ်လို စ၊ ဘယ်လို ဆုံးမလဲ
- **အားနည်းချက် အတန်းအစား (vulnerability class)** — SQLi, XSS, SSRF, IDOR, JWT, smuggling, business logic
- **ပလက်ဖောင်း (platform)** — cloud (AWS/Azure/GCP), Kubernetes, Web3
- **နောက်ဆက်တွဲ (post-exploitation)** — Active Directory
- **ထောက်ပံ့ရေးကွင်းဆက် (supply chain)** — dependency, CVE, API key
- **AI/LLM** — prompt injection
- **အစီရင်ခံ (reporting)** — disclosure, leak triage
- **ကိုယ်ရံတော် လုံခြုံရေး (OPSEC)** — attribution လျှော့ချခြင်း
- **အင်ဂျင်နီယာ (engineering)** — npm package, Telegram bot, WSL Kali, secret vault စသဖြင့်

Skill တစ်ခုချင်းစီမှာ **သက်သေ စည်းမျဉ်း** တူတူ ရှိတယ်: သက်သေ မရှိရင် "bug" လို့ မခေါ်ရဘူး။
အသေးစိတ်ကို `skills/_shared/evidence-policy.md` မှာ ဖတ်ပါ။

---

## ၂။ Skill ၃၈ ခု စာရင်း

### 00 — နည်းစနစ် နှင့် engagement အစီအစဉ်
| Skill | ဘာအတွက်လဲ |
|---|---|
| `red-team-web-methodology` | အဆင့် ၅ ဆင့် red-team web နည်းစနစ် အပြည့်အစုံ |
| `web-pentest` | Web pentest — exploit chain ဆက်ခြင်း၊ business-logic စစ်ခြင်း |
| `web-pentest-setup` | Engagement မစခင် workspace/proxy/scope ပြင်ဆင်ခြင်း |
| `zero-day-hunting` | Zero-day သုတေသန — source review, differential fuzzing, exploit dev |
| `bounty-deep-hunt` | Bug bounty — duplicate ကျော်ပြီး invariant ချိုးတဲ့ bug ရှာခြင်း |

### 01 — Recon
| Skill | ဘာအတွက်လဲ |
|---|---|
| `osint-recon` | Subdomain, certificate transparency, DNS history, tech fingerprint |

### 02 — အားနည်းချက် အတန်းအစား
| Skill | ဘာအတွက်လဲ |
|---|---|
| `sql-injection` | Union / error / boolean / time-blind / ORM-layer SQLi |
| `xss` | Reflected / stored / DOM XSS, sink-to-source လိုက်ခြင်း |
| `ssrf` | SSRF — cloud metadata, internal service, blind OOB |
| `idor` | Object-level authorization (IDOR/BOLA) |
| `authentication-jwt` | JWT နှင့် session/cookie flaw စစ်ခြင်း |
| `http-request-smuggling` | CL.TE / TE.CL / TE.TE smuggling |
| `business-logic` | ငွေကြေး၊ ကုဒ်ပွန်၊ အဆင့်ကျော်ခြင်း စတဲ့ logic ချို့ယွင်းချက် |
| `cookie-session-audit` | Cookie/session အစုလိုက် စစ်ခြင်း (တန်ဖိုးတွေ mask လုပ်ပြီး) |

### 03 — ပလက်ဖောင်း
| Skill | ဘာအတွက်လဲ |
|---|---|
| `cloud-exploitation` | AWS/Azure/GCP — IAM privesc, storage, metadata, serverless |
| `kubernetes` | K8s — RBAC, service account, etcd, escape path |
| `web3-security` | Smart contract — reentrancy, access control, oracle, replay |

### 06 — Post-exploitation
| Skill | ဘာအတွက်လဲ |
|---|---|
| `active-directory` | AD/Kerberos — enumeration, ACL abuse, delegation, DCSync |

### 07 — Supply chain
| Skill | ဘာအတွက်လဲ |
|---|---|
| `supply-chain` | Dependency confusion, typosquat, pipeline hijack |
| `cve-threat-intel` | Version → CVE mapping, EPSS/CVSS ဦးစားပေး စီခြင်း |
| `api-key-audit` | Bundle/repo/log ထဲက key ယိုစိမ့်မှု ရှာခြင်း |

### 08 — AI / LLM
| Skill | ဘာအတွက်လဲ |
|---|---|
| `llm-prompt-injection` | Direct/indirect prompt injection, tool abuse, exfil path |

### 09 — Reporting
| Skill | ဘာအတွက်လဲ |
|---|---|
| `disclosure-communication` | Advisory ရေးခြင်း, vendor timeline, CVE request |
| `leak-triage-and-validation` | ယိုစိမ့်ဒေတာ/stealer log စစ်ဆေးခြင်း |

### 10 — OPSEC
| Skill | ဘာအတွက်လဲ |
|---|---|
| `opsec` | Infrastructure ခွဲခြားခြင်း, identity hygiene, attribution လျှော့ချခြင်း |

### 99 — Engineering (တိုက်ခိုက်ရေး မဟုတ်)
| Skill | ဘာအတွက်လဲ |
|---|---|
| `web-security-advanced` | ကာကွယ်ရေး secure-coding နှင့် audit playbook |
| `npm-package-dev` | npm package ဖွဲ့/version/publish |
| `web-fetch-advanced` | Retry, pagination, auth flow ပါတဲ့ HTTP client |
| `telegram-bot-cloudflare` | Cloudflare Workers ပေါ် Telegram bot |
| `telegram-bot-broadcast` | Broadcast bot — subscriber, rate limit, delivery tracking |
| `real-registration` | စမ်းသပ်ပတ်ဝန်းကျင်အတွက် account/signup flow |
| `wsl-kali` | WSL2 Kali — networking, GUI, tool install |
| `web-developer` | PoC page/lab app ရေးတဲ့ web dev ပုံစံများ |
| `file-format-organizer` | ဖိုင်အစုလိုက် စီခြင်း + manifest |
| `secret-vault` | age/gpg နဲ့ local secret သိမ်းခြင်း |
| `tool-script-dev` | ပြုပြင်လွယ်တဲ့ CLI script ရေးခြင်း |
| `env-config` | `.env` အလွှာ, secret injection |
| `new-project-desktop` | Desktop project scaffold + CI |

> စက်နဲ့ ဖတ်လွယ်တဲ့ စာရင်း (severity ceiling, requires ပါ) ကို **[SKILLS.md](SKILLS.md)** မှာ ကြည့်ပါ။

---

## ၃။ တပ်ဆင်နည်း (Install)

### လိုအပ်တာ
- OpenCode (v1 သို့မဟုတ် v2 — နှစ်မျိုးလုံး အလုပ်ဖြစ်တယ်)
- `git`
- (စစ်ချင်ရင်) Python 3.9+ နှင့် `pip install pyyaml`

Skill တွေက **Markdown ဖိုင်သက်သက်** ပါ။ Build လုပ်စရာ မလိုပါ၊ npm install မလိုပါ။

### ဖွဲ့စည်းပုံ (ဘာကြောင့် ဒီပုံစံလဲ)

```
skills/
├── _shared/              ← မူဝါဒ ၄ ဖိုင် (skill မဟုတ်)
│   ├── SKILL-FORMAT.md
│   ├── evidence-policy.md
│   ├── scope-gate.md
│   └── report-template.md
├── sql-injection/SKILL.md   ← skill တစ်ခု = folder တစ်ခု
├── xss/SKILL.md
└── ... (စုစုပေါင်း ၃၈)
```

Folder နာမည်က **skill ID** ပါ။ `track:` (00-orchestration, 02-vuln-class စသဖြင့်) က
frontmatter ထဲမှာ ရှိပြီး catalog ကို အုပ်စုဖွဲ့ဖို့သာ သုံးတယ်။
ဒီပုံစံက OpenCode **v1** (`skills/*/SKILL.md` ကို တစ်ထပ်ပဲ ရှာ) နဲ့ **v2**
(folder အတွင်း ထပ်ရှာ) နှစ်မျိုးလုံးမှာ တူတူ အလုပ်ဖြစ်တယ်။

### Linux / macOS

```bash
# 1) ဆွဲချ
git clone https://github.com/aungkaungsetkiki/kkuser-hacking-skill38.git ~/kkuser-hacking-skill38

# 2) OpenCode config folder ဖန်တီး
mkdir -p ~/.config/opencode/skills ~/.config/opencode/agents

# 3) skill နဲ့ agent တွေ ကူးထည့်
cp -r ~/kkuser-hacking-skill38/skills/* ~/.config/opencode/skills/
cp -r ~/kkuser-hacking-skill38/agents/* ~/.config/opencode/agents/

# 4) စစ် — ၃၈ ဖြစ်ရမယ်
ls -d ~/.config/opencode/skills/*/SKILL.md | wc -l
```

### Windows (PowerShell)

```powershell
# 1) ဆွဲချ
git clone https://github.com/aungkaungsetkiki/kkuser-hacking-skill38.git "$HOME\kkuser-hacking-skill38"

# 2) folder ဖန်တီး + ကူးထည့်
New-Item -ItemType Directory -Force "$HOME\.config\opencode\skills"  | Out-Null
New-Item -ItemType Directory -Force "$HOME\.config\opencode\agents"  | Out-Null
Copy-Item "$HOME\kkuser-hacking-skill38\skills\*" "$HOME\.config\opencode\skills\" -Recurse -Force
Copy-Item "$HOME\kkuser-hacking-skill38\agents\*" "$HOME\.config\opencode\agents\" -Recurse -Force

# 3) စစ် — ၃၉ ဖြစ်ရမယ် (၃၈ skill + _shared)
(Get-ChildItem "$HOME\.config\opencode\skills" -Directory).Count
```

> WSL ထဲမှာ OpenCode သုံးရင် Linux နည်းလမ်းအတိုင်း လုပ်ပါ။
> Windows နဲ့ WSL မှာ config folder နှစ်ခု သီးခြား ဖြစ်တယ် — ဘယ်ဘက်မှာ သုံးလဲ ဆုံးဖြတ်ပါ။

### `opencode.jsonc` နဲ့ ချိတ်တဲ့ နည်း (မကူးဘဲ)

Skill folder ကို နေရာမရွှေ့ဘဲ config ကနေ ညွှန်လည်း ရတယ်:

**V2** (array — path နဲ့ URL ရော):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "skills": [
    "~/kkuser-hacking-skill38/skills"
  ]
}
```

**V1** (object — `paths` နဲ့ `urls` ကွဲ):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "skills": {
    "paths": ["~/kkuser-hacking-skill38/skills"]
  }
}
```

v1 မှာ ဒီ field ကို သေချာ မထောက်ပံ့နိုင်ရင် အပေါ်က ကူးထည့်တဲ့
နည်းလမ်း (၃) ကို သုံးပါ — နှစ်မျိုးလုံးမှာ အလုပ်ရတယ်။

> ဒီ repo ရဲ့ `skills/<skill-id>/SKILL.md` ပုံစံက V2 ရဲ့ တရားဝင်
grouping layout နဲ့ တူတယ်။ V2 က `.opencode/skill/` နဲ့ `.opencode/skills/`
နှစ်ခုလုံးကို ရှာတယ်။ V1 က `skills/*/SKILL.md` တစ်ထပ်ပဲ ရှာတယ်။

---

## ၄။ OpenCode မှာ သုံးနည်း

### ၄.၁ စတင် စစ်ဆေးခြင်း

```bash
opencode --version      # ဘယ် version လဲ သိရမယ်
opencode                # repo တစ်ခုခုထဲမှာ ဖွင့်
```

OpenCode က skill တွေကို **အလိုအလျောက်** ရှာတယ်။ သီးခြား enable လုပ်စရာ မလိုပါ။
Model က သင့်တောင်းဆိုချက်နဲ့ ကိုက်တဲ့ skill ကို ကိုယ်တိုင် ရွေးပြီး ဖတ်တယ်။

### ၄.၂ Skill ကို ကိုယ်တိုင် ခေါ်ခြင်း

Prompt ထဲမှာ `@` + skill ID ရိုက်ပါ:

```
@sql-injection https://lab.example.com/product?id=1 ကို စစ်ပေးပါ
```

```
@idor /api/invoices/1001 — account A နဲ့ account B နှစ်ခု ရှိတယ်
```

```
@active-directory 10.10.10.0/24 lab အတွက် enumeration အစီအစဉ် ချပေးပါ
```

Skill တစ်ခုကို ခေါ်လိုက်ရင် သူ့ရဲ့ လမ်းညွှန်ချက်တွေ ကို context ထဲ ထည့်ပေးတယ်။
ပြီးရင် သူ့အဆင့်တွေအတိုင်း အလုပ်လုပ်တယ်။

### ၄.၃ Agent ရွေးခြင်း

ဒီ repo မှာ agent ၄ ခု ပါတယ် (`agents/` folder):

| Agent | mode | ဘာအတွက် |
|---|---|---|
| `red-team-lead` | primary | တိုက်ခိုက်မှု တစ်ခုလုံး ကိုင် — "စစ်လိုက်", "ဖောက်" |
| `recon-lead` | subagent | ပစ်မှတ် စာရင်း တည်ဆောက်ခြင်း |
| `vuln-validator` | subagent | "ဒါ တကယ်လား" — false positive ရှင်းခြင်း |
| `report-writer` | subagent | Client-grade report ရေးခြင်း |

**Agent တပ်ပြီလား စစ်ရန်:**

```bash
opencode agent list     # သင့် agent ID ၄ ခု ပေါ်ရမယ်
```

**အသုံးပြုနည်း:**

- **OpenCode V1** — primary agent တွေကို **`Tab`** ခလုတ်နဲ့ လှည့်တယ်။
  subagent တွေကို `@` နဲ့ ခေါ်တယ် — ဥပမာ `@vuln-validator ဒါ စစ်ပေး`။
- **OpenCode V2** — `opencode.jsonc` မှာ `"default_agent": "red-team-lead"` လို့ သတ်မှတ်တယ်။
  subagent ကို primary agent က ကိုယ်တိုင် ခေါ်တယ်: "use the vuln-validator subagent to …"။

> Agent ဖိုင်တွေက **V1 frontmatter** (`permission:` map, `temperature:`) သုံးတယ်။
> V2 က V1 frontmatter ကို အလိုအလျောက် ဘာသာပြန်တယ် — ဒါကြောင့် V1/V2 နှစ်မျိုးလုံး အလုပ်ဖြစ်တယ်။
> `temperature` က V2 မှာ အာနိသင် မရှိဘူး (model variant မှာ သတ်မှတ်ရတယ်) — ဒါက error မဟုတ်ပါ။

### ၄.၄ လက်တွေ့ အလုပ်စဉ် ဥပမာ

```
1) @web-pentest-setup   → workspace ပြင် (scope.txt, evidence/ folder)
2) @osint-recon         → ပစ်မှတ် စာရင်း
3) @web-pentest         → hypothesis ဆွဲ၊ စမ်းသပ်
4) @sql-injection       → တိကျတဲ့ class ကို နက်နက်ရှိုင်းရှိုင်း စစ်
5) @vuln-validator      → ရလာတဲ့ finding ကို ချိုးကြည့် (မချိုးနိုင်မှ report)
6) @report-writer       → report ရေး
```

### ၄.၅ Skill မပေါ်ရင် စစ်ရန် (Troubleshooting)

```bash
# ၁။ ဖိုင် နာမည် SKILL.md (အကြီးစာလုံး အတိ) ဟုတ်လား
ls ~/.config/opencode/skills/sql-injection/SKILL.md

# ၂။ frontmatter မှာ name နဲ့ description ရှိလား
head -5 ~/.config/opencode/skills/sql-injection/SKILL.md

# ၃။ ID က folder နာမည်ကနေ ဆင်းသက်တယ် (frontmatter name မဟုတ်)
ls ~/.config/opencode/skills
```

အများဆုံး တွေ့ရတဲ့ အကြောင်းရင်း ၄ ခု:

1. **Folder နှစ်ထပ် ဖြစ်နေတယ်** — `skills/02-vuln-class/sql-injection/SKILL.md` ဆိုရင်
   v1 မှာ မတွေ့ဘူး။ ဒီ repo က flat (`skills/sql-injection/SKILL.md`) ဖြစ်လို့
   `cp -r skills/* ...` လုပ်ရင် မှန်တယ်။
2. **`description` မရှိ** — description မပါတဲ့ skill ကို model ကို မကြော်ငြာဘူး။
   ဒီ repo မှာ ၃၈ ခုလုံး ပါတယ်။
3. **Permission က deny** — `opencode.json` ရဲ့ `permission.skill` မှာ စစ်ပါ။
4. **ID ထပ်** — တခြား source မှာ အလားတူ ID ရှိရင် နောက်က တစ်ခုက လွှမ်းတယ်။

Skill တစ်ခုကို model ကို မ​ကြော်ငြာစေချင်ဘဲ ကိုယ်တိုင် `@` နဲ့ပဲ ခေါ်ချင်ရင်
frontmatter မှာ ဒါ ထည့်ပါ:

```yaml
metadata:
  opencode/autoinvoke: false
```

### ၄.၆ ဘယ် skill က ဘယ်အလုပ်မှာ လဲ — လျင်မြန်စွာ ရှာခြင်း

```bash
# နာမည်နဲ့ ရှာ
ls ~/.config/opencode/skills | grep -i jwt

# ဖော်ပြချက်ထဲက စကားလုံးနဲ့ ရှာ
grep -ril "smuggling" ~/.config/opencode/skills --include=SKILL.md

# skill တစ်ခုရဲ့ ညွှန်ကြားချက် အပြည့်အစုံ ဖတ်
less ~/.config/opencode/skills/sql-injection/SKILL.md
```

---

## ၅။ Update လုပ်နည်း

```bash
cd ~/kkuser-hacking-skill38
git pull
cp -r skills/* ~/.config/opencode/skills/
cp -r agents/* ~/.config/opencode/agents/
opencode   # restart
```

⚠️ `cp -r` က **ဖျက်တာ မလုပ်ဘူး**။ skill တစ်ခု ဖယ်ထုတ်ခံရရင် config folder ထဲမှာ
အဟောင်း ကျန်နေမယ်။ ရှင်းချင်ရင်:

```bash
rm -rf ~/.config/opencode/skills
mkdir -p ~/.config/opencode/skills
cp -r ~/kkuser-hacking-skill38/skills/* ~/.config/opencode/skills/
```

> ဒါက သင့် skill အဟောင်းတွေကိုပါ ဖျက်ပါမယ်။ တခြား skill ရှိရင် မလုပ်ပါနဲ့။

---

## ၆။ Repo ဖွဲ့စည်းပုံ

```
kkuser-hacking-skill38/
├── README.md               ← ဒီဖိုင်
├── SKILLS.md               ← စက်ဖတ်လွယ် catalog (auto-generated)
├── LICENSE                 ← MIT
├── skills/
│   ├── _shared/            ← မူဝါဒ ၄ ဖိုင် (skill မဟုတ်)
│   └── <38 skill folders>/SKILL.md
├── agents/                 ← agent ၄ ခု
├── mcp/opencode.jsonc      ← ရွေးချယ်နိုင်တဲ့ MCP config
└── tools/                  ← စစ်ဆေးရေး script များ
```

---

## ၇။ ကိုယ်တိုင် စစ်ဆေးခြင်း (Validation)

```bash
pip install pyyaml            # frontmatter ကို တကယ် YAML parser နဲ့ ဖတ်ဖို့
pip install markdown-it-py    # render_check.py အတွက် (ရွေးချယ်နိုင်)

python3 tools/validate_skills.py          # frontmatter + ၁၁ ပိုင်း စည်းမျဉ်း
python3 tools/deep_audit.py               # semantic audit
python3 tools/code_block_audit.py skills  # code block syntax
python3 tools/fence_report.py skills      # fence nesting
python3 tools/selftest.py                 # linter တကယ် fail လားဆိုတာ သက်သေ
python3 tools/build_catalog.py            # SKILLS.md ပြန်ထုတ်
```

ဒီ repo ရဲ့ နောက်ဆုံး ရလဒ်:

| စစ်ဆေးချက် | ရလဒ် |
|---|---|
| `validate_skills.py` | 38 skills, **38 ok, 0 failing** |
| `deep_audit.py` | **TOTAL PROBLEMS: 0** |
| `code_block_audit.py` | 399 blocks, 250 validated, **0 failed** |
| `fence_report.py` | **0 defects in 38 files** |
| `selftest.py` | **7 checks, 0 failing** |

`code_block_audit.py` က ဒီ language တွေကို တကယ့် toolchain နဲ့ စစ်တယ်:
bash (`bash -n`), javascript (`node --check`), typescript (`esbuild`), json, jsonc,
yaml (`PyYAML`), python (`ast`), php (`php -l`), ruby (`ruby -c`),
solidity (`solcjs`), **powershell (`pwsh` parser)**, **xml (ElementTree)**,
**html (tag nesting)**, **java (`javac` — syntax သာ)**, **sql (SQLite EXPLAIN)**,
**http (request/status line + headers)**, **gitignore (git status)**။

Toolchain တစ်ခု မရှိရင် အဲဒီ block တွေကို "skipped" လို့ ရိုးသားစွာ ပြတယ် —
မစစ်နိုင်တာကို စစ်ပြီးလို့ မပြောပါ။ ဒီ repo မှာ ကျန်တဲ့ **149 block** က
`(none) 75`, `markdown 50`, `text 24` — အားလုံး diagram/prose/output ဖြစ်လို့ code မဟုတ်ပါ။

Checker တစ်ခုချင်းစီကို **ကျိုးနေတဲ့ input နဲ့ မှန်တဲ့ input** နှစ်မျိုးလုံး စမ်းပြီးမှ ယုံတယ် —
ဒါမှ "failed 0" ဆိုတာ အဓိပ္ပာယ် ရှိတယ်။

---

## ၈။ ဒီဇိုင်း မူဝါဒ

1. **သက်သေ မရှိ = bug မရှိ။** Finding တစ်ခု report တင်ဖို့ asset, reproduction, PoC,
   control case, impact — ငါးခုလုံး လိုတယ်။ (`_shared/evidence-policy.md`)
2. **Scope ကို မချဲ့။** ရှာတွေ့တဲ့ host အသစ်က scope ထဲ ပါလား မေးစရာပါ၊
   အလိုအလျောက် ချဲ့လို့ မရဘူး။ (`_shared/scope-gate.md`)
3. **Severity ကို မြှင့်မတင်း။** Skill တစ်ခုချင်းစီမှာ `severity_ceiling` ရှိတယ် —
   အဲဒီအထက်ကို မတင်ရဘူး။
4. **နှစ်ဖက်သက်သေ။** Behavior ကွာခြားချက်ကို ပြတဲ့အခါ baseline နဲ့ exploit
   နှစ်ခုလုံး သိမ်းထားရတယ်။
5. **လျှို့ဝှက်ချက် မ mask ဘူး။** Cookie/token ကို `prefix...suffix` ပုံစံ mask လုပ်တယ်။

---

## ၉။ ရွေးချယ်နိုင်တဲ့ MCP

`mcp/opencode.jsonc` ထဲမှာ MCP server ၅ ခု ရှိတယ် (sequential-thinking, playwright,
fetch, filesystem, wsl-security-tools)။ လိုတာ ရွေးပြီး သင့်
`~/.config/opencode/opencode.jsonc` ထဲက `mcp` block မှာ ပေါင်းထည့်ပါ။
**မဖြစ်မနေ မလိုပါ** — skill တွေ အလုပ်လုပ်ဖို့ MCP မလိုဘူး။

ဒီဖိုင်က **V1 ပုံစံ** (`mcp.<name>.enabled`) သုံးတယ်။ V2 က `mcp` ထဲမှာ V1/V2
ရောနှောထားတာကို လက်ခံတယ် — ဒါကြောင့် ဒီအတိုင်း ထည့်လို့ ရတယ်။
V2 native ပုံစံ လိုချင်ရင် `mcp.servers` အောက်မှာ ထည့်ပြီး `enabled` အစား
`disabled` (ပြောင်းပြန်) သုံးပါ။

⚠️ ဒီဖိုင်ထဲက `wsl-security-tools` က `~/.config/opencode/mcp-servers/wsl-security-tools/index.js`
ကို ရှာတယ် — အဲဒီဖိုင် မရှိရင် အဲဒီ server ကို enable မလုပ်ပါနဲ့။

---

## ၁၀။ License

MIT — [LICENSE](LICENSE) ကြည့်ပါ။

ဒီ skill တွေက ပညာရေး နှင့် ခွင့်ပြုချက်ရှိ စစ်ဆေးမှုအတွက်ပါ။
ခွင့်ပြုချက်မရှိဘဲ စနစ်တစ်ခုကို စမ်းသပ်ခြင်းက ဥပဒေချိုးဖောက်မှု ဖြစ်နိုင်တယ် —
အန္တရာယ်ကို အသုံးပြုသူကိုယ်တိုင် ခံယူရမယ်။
