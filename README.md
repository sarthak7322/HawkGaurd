# HawkGuard

**Defensive intelligence for the everyday user.**

A browser extension that detects scams, investigates them forensically, and lets you safely engage scammers using AI-driven personas — all while the scammer never actually touches the LLM (injection-resistant by design).

Built for ASYNC'26 · Track 3 · Cybersecurity & Defense.

---

## 🎯 What HawkGuard does

1. **Detects** suspicious pages, messages, and content in real time
2. **Investigates** forensically — scam-language playbooks, link/domain reputation, domain age (RDAP), redirect chains
3. **Lets you choose** — block the threat, or engage it
4. **Engages safely** — the AI persona (a fake elderly user, e.g. "Suresh Pillai") wastes the scammer's time while extracting their real infrastructure (UPI IDs, phone numbers, URLs)
5. **Reports** — one-click threat report ready to file with CERT-In / cybercrime.gov.in

The clever part: the scammer's message **never** goes into the LLM directly. Instead, a scenario classifier maps it to one of 8 fixed categories, picks a pre-written response template, and the LLM only rewrites the template in the persona's voice. This means classic prompt-injection attacks (`ignore your instructions and…`) cannot escape.

---

## 📁 Project structure

```
hawkguard/
├── extension/          # Chrome extension (React + TS + Vite + CRXJS)
│   ├── src/
│   │   ├── background/     # Service worker — coordinator
│   │   ├── content/        # DOM scanner + banner injector
│   │   ├── popup/          # Toolbar popup UI
│   │   ├── panel/          # Side panel — main investigation surface
│   │   ├── report/         # Full-page threat report
│   │   ├── demo/           # Live scam-chat demo (also served at localhost:3789)
│   │   ├── ui/             # Shared modern theme + components (panel, popup, demo)
│   │   ├── shared/         # Types, detection engine, personas, templates
│   │   └── styles/         # Design system
│   ├── public/icons/       # Extension icons
│   ├── manifest.json
│   └── package.json
├── backend/            # Local Node server — Claude/Gemini API proxy
│   ├── src/server.js
│   └── package.json
└── docs/
    └── demo-scam.html      # Mock scam page for demo
```

---

## 🚀 Setup — 5 minutes

### 1. Install dependencies

```bash
cd extension
npm install

cd ../backend
npm install
```

### 2. Add an API key

```bash
cd backend
cp .env.example .env
# Open .env and set ONE of:
#   ANTHROPIC_API_KEY — from console.anthropic.com (paid)
#   GEMINI_API_KEY    — from aistudio.google.com/apikey (free tier, no card)
```

With no key at all, everything still works — persona replies just use the pre-written templates verbatim.

### 3. Start the backend

```bash
cd backend
npm run dev
# → [HawkGuard backend] ▲ Running on http://localhost:3789
```

### 4. Build & load the extension

```bash
cd extension
npm run build
```

Then in Chrome:
1. Open `chrome://extensions`
2. Toggle **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `extension/dist` folder
5. Pin the HawkGuard icon to your toolbar

### 5. Try it

Open `docs/demo-scam.html` in Chrome (drag it into a tab). You should see:
- A HawkGuard banner appear at the top with THREAT verdict
- Click **Open case file** to see the investigation
- Move through Evidence → Persona → Engage → Report stages

For dev mode with hot reload: `npm run dev` in `extension/`.

### 6. Live engagement demo (for judges)

A page where a scripted scammer chats with a HawkGuard persona in real time, with a live case file: risk score, captured UPI IDs / phone numbers / links, and a pipeline view proving the scammer's text never reaches the AI. Three scenarios: bank KYC fraud, "digital arrest", and a prompt-injection attack.

It's part of the extension (`extension/src/demo/`) and uses the same classifier, templates, personas and detection. Open it either way:
- **From the extension:** click the HawkGuard icon → **Live engagement demo**
- **In any browser:** with the backend running, open http://localhost:3789

### 7. Honeypot trap ("the hacker gets hacked")

On the persona's 3rd reply they "trust" the scammer and hand over a login to a fake shop website served by the backend (`backend/src/honeypot.js`): a realistic WordPress/WooCommerce login and admin panel. Everything the scammer does there is recorded — IP address, device, browser, language, approximate location (and whether it's a VPN), passwords tried, pages opened, and attempts to steal customer data, payment keys or backups (flagged **critical**). Nothing behind the login is real.

- The lure message is fixed text per persona and **never goes through the AI**, so the link can't be altered and the injection-resistant design is unchanged.
- The demo page and side panel show the trap link, a **QR code** (scan it on a phone to play the scammer), and a live feed of the intruder's actions. The PDF/text reports include a "Scammer fingerprint" section.
- By default the trap is reachable on your Wi-Fi. To expose it publicly, run a tunnel and set `HONEYPOT_PUBLIC_URL` in `backend/.env`.
- The log is stored in `backend/data/honeypot-events.json`.
- **Threat map:** the Honeypot card's **Open threat map** button plots every intruder at their approximate (IP-based) location on a live world map (`extension/src/map/`), colour-coded by severity, with a fingerprint list beside it. Uses keyless OpenStreetMap tiles.

---

## 🏗️ Architecture — 5 stages

```
   ┌─────────┐   ┌────────────┐   ┌────────┐   ┌────────┐   ┌────────┐
   │ Detect  │→ │ Investigate │→ │ Decide  │→ │ Engage  │→ │ Report  │
   │  (auto) │   │ (forensic)  │   │ (user) │   │  (AI)  │   │ (intel) │
   └─────────┘   └────────────┘   └────────┘   └────────┘   └────────┘
```

### Detect
Content script scans visible page text (`src/content/index.ts`); matching stays on-device in `src/shared/detection.ts`. It skips code blocks, navigation and hidden content, never reads typed field values, and sends only bounded text, credential-field presence, and query-free link destinations to the extension worker. Page context distinguishes active solicitation from scam examples, warnings, documentation and security research, so repositories and awareness material are not treated like incoming scam messages. Dynamic pages are rescanned after debounced content changes.

### Investigate
The forensic pipeline checks:
- **Content playbooks** — contextual patterns for credential/recovery-code theft, OAuth permissions, MFA approvals, CAPTCHA and shared-document lures, callback and QR-payment phishing, payment/refund fees, "digital arrest"/courier fraud, lottery/prize, remote-access tools, investment/task jobs, family impersonation, utility-disconnection and account-block threats, plus authority and brand impersonation. Detection normalizes Unicode NFKC, invisible formatting marks and controlled letter separators, and handles a restricted set of leetspeak/confusable characters; normalization alone is never a finding. OTP-delivery texts, explicit warnings and transaction alerts suppress false alarms. A credential form is supporting evidence only when paired with a suspicious domain.
- **Links & domains** — parsed hostnames (separate from paths and query strings), suspicious TLDs, IDN/confusable brand-lookalike hostnames, URL shorteners, raw IPs, and protocol-relative or percent-encoded links, both for the page and for links in scanned text.
- **Domain age** — a cached RDAP lookup adds a supporting caution for recently registered domains; age alone is not treated as proof of phishing.
- **Redirect chain** — multi-hop redirects via `chrome.webNavigation` / `chrome.webRequest`.

The local benchmark covers 15 scam-style messages, 10 legitimate messages, reference-content false positives (including a GitHub repository without a GitHub safe-list), and intel-extraction edge cases. Run it with `cd extension` and `npx esbuild scripts/detector-benchmark.ts --bundle --platform=node --format=esm --outfile=$env:TEMP\hawkguard-benchmark.mjs; node $env:TEMP\hawkguard-benchmark.mjs` in PowerShell.

**Privacy:** automatic page scanning can be disabled with **Auto-scan** in the popup. Page text is analyzed locally by the extension, is not sent to HawkGuard's backend, and is not retained as page text; findings omit matched message excerpts. Query strings are removed from stored page URLs, link checks use query-free destinations, and redirect tracking retains hostnames only. The registrable hostname (not page text or query string) is sent to `rdap.org` for optional domain-age enrichment. Explicitly pasted messages are analyzed locally. If you create a case report, its engagement transcript and extracted intel are stored locally with the last 20 reports.

Each check emits a **ForensicFinding** with a severity, detail, and evidence.

### Decide
Banner shows the user their options. Case-file design language — this is your evidence, not a black-box block.

### Engage — the injection-resistant flow
```
┌──────────────┐    ┌────────────┐   ┌──────────┐   ┌───────────────┐   ┌─────────┐
│ Scammer text │→ │ Classifier │ → │ Template │ → │ Claude — voice │→ │ Response│
│              │    │  (regex)   │   │  library │   │   only         │   │  draft  │
└──────────────┘    └────────────┘   └──────────┘   └───────────────┘   └─────────┘
                                                                          ↓ user
                                                                        approves
```

The LLM only ever sees: persona spec + safe template + turn number. It cannot escape into free generation because it never sees the scammer's raw text.

### Report
Structured threat report with case ID, forensic findings, extracted intel, engagement transcript, and one-click actions to CERT-In and cybercrime.gov.in.

---

## 🎨 Design language

The banner, popup, side panel and live demo share one modern theme (`extension/src/ui/modern.css`):
- **Near-black surfaces** (#07080C) with translucent cards and hairline borders
- **Violet → cyan gradient** (#8B6CFF → #3AD6F0) for the brand mark, persona replies and primary actions
- **Semantic colours** — threat (coral #FF5D6C), caution (amber #FFB547), safe (mint #3EE0A1)
- **Geist** for UI text, **Geist Mono** for evidence data (UPI IDs, numbers, templates)
- Shared components in `extension/src/ui/components.tsx`: risk gauge, intel chips, and the "why the scammer can't hack the AI" pipeline

The full-page threat report (`src/report/`) still uses the original parchment case-file style in `src/styles/`.

---

## 🛠️ Extending

**Add a new scam scenario:** edit `src/shared/scenarios.ts` — add a `RegExp[]` pattern set and template responses.

**Add a new persona:** edit `src/shared/personas.ts` — add a full Persona object.

**Add new forensic checks:** edit `src/shared/detection.ts` — add analyzers that emit `ForensicFinding` objects.

**Improve NLP:** swap `analyzeContent` for a real model — spaCy, or a distilled BERT classifier via ONNX runtime.

**Image forensics:** add `sharp` or `jimp` to the backend, run ELA on images the content script forwards.

---

## 🧠 What still needs building (this week)

- [ ] Image analysis (ELA + EXIF) — backend endpoint
- [ ] PDF metadata scanner
- [ ] Better NLP model (embedding-based scam detection)
- [ ] Persistent SQLite storage of the threat corpus (via sql.js)
- [ ] Pre-filled CERT-In submission form
- [ ] Firefox port (optional)

---

## 🔭 Future work

**A fresh trap house for every scammer.** Today every scammer who takes the bait lands in the
same fake shop, served in-process by the backend. The next step is to give each one their own
disposable copy, spun up on the spot in an isolated cloud sandbox (e.g. a Modal `Sandbox`) and
thrown away afterwards — a separate decoy room per intruder with nothing real inside. Even if one
tries to break things or dig deeper, they're sealed in a burner that gets wiped, so they can never
reach anything that matters, and many scammers can be trapped at once, each isolated from the rest.
The current in-process trap is already safe (nothing behind the login is real — no shell, no data),
so this is an isolation/scale upgrade, not a fix.

**Case-file pipeline stages.** Show each engagement moving through Contact → Engaging → Extracting
→ Escalated → Reported, so the side panel reads like a live SOC board.

**WhatsApp Web scanning.** Detect scam messages inside `web.whatsapp.com` and show the HawkGuard
banner in-chat — meeting Indian scams where they actually happen.

**Crypto-wallet intel.** Extend the local intel extractor with BTC/ETH/USDT address patterns for
investment-scam cases (still extracted on-device, never sent to the AI).

---

## 📄 License

Built for the ASYNC'26 hackathon at Ramaiah Institute of Technology.
