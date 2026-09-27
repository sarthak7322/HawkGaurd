# HawkGuard — test findings (2026-09-24)

Ranked by how much they'd hurt at the hackathon. Two are already fixed (marked ✅).

## Fixed during this pass

- ✅ **Backend crashed on a malformed persona.** A `/api/generate-response` call with a
  persona missing `quirks` threw and killed the whole backend (all features down until
  restart). Now every persona/template field is validated and bad input returns HTTP 400.
  Added a `process.on('unhandledRejection')` net so one bad request can never take the
  server down mid-demo. *(server.js)*
- ✅ **Threat map tiles demanded an API key.** The first map build used CARTO tiles that
  now stamp "API KEY REQUIRED" across the map. Switched to keyless OpenStreetMap tiles
  darkened with a CSS filter. *(map/)*

## High — could bite you in the demo or a code review

1. ✅ **Detection false positives and coverage (updated 2026-09-28).**
   The earlier baseline caught only ~1 in 3 scam texts and had 20% false alarms. Contextual
   analysis now distinguishes documentation, warnings, examples and active solicitations;
   the current local benchmark catches 15/15 scam-style messages with 0/10 false alarms.
   It also checks a GitHub repository and unrelated documentation host without a GitHub
   allowlist. The benchmark includes intel-extraction regression checks.
   The corpus includes the prior lottery, courier, job, remote-access, obfuscated-text,
   refund, family-impersonation, Hindi OTP, HDFC OTP-delivery and RBI-warning cases.

2. ✅ **Domain-age check is implemented.** `detection.ts` performs a cached RDAP lookup;
   recent registration is a supporting caution rather than proof of phishing. There is
   still no certificate-mismatch analyzer, so that finding category remains unused.

3. **Redirect tracker never resets.** `redirectChains` in `background/index.ts` accumulates
   per tab and is never cleared on navigation or tab close. After enough browsing, ordinary
   pages can be falsely flagged "multi-hop redirect chain", and it's a slow memory leak.
   Fix: clear the tab's entry on `webNavigation.onBeforeNavigate` / `tabs.onRemoved`.

## Medium — security posture (matters for a *security* project)

4. ✅ **Fixed 2026-09-25** (`backend/src/access.js`): only `/shop` is reachable from the
   tunnel or Wi-Fi; the API and demo answer only this laptop (Host/Origin checked too).
   ~~Anyone on the same Wi-Fi can read and wipe the captured attacker data, and burn your
   AI quota.~~ The CORS lock only stops *browsers* on other origins; a direct request
   (curl, script) with no `Origin` header still gets `GET/DELETE /api/honeypot` and
   `POST /api/generate-response`. On shared campus Wi-Fi that's a real exposure. Fix: gate
   `/api/honeypot` and the AI proxy behind a token, or bind the server to localhost and
   only expose `/shop` publicly via the tunnel.

5. **Trap admin has no real auth — a guessed/forged cookie walks in.** Setting
   `hg_auth == hg_sid` (both attacker-chosen) grants the fake admin without ever logging in.
   For a *decoy* this is arguably fine (we want them in), but note it: a curious visitor who
   never saw the lure can reach the admin and get logged as a "login". Low impact by design.

6. **`X-Forwarded-For` spoofing.** Only trusted when `HONEYPOT_PUBLIC_URL` is set (correct),
   but behind a tunnel the client can still send multiple XFF hops; we take the first, which
   is right. Verified: with no tunnel, a spoofed XFF is ignored (records the real socket IP).
   No action needed — noted for completeness.

## Low — polish

7. **Whole extension `dist/` (incl. `manifest.json`) is served to the LAN** by the backend's
   static handler. Harmless (it's public code) but unnecessary exposure; could scope the
   static mount to only what the demo needs.

8. **Intel extractor rough edges.** A phone number like `7894561230123` is also captured as
   a "bank account", a trailing `).` sticks to a captured URL, and any `x@y` (e.g.
   `support@company.com` minus the TLD) is read as a UPI ID. Cosmetic in the demo.

9. **Popup "Paste" replaces the live case.** Analysing pasted text mid-engagement overwrites
   `currentAnalysis`. Minor; the session itself is preserved.

## What was tested and is solid

- Injection-resistant flow: scammer text never reaches the LLM; the classifier output is
  ignored if it's not a known category; the lure is fixed text, not AI-generated. ✔
- Honeypot end-to-end: login capture, page/exfil logging, severity grading, per-visitor
  grouping, fingerprint (IP, device, browser, language, geo, coords, ASN, VPN flag). ✔
- Report PDF/text incl. the scammer-fingerprint section. ✔
- Log capped at 500 events (flood-tested with 600 rapid logins → stayed at 500). ✔
- Provider fallback chain across Gemini models when one is out of quota. ✔
