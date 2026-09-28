// Honeypot lure — the persona "trusts" the scammer and hands over a login to a decoy shop site
// hosted by the backend (backend/src/honeypot.js). Anything the scammer does there is recorded.
//
// The lure is FIXED text per persona and never goes through the LLM: the URL and credentials must
// arrive intact, and it keeps the rule that the model only ever rewrites pre-approved templates.

export interface DecoyInfo {
  loginUrl: string;
  username: string;
  password: string;
  shop: string;
}

export interface HoneypotEvent {
  id: string;
  at: number;
  type: 'visit' | 'probe' | 'login_failed' | 'login_success' | 'page_view' | 'exfil_attempt' | 'precise_location';
  severity: 'info' | 'medium' | 'high' | 'critical';
  visitor: string;
  ip: string;
  // Approximate, IP-based (city level — the ISP's network, not the device's exact position)
  geo: { label: string; lat?: number; lon?: number; timezone?: string; isp?: string; asn?: string; mobile?: boolean; vpn?: boolean; sameNetwork?: boolean; precise?: boolean; accuracyM?: number };
  device: string;
  browser: string;
  automated: boolean;
  language: string | null;
  detail: string;
  page?: string;
  username?: string;
  password?: string;
}

// Offer the login on the persona's 3rd reply — after some rapport, before the scammer gives up
export const LURE_TURN = 3;

// Written as a favour, not an offer: the persona is asking the "helpful officer" to look at the
// shop website their family set up, and mentions the shop's payments come through it — the bait
// a scammer can't resist checking.
const LURES: Record<string, string> = {
  suresh_pillai:
    "sir one small help. my grandson made a website for my wife's saree shop {shop}. all the shop payments come there he said. i cant login, always wrong password. you can check once?\n{url}\nid {user}\npassword {pass}",
  meera_desai:
    'acha ek kaam karoge? mere bete ne hamari dukaan {shop} ki website banayi hai, customer ke payment usi mein aate hai. mujhse login nahi hota, error aata hai. aap ek baar dekh lo\n{url}\nusername {user}\npassword {pass}',
  ramesh_bhat:
    "Before we continue, may I ask a small favour? My grandson made a website for our family shop, {shop}. He says the customer payments are received there, but I have never managed to log in. Could you please check?\n{url}\nUsername: {user}\nPassword: {pass}",
};

export const mapUrl = (lat: number, lon: number) =>
  `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=11/${lat}/${lon}`;

export function lureMessage(personaId: string, decoy: DecoyInfo): string {
  return (LURES[personaId] || LURES.suresh_pillai)
    .replace('{shop}', decoy.shop)
    .replace('{url}', decoy.loginUrl)
    .replace('{user}', decoy.username)
    .replace('{pass}', decoy.password);
}

// One attacker = one browser session on the decoy. Collapse their events into a fingerprint.
export interface Intruder {
  visitor: string;
  ip: string;
  geo: HoneypotEvent['geo'];
  device: string;
  browser: string;
  automated: boolean;
  language: string | null;
  firstSeen: number;
  lastSeen: number;
  loggedIn: boolean;
  credentialsTried: { username: string; password: string }[];
  actions: HoneypotEvent[];
  worst: HoneypotEvent['severity'];
}

const RANK = { info: 0, medium: 1, high: 2, critical: 3 } as const;

export function groupIntruders(events: HoneypotEvent[]): Intruder[] {
  const byVisitor = new Map<string, Intruder>();
  for (const e of events) {
    let v = byVisitor.get(e.visitor);
    if (!v) {
      v = {
        visitor: e.visitor,
        ip: e.ip,
        geo: e.geo,
        device: e.device,
        browser: e.browser,
        automated: e.automated,
        language: e.language,
        firstSeen: e.at,
        lastSeen: e.at,
        loggedIn: false,
        credentialsTried: [],
        actions: [],
        worst: 'info',
      };
      byVisitor.set(e.visitor, v);
    }
    v.lastSeen = e.at;
    // A consented GPS fix wins over IP geo (keeping its city/ISP details); otherwise adopt the first located fix
    if (e.geo?.precise) v.geo = { ...v.geo, ...e.geo };
    else if (!v.geo.precise && v.geo.lat === undefined && e.geo?.lat !== undefined) v.geo = e.geo;
    v.actions.push(e);
    if (e.type === 'login_success') v.loggedIn = true;
    if (e.username !== undefined) v.credentialsTried.push({ username: e.username, password: e.password || '' });
    if (RANK[e.severity] > RANK[v.worst]) v.worst = e.severity;
  }
  return [...byVisitor.values()].sort((a, b) => b.lastSeen - a.lastSeen);
}
