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
  type: 'visit' | 'probe' | 'login_failed' | 'login_success' | 'page_view' | 'exfil_attempt';
  severity: 'info' | 'medium' | 'high' | 'critical';
  visitor: string;
  ip: string;
  // Approximate, IP-based (city level — the ISP's network, not the device's exact position)
  geo: { label: string; lat?: number; lon?: number; timezone?: string; isp?: string; asn?: string; mobile?: boolean; vpn?: boolean; sameNetwork?: boolean };
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

const LURES: Record<string, string> = {
  suresh_pillai:
    "sir one thing. my grandson made a website for my wife's saree shop, {shop}. i can never log in, always says wrong password. you know computers, can you check?\n{url}\nusername {user}\npassword {pass}\ntell me what you see",
  meera_desai:
    'acha ek kaam karo please. my son made a website for our shop {shop}, i can never open it, some error aata hai. you check once?\n{url}\nusername {user}\npassword {pass}\nbatao kya dikh raha hai',
  ramesh_bhat:
    "Before we go on, could you look at something for me? My grandson built a website for our family shop, {shop}, and I've never managed to log in. You clearly know computers.\n{url}\nUsername {user}, password {pass}.\nLet me know what you see.",
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
    v.actions.push(e);
    if (e.type === 'login_success') v.loggedIn = true;
    if (e.username !== undefined) v.credentialsTried.push({ username: e.username, password: e.password || '' });
    if (RANK[e.severity] > RANK[v.worst]) v.worst = e.severity;
  }
  return [...byVisitor.values()].sort((a, b) => b.lastSeen - a.lastSeen);
}
