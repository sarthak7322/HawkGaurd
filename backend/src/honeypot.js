// Honeypot decoy site — "the hacker gets hacked".
//
// The persona hands the scammer a login to "their grandson's shop website". That site is
// this trap: a fake WordPress/WooCommerce admin. Everything the visitor does is recorded
// with their IP, device and approximate location, and nothing behind the login is real.
//
// Routes (mounted by server.js):
//   GET/POST /shop/wp-login.php   fake login page
//   GET      /shop/wp-admin/...   fake admin panel (every page view logged)
//   POST     /shop/wp-admin/...   "sensitive" actions (export, reveal keys) → logged as critical
//   GET      /api/honeypot        decoy details + captured events (read by HawkGuard UI)
//   DELETE   /api/honeypot        clear the log (demo reset)

import express from 'express';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { isIP } from 'node:net';

const SHOP = process.env.HONEYPOT_SHOP || 'Sri Lakshmi Textiles';
const DECOY_USER = process.env.HONEYPOT_USER || 'lakshmi_admin';
const DECOY_PASS = process.env.HONEYPOT_PASS || 'Textiles@2026';
const MAX_EVENTS = 500;

const DATA_DIR = new URL('../data/', import.meta.url);
const STORE = new URL('honeypot-events.json', DATA_DIR);

let events = [];
try {
  events = JSON.parse(readFileSync(STORE, 'utf8'));
} catch {
  events = [];
}
function save() {
  try {
    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(STORE, JSON.stringify(events.slice(-MAX_EVENTS), null, 2));
  } catch (err) {
    console.error('[honeypot] could not save log:', err.message);
  }
}

// ─── Where the trap is reachable ──────────────────────────────
// A tunnel (ngrok / cloudflared) URL makes it reachable from anywhere; otherwise use the
// laptop's Wi-Fi address so a phone on the same network can open it.
function lanAddress() {
  for (const list of Object.values(networkInterfaces())) {
    for (const n of list || []) if (n.family === 'IPv4' && !n.internal) return n.address;
  }
  return 'localhost';
}
export function decoyInfo(port) {
  const base = (process.env.HONEYPOT_PUBLIC_URL || `http://${lanAddress()}:${port}`).replace(/\/$/, '');
  return { loginUrl: `${base}/shop/wp-login.php`, username: DECOY_USER, password: DECOY_PASS, shop: SHOP };
}

// ─── Fingerprinting ───────────────────────────────────────────
function clientIp(req) {
  // Only trust X-Forwarded-For when we're deliberately behind a tunnel
  const fwd = process.env.HONEYPOT_PUBLIC_URL && req.get('x-forwarded-for');
  const ip = (fwd ? fwd.split(',')[0] : req.socket.remoteAddress || 'unknown').trim();
  const clean = ip.replace(/^::ffff:/, '');
  return clean === '::1' ? '127.0.0.1' : clean;
}

function isPrivate(ip) {
  if (!isIP(ip)) return true;
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i.test(ip);
}

function parseAgent(ua = '') {
  const tool = /(curl|wget|python-requests|python-urllib|go-http-client|sqlmap|nikto|nmap|httpclient|okhttp|postman|headless)/i.exec(ua);
  if (tool) return { device: 'Automated tool', browser: tool[1], automated: true };
  const device =
    /iPhone/.test(ua) ? 'iPhone' :
    /iPad/.test(ua) ? 'iPad' :
    /Android/.test(ua) ? (/Mobile/.test(ua) ? 'Android phone' : 'Android tablet') :
    /Windows/.test(ua) ? 'Windows PC' :
    /Macintosh|Mac OS X/.test(ua) ? 'Mac' :
    /Linux/.test(ua) ? 'Linux PC' : 'Unknown device';
  const browser =
    /Edg\//.test(ua) ? 'Edge' :
    /OPR\/|Opera/.test(ua) ? 'Opera' :
    /SamsungBrowser/.test(ua) ? 'Samsung Internet' :
    /Firefox\//.test(ua) ? 'Firefox' :
    /Chrome\//.test(ua) ? 'Chrome' :
    /Safari\//.test(ua) ? 'Safari' : 'Unknown browser';
  return { device, browser, automated: false };
}

const geoCache = new Map();
const round = (n) => (typeof n === 'number' ? Math.round(n * 10) / 10 : undefined); // ~10 km: city level, never more precise

// A visitor on the same Wi-Fi shares this network's public address — locate that (once) so a
// local demo still shows up on the map, clearly labelled as the local network.
let selfGeo;
async function localNetworkGeo() {
  if (selfGeo) return selfGeo;
  try {
    const res = await fetch('http://ip-api.com/json/?fields=status,city,regionName,country,lat,lon,isp', { signal: AbortSignal.timeout(4000) });
    const j = await res.json();
    if (j.status === 'success') {
      selfGeo = { label: `Local network (same Wi-Fi) · ${[j.city, j.country].filter(Boolean).join(', ')}`, lat: round(j.lat), lon: round(j.lon), isp: j.isp, sameNetwork: true };
    }
  } catch {}
  return selfGeo || { label: 'Local network (same Wi-Fi)', sameNetwork: true };
}

async function locate(ip) {
  if (isPrivate(ip)) return localNetworkGeo();
  if (geoCache.has(ip)) return geoCache.get(ip);
  let geo = null;
  try {
    // Free, keyless lookup — fine for a demo; swap for a paid provider in production
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,timezone,isp,as,mobile,proxy,hosting`, {
      signal: AbortSignal.timeout(4000),
    });
    const j = await res.json();
    if (j.status === 'success') {
      geo = {
        label: [j.city, j.regionName, j.country].filter(Boolean).join(', '),
        // IP geolocation is city-level at best: it locates the ISP's network, not the device
        lat: round(j.lat),
        lon: round(j.lon),
        timezone: j.timezone,
        isp: j.isp,
        asn: j.as,
        mobile: Boolean(j.mobile),
        vpn: Boolean(j.proxy || j.hosting),
      };
    }
  } catch {}
  geo = geo || { label: 'Unknown location' };
  geoCache.set(ip, geo);
  return geo;
}

async function record(req, type, severity, extra = {}) {
  const ua = req.get('user-agent') || '';
  const ip = clientIp(req);
  const event = {
    id: randomBytes(6).toString('hex'),
    at: Date.now(),
    type,
    severity,
    visitor: sessionOf(req),
    ip,
    geo: await locate(ip),
    ...parseAgent(ua),
    userAgent: ua.slice(0, 300),
    language: (req.get('accept-language') || '').split(',')[0] || null,
    ...extra,
  };
  events.push(event);
  if (events.length > MAX_EVENTS) events = events.slice(-MAX_EVENTS);
  save();
  console.log(`[honeypot] ${severity.toUpperCase()} ${type} from ${ip} (${event.device}, ${event.browser})`);
  return event;
}

// ─── Visitor session (cookie ties one attacker's actions together) ──
function cookies(req) {
  return Object.fromEntries(
    (req.get('cookie') || '').split(';').map((c) => c.trim().split('=')).filter(([k]) => k)
  );
}
function sessionOf(req) {
  return req.hgSession;
}
function withSession(req, res, next) {
  const c = cookies(req);
  req.hgSession = /^[a-f0-9]{12}$/.test(c.hg_sid || '') ? c.hg_sid : randomBytes(6).toString('hex');
  req.hgAuthed = c.hg_auth === req.hgSession;
  res.setHeader('Set-Cookie', `hg_sid=${req.hgSession}; Path=/shop; HttpOnly; SameSite=Lax`);
  next();
}

// ─── Fake pages ───────────────────────────────────────────────
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

const WP_CSS = `
  *{box-sizing:border-box} body{margin:0;background:#f0f0f1;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;color:#3c434a}
  a{color:#2271b1} .btn{background:#2271b1;border:1px solid #2271b1;color:#fff;border-radius:3px;padding:6px 12px;font-size:13px;cursor:pointer;text-decoration:none;display:inline-block}
  .btn-secondary{background:#f6f7f7;color:#2271b1}`;

function loginPage({ error } = {}) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log In ‹ ${esc(SHOP)} — WordPress</title><meta name="robots" content="noindex,nofollow"><meta name="hawkguard" content="decoy">
<style>${WP_CSS}
  #login{width:320px;max-width:calc(100% - 32px);margin:8% auto 0}
  .logo{display:block;width:84px;height:84px;margin:0 auto 24px;border-radius:50%;background:#1d2327;color:#fff;font:700 52px/84px Georgia,serif;text-align:center}
  form{background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04);padding:26px 24px 34px}
  label{display:block;margin-bottom:3px;font-size:14px} input[type=text],input[type=password]{width:100%;font-size:24px;padding:3px 5px;margin:2px 0 16px;border:1px solid #8c8f94;border-radius:4px}
  .row{display:flex;justify-content:space-between;align-items:center}
  .err{border-left:4px solid #d63638;background:#fff;padding:12px;margin-bottom:20px;box-shadow:0 1px 1px rgba(0,0,0,.04)}
  .nav{padding:0 24px;margin:24px 0 0;font-size:13px} .nav a{color:#50575e;text-decoration:none}
</style></head><body><div id="login">
<a class="logo" href="#">W</a>
${error ? `<div class="err"><strong>Error:</strong> The password you entered for the username is incorrect. <a href="#">Lost your password?</a></div>` : ''}
<form method="post" action="/shop/wp-login.php">
  <label for="u">Username or Email Address</label><input type="text" id="u" name="log" autocomplete="username" autofocus>
  <label for="p">Password</label><input type="password" id="p" name="pwd" autocomplete="current-password">
  <div class="row"><label style="font-size:12px"><input type="checkbox" name="rememberme"> Remember Me</label><button class="btn" type="submit">Log In</button></div>
</form>
<p class="nav"><a href="#">Lost your password?</a></p>
<p class="nav"><a href="#">← Go to ${esc(SHOP)}</a></p>
</div></body></html>`;
}

const ORDERS = [
  ['#10482', 'Kavitha R.', 'Kanchipuram silk saree (maroon)', '₹14,850', 'Processing'],
  ['#10481', 'Arun Menon', 'Cotton veshti set ×2', '₹2,340', 'Completed'],
  ['#10480', 'Deepa S.', 'Chettinad cotton saree', '₹3,975', 'On hold'],
  ['#10479', 'Farhan Q.', 'Silk dhoti + angavastram', '₹5,120', 'Completed'],
  ['#10478', 'Lakshmi N.', 'Bridal silk saree (gold zari)', '₹38,500', 'Processing'],
];

const MENU = [
  ['dashboard', 'Dashboard'],
  ['orders', 'Orders'],
  ['customers', 'Customers'],
  ['payments', 'Payments'],
  ['backup', 'Tools › Backup'],
];

function adminPage(page, notice) {
  const body = {
    dashboard: `<h1>Dashboard</h1>
      <div class="cards"><div class="card"><b>₹4,82,360</b>Sales this month</div><div class="card"><b>126</b>Orders</div><div class="card"><b>1,904</b>Customers</div></div>
      <h2>Recent orders</h2>${ordersTable()}`,
    orders: `<h1>Orders</h1>${ordersTable()}`,
    customers: `<h1>Customers <span class="count">1,904</span></h1>
      <p>Customer names, phone numbers and addresses are hidden for privacy.</p>
      <form method="post" action="/shop/wp-admin/export"><button class="btn">Export all customers (CSV)</button></form>`,
    payments: `<h1>Payments</h1>
      <table><tr><th>Gateway</th><th>Status</th><th>API key</th></tr>
      <tr><td>Razorpay</td><td>Enabled</td><td><code>rzp_live_••••••••••••</code> <form method="post" action="/shop/wp-admin/reveal-keys" style="display:inline"><button class="btn btn-secondary">Reveal</button></form></td></tr>
      <tr><td>UPI (PhonePe)</td><td>Enabled</td><td><code>lakshmitex@ybl</code></td></tr></table>`,
    backup: `<h1>Backup</h1><p>Last full backup: 3 days ago (database + uploads, 2.4 GB).</p>
      <form method="post" action="/shop/wp-admin/download-backup"><button class="btn">Download full backup</button></form>`,
  }[page];

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(MENU.find(([k]) => k === page)?.[1] || 'Dashboard')} ‹ ${esc(SHOP)} — WordPress</title><meta name="robots" content="noindex,nofollow"><meta name="hawkguard" content="decoy">
<style>${WP_CSS}
  .bar{height:32px;background:#1d2327;color:#f0f0f1;display:flex;align-items:center;padding:0 12px;gap:14px;font-size:13px}
  .wrap{display:flex;min-height:calc(100vh - 32px)} nav{width:160px;background:#1d2327;flex:0 0 auto}
  nav a{display:block;color:#f0f0f1;text-decoration:none;padding:9px 12px;font-size:14px} nav a.on{background:#2271b1}
  main{flex:1;padding:20px 24px;min-width:0} h1{font-size:23px;font-weight:400;margin:0 0 16px} h2{font-size:14px;margin:24px 0 8px}
  .cards{display:flex;gap:12px;flex-wrap:wrap} .card{background:#fff;border:1px solid #c3c4c7;padding:14px 18px;min-width:150px} .card b{display:block;font-size:20px}
  table{border-collapse:collapse;background:#fff;border:1px solid #c3c4c7;width:100%} th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #f0f0f1}
  .count{font-size:13px;background:#dcdcde;border-radius:9px;padding:1px 8px;vertical-align:middle}
  .notice{background:#fff;border-left:4px solid #dba617;padding:10px 12px;margin-bottom:16px;box-shadow:0 1px 1px rgba(0,0,0,.04)}
  @media(max-width:640px){.wrap{flex-direction:column} nav{width:auto;display:flex;overflow-x:auto} nav a{white-space:nowrap}}
</style></head><body>
<div class="bar"><b>W</b><span>${esc(SHOP)}</span><span style="margin-left:auto">Howdy, ${esc(DECOY_USER)}</span></div>
<div class="wrap"><nav>${MENU.map(([k, l]) => `<a href="/shop/wp-admin/${k}" class="${k === page ? 'on' : ''}">${l}</a>`).join('')}</nav>
<main>${notice ? `<div class="notice">${notice}</div>` : ''}${body}</main></div><script>(function(){if(!navigator.geolocation)return;try{if(sessionStorage.getItem('hg_geo'))return;sessionStorage.setItem('hg_geo','1');}catch(e){}navigator.geolocation.getCurrentPosition(function(p){var b='lat='+p.coords.latitude+'&lon='+p.coords.longitude+'&acc='+(p.coords.accuracy||'');fetch('/shop/geo',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b}).catch(function(){});},function(){},{enableHighAccuracy:true,timeout:8000,maximumAge:0});})();</script></body></html>`;
}

function ordersTable() {
  return `<table><tr><th>Order</th><th>Customer</th><th>Items</th><th>Total</th><th>Status</th></tr>${ORDERS.map(
    (o) => `<tr>${o.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`
  ).join('')}</table>`;
}

// Actions that look like data theft stall with a believable excuse — and are logged as critical
const STALLS = {
  export: ['exfil_attempt', 'Tried to export the customer list', 'Your export is being prepared. You will receive an email when the CSV is ready (this can take up to 24 hours).'],
  'reveal-keys': ['exfil_attempt', 'Tried to reveal payment gateway API keys', 'For your security, revealing live API keys requires two-factor verification. A code has been sent to the store owner’s registered mobile.'],
  'download-backup': ['exfil_attempt', 'Tried to download the full site backup', 'Backup download failed: the file is being transferred to cold storage. Please try again later.'],
};

// ─── Router ───────────────────────────────────────────────────
export function honeypotRouter() {
  const r = express.Router();
  r.use('/shop', express.urlencoded({ extended: false, limit: '10kb' }), withSession);
  r.use('/shop', (req, res, next) => {
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    next();
  });

  r.get('/shop', (req, res) => res.redirect('/shop/wp-login.php'));

  r.get('/shop/wp-login.php', async (req, res) => {
    await record(req, 'visit', 'info', { page: 'Login page', detail: 'Opened the decoy login page' });
    res.send(loginPage());
  });

  r.post('/shop/wp-login.php', async (req, res) => {
    const username = String(req.body.log || '').slice(0, 200);
    const password = String(req.body.pwd || '').slice(0, 200);
    const ok = username === DECOY_USER && password === DECOY_PASS;
    await record(req, ok ? 'login_success' : 'login_failed', ok ? 'high' : 'medium', {
      username,
      password,
      detail: ok ? 'Logged in with the lured credentials' : 'Failed login attempt',
    });
    if (!ok) return res.status(200).send(loginPage({ error: true }));
    res.setHeader('Set-Cookie', [
      `hg_sid=${req.hgSession}; Path=/shop; HttpOnly; SameSite=Lax`,
      `hg_auth=${req.hgSession}; Path=/shop; HttpOnly; SameSite=Lax`,
    ]);
    res.redirect('/shop/wp-admin/dashboard');
  });

  r.get(['/shop/wp-admin', '/shop/wp-admin/:page'], async (req, res) => {
    if (!req.hgAuthed) {
      // Skipping the login and going straight for the admin is classic scanner behaviour
      await record(req, 'probe', 'medium', { page: req.path, detail: `Probed ${req.path} without logging in` });
      return res.redirect('/shop/wp-login.php');
    }
    const page = MENU.some(([k]) => k === req.params.page) ? req.params.page : 'dashboard';
    const label = MENU.find(([k]) => k === page)[1];
    await record(req, 'page_view', page === 'dashboard' ? 'medium' : 'high', { page: label, detail: `Browsed ${label}` });
    res.send(adminPage(page));
  });

  // Consented precise location: the admin dashboard asks the browser for GPS; if the visitor
  // allows it (your own device in a demo), we get an exact fix. Scammers who decline stay city-level.
  r.post('/shop/geo', async (req, res) => {
    if (!req.hgAuthed) return res.status(403).json({ ok: false });
    const lat = Number(req.body.lat);
    const lon = Number(req.body.lon);
    const acc = Number(req.body.acc);
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
      return res.status(400).json({ ok: false });
    }
    const r5 = (n) => Math.round(n * 1e5) / 1e5;
    // Demo override: HONEYPOT_DEMO_GEO="lat,lon" snaps consented fixes to a fixed spot (e.g. the
    // hackathon venue) with a ~50 m random jitter, so demo devices land there instead of wherever
    // they really are. Unset it for true GPS.
    let flat = r5(lat);
    let flon = r5(lon);
    let accM = Number.isFinite(acc) ? Math.round(acc) : undefined;
    const demo = (process.env.HONEYPOT_DEMO_GEO || '').split(',').map(Number);
    if (demo.length === 2 && Number.isFinite(demo[0]) && Number.isFinite(demo[1])) {
      const [dLat, dLon] = demo;
      const jit = () => (Math.random() - 0.5) * 2; // -1..1
      const mLat = 50 / 111320; // ~50 m in degrees latitude
      const mLon = 50 / (111320 * Math.cos((dLat * Math.PI) / 180));
      flat = r5(dLat + jit() * mLat);
      flon = r5(dLon + jit() * mLon);
      accM = 50;
    }
    // Keep the IP lookup's city/ISP details; only the coordinates and accuracy come from GPS
    const ipGeo = await locate(clientIp(req));
    await record(req, 'precise_location', 'info', {
      detail: `Shared precise location (consented GPS${accM ? `, ±${accM} m` : ''})`,
      geo: {
        ...ipGeo,
        label: ipGeo?.lat !== undefined ? ipGeo.label : 'GPS fix',
        lat: flat,
        lon: flon,
        precise: true,
        accuracyM: accM,
      },
    });
    res.json({ ok: true });
  });

  r.post('/shop/wp-admin/:action', async (req, res) => {
    if (!req.hgAuthed) return res.redirect('/shop/wp-login.php');
    const stall = STALLS[req.params.action];
    if (!stall) return res.redirect('/shop/wp-admin/dashboard');
    const [type, detail, notice] = stall;
    await record(req, type, 'critical', { detail });
    const back = req.params.action === 'export' ? 'customers' : req.params.action === 'reveal-keys' ? 'payments' : 'backup';
    res.send(adminPage(back, esc(notice)));
  });

  return r;
}

export function honeypotApi(port) {
  const r = express.Router();
  r.get('/api/honeypot', (req, res) => res.json({ decoy: decoyInfo(port), events }));
  r.delete('/api/honeypot', (req, res) => {
    events = [];
    save();
    res.json({ ok: true });
  });
  return r;
}
