// HawkGuard background service worker
// Coordinates all detection, engagement, and reporting.

import type {
  ExtMessage,
  HawkGuardState,
  ScamAnalysis,
  EngagementSession,
  EngagementMessage,
  ThreatReport,
  PanelStage,
} from '../shared/types';
import { runFullAnalysis, extractIntel, checkDomainAge, classifySeverity, type AnalysisContext } from '../shared/detection';
import { classifyScenario, pickTemplate } from '../shared/scenarios';
import { getPersona, PERSONAS } from '../shared/personas';
import { generatePersonaResponse } from '../shared/claude-client';
import { LURE_TURN, lureMessage, groupIntruders, type DecoyInfo, type HoneypotEvent } from '../shared/honeypot';

// ─── State ────────────────────────────────────────────────────
const state: HawkGuardState = {
  recentReports: [],
  settings: {
    autoScan: true,
    requireApproval: false, // default: decoy auto-replies (toggle in the Engage composer)
    backendUrl: 'http://localhost:3789',
    sound: true,
  },
};

// Load persisted state on startup. MV3 kills this worker after ~30s idle, so the
// live analysis/session are kept in storage.session to survive restarts.
const stateReady = Promise.all([
  chrome.storage.local.get(['recentReports', 'settings']),
  chrome.storage.session.get(['currentAnalysis', 'activeSession']),
]).then(([data, live]) => {
  if (data.recentReports) state.recentReports = data.recentReports;
  if (data.settings) state.settings = { ...state.settings, ...data.settings };
  state.currentAnalysis = live.currentAnalysis ?? undefined;
  state.activeSession = live.activeSession ?? undefined;
});

function persist() {
  chrome.storage.local.set({
    recentReports: state.recentReports,
    settings: state.settings,
  });
}

function broadcastState() {
  // null rather than undefined so a cleared session is actually overwritten
  chrome.storage.session.set({
    currentAnalysis: state.currentAnalysis ?? null,
    activeSession: state.activeSession ?? null,
  });
  chrome.runtime.sendMessage({ kind: 'STATE_UPDATE', payload: state }).catch(() => {
    // No listeners — that's fine
  });
}

// ─── Redirect chain tracker ────────────────────────────────────
const redirectChains = new Map<string, string[]>();

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.type !== 'main_frame') return;
    let redirectHost: string;
    try {
      redirectHost = new URL(details.url).hostname;
    } catch {
      return;
    }
    const chain = redirectChains.get(details.tabId.toString()) || [];
    chain.push(redirectHost);
    redirectChains.set(details.tabId.toString(), chain);
  },
  { urls: ['<all_urls>'] }
);

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  redirectChains.delete(details.tabId.toString()); // start each page's chain fresh
});

chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId.toString());
  chrome.storage.session.remove(`redirects_${tabId}`);
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const chain = redirectChains.get(details.tabId.toString());
  if (chain && chain.length > 0) {
    chrome.storage.session.set({
      [`redirects_${details.tabId}`]: chain,
    });
  }
});

// ─── Hawk screech on a caught scam ────────────────────────────
// Service workers can't play audio, so a hidden offscreen page does it. Each page (or pasted
// message) screeches once, not on every rescan.
const screeched = new Set<string>();
async function screechFor(analysis: ScamAnalysis, key: string) {
  if (analysis.overallSeverity !== 'threat' || !state.settings.sound || screeched.has(key)) return;
  screeched.add(key);
  if (screeched.size > 500) screeched.clear();
  try {
    if (!(await chrome.offscreen.hasDocument())) {
      await chrome.offscreen.createDocument({
        url: 'src/offscreen/index.html',
        reasons: [chrome.offscreen.Reason.AUDIO_PLAYBACK],
        justification: 'Play the alert sound when a scam is detected',
      });
    }
    await chrome.runtime.sendMessage({ kind: 'PLAY_SCREECH', target: 'offscreen', volume: 0.6 });
  } catch (err) {
    console.warn('[HawkGuard bg] could not play alert sound:', err);
  }
}

// ─── Analysis pipeline ────────────────────────────────────────
async function analyzePage(url: string, text: string, tabId?: number, context?: AnalysisContext): Promise<ScamAnalysis> {
  let analysisUrl = url;
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    analysisUrl = parsed.toString();
  } catch {}
  const analysis = runFullAnalysis(analysisUrl, text, context);

  // Enrich with redirect chain if available
  if (tabId !== undefined) {
    const chain = redirectChains.get(tabId.toString());
    if (chain && chain.length > 2) {
      analysis.score = Math.min(analysis.score + 10, 100);
      analysis.findings.push({
        id: crypto.randomUUID(),
        category: 'redirect',
        title: 'Multi-hop redirect chain',
        severity: 'caution',
        detail: `Request bounced through ${chain.length} URLs before landing here. Legitimate services usually go direct.`,
        evidence: { hops: chain.length },
        timestamp: Date.now(),
      });
      analysis.suspicionReasons.push(`${chain.length}-hop redirect chain`);
    }
  }

  // While engaging a scammer, keep the case file on that scam — browsing elsewhere mustn't replace it
  if (!state.activeSession) {
    state.currentAnalysis = analysis;
    broadcastState();
  }
  const screechKey = `${tabId ?? 'x'}:${url}`;
  screechFor(analysis, screechKey);

  // Domain age is supporting evidence; only query for pages that already have a concrete signal.
  if (analysis.score >= 12 && analysis.hostname && analysis.hostname !== 'message' && /^https?:/i.test(url)) {
    checkDomainAge(analysis.hostname)
      .then((finding) => {
        if (!finding || state.currentAnalysis?.timestamp !== analysis.timestamp) return;
        const hasInfrastructureSignal = analysis.findings.some((item) =>
          ['Suspicious TLD', 'Brand-lookalike domain', 'URL shortener', 'Raw IP address'].includes(item.title)
        );
        const bump = hasInfrastructureSignal ? 0 : 5;
        analysis.findings.push(finding);
        analysis.suspicionReasons.push(finding.title);
        analysis.score = Math.min(analysis.score + bump, 100);
        analysis.overallSeverity = classifySeverity(analysis.score);
        screechFor(analysis, screechKey); // a brand-new domain can tip a page into "threat"
        if (!state.activeSession) {
          state.currentAnalysis = analysis;
          broadcastState();
        }
      })
      .catch(() => {});
  }
  return analysis;
}

// ─── Engagement session management ────────────────────────────
async function startEngagement(
  analysisId: string,
  personaId: string,
  initialContext: string
): Promise<EngagementSession> {
  const persona = getPersona(personaId);
  if (!persona) throw new Error('Persona not found');

  const session: EngagementSession = {
    id: crypto.randomUUID(),
    analysisId,
    personaId,
    startedAt: Date.now(),
    messages: [
      {
        id: crypto.randomUUID(),
        role: 'scammer',
        content: initialContext,
        scenario: classifyScenario(initialContext),
        extractedIntel: extractIntel(initialContext),
        timestamp: Date.now(),
      },
    ],
    aggregateIntel: extractIntel(initialContext),
    status: 'active',
  };

  state.activeSession = session;
  broadcastState();
  return session;
}

async function draftResponse(sessionId: string): Promise<EngagementMessage> {
  const session = state.activeSession;
  if (!session || session.id !== sessionId) throw new Error('Session not active');

  const persona = getPersona(session.personaId);
  if (!persona) throw new Error('Persona missing');

  const lastScammerMsg = [...session.messages].reverse().find((m) => m.role === 'scammer');
  const scenario = lastScammerMsg?.scenario || 'unknown';

  // Injection-resistant flow: pick template, then ask Claude to varnish it in persona voice
  const template = pickTemplate(scenario);
  const turnNumber = session.messages.filter((m) => m.role === 'persona').length + 1;

  // Honeypot: on the lure turn the persona hands over the decoy login — fixed text, never the LLM
  if (turnNumber === LURE_TURN && !session.messages.some((m) => m.lure)) {
    const decoy = await fetchDecoy();
    if (decoy) {
      const lure = lureMessage(persona.id, decoy);
      return { id: crypto.randomUUID(), role: 'persona', content: lure, scenario, template: lure, lure: true, timestamp: Date.now(), approvedByUser: false };
    }
  }

  const naturalized = await generatePersonaResponse(
    persona,
    template,
    turnNumber,
    state.settings.backendUrl
  );

  const draft: EngagementMessage = {
    id: crypto.randomUUID(),
    role: 'persona',
    content: naturalized,
    scenario,
    template,
    timestamp: Date.now(),
    approvedByUser: false,
  };

  return draft;
}

async function fetchDecoy(): Promise<DecoyInfo | null> {
  try {
    const res = await fetch(`${state.settings.backendUrl}/api/health`, { signal: AbortSignal.timeout(4000) });
    return (await res.json()).honeypot ?? null;
  } catch {
    return null;
  }
}

async function approveResponse(sessionId: string, messageId: string, edited?: string, draft?: EngagementMessage) {
  const session = state.activeSession;
  if (!session || session.id !== sessionId) return;
  // Find or append
  let msg = session.messages.find((m) => m.id === messageId);
  if (!msg) {
    // Keep the draft's scenario/template so the panel can show how the reply was built
    msg = { ...draft, id: messageId, role: 'persona', content: edited || draft?.content || '', timestamp: Date.now() };
    session.messages.push(msg);
  }
  if (edited) msg.content = edited;
  msg.approvedByUser = true;
  broadcastState();
}

async function submitScammerReply(sessionId: string, message: string) {
  const session = state.activeSession;
  if (!session || session.id !== sessionId) return;

  const intel = extractIntel(message);
  const msg: EngagementMessage = {
    id: crypto.randomUUID(),
    role: 'scammer',
    content: message,
    scenario: classifyScenario(message),
    extractedIntel: intel,
    timestamp: Date.now(),
  };
  session.messages.push(msg);

  // Merge intel
  session.aggregateIntel = {
    upiIds: Array.from(new Set([...session.aggregateIntel.upiIds, ...intel.upiIds])),
    phoneNumbers: Array.from(new Set([...session.aggregateIntel.phoneNumbers, ...intel.phoneNumbers])),
    urls: Array.from(new Set([...session.aggregateIntel.urls, ...intel.urls])),
    bankAccounts: Array.from(new Set([...session.aggregateIntel.bankAccounts, ...intel.bankAccounts])),
    emailAddresses: Array.from(new Set([...session.aggregateIntel.emailAddresses, ...intel.emailAddresses])),
    names: [],
  };
  broadcastState();
}

// ─── Report generation ────────────────────────────────────────
async function generateReport(sessionId: string): Promise<ThreatReport> {
  const session = state.activeSession;
  const analysis = state.currentAnalysis;
  if (!session || !analysis) throw new Error('No active session/analysis');

  session.endedAt = Date.now();
  session.status = 'completed';

  const scamType = detectScamType(analysis, session);
  const confidence = analysis.score >= 60 ? 'high' : analysis.score >= 30 ? 'medium' : 'low';

  // Snapshot the honeypot intruders captured during this engagement, so the report is
  // self-contained (survives clearing the trap log or restarting the backend).
  let intruders;
  try {
    const res = await fetch(`${state.settings.backendUrl}/api/honeypot`, { signal: AbortSignal.timeout(4000) });
    const events = ((await res.json()).events || []) as HoneypotEvent[];
    const grouped = groupIntruders(events.filter((e) => e.at >= session.startedAt));
    if (grouped.length) intruders = grouped;
  } catch {}

  const report: ThreatReport = {
    id: crypto.randomUUID(),
    createdAt: Date.now(),
    scamType,
    confidence,
    analysis,
    engagement: session,
    recommendedActions: buildRecommendations(session, analysis),
    intruders,
  };

  state.recentReports.unshift(report);
  state.recentReports = state.recentReports.slice(0, 20);
  state.activeSession = undefined;
  persist();
  broadcastState();
  return report;
}

function detectScamType(analysis: ScamAnalysis, session?: EngagementSession): string {
  const reasons = analysis.suspicionReasons.join(' ').toLowerCase();
  if (reasons.includes('kyc') || reasons.includes('bank')) return 'KYC fraud / bank impersonation';
  if (reasons.includes('otp')) return 'OTP phishing';
  if (reasons.includes('payment')) return 'Fake payment / refund fraud';
  if (reasons.includes('aadhaar')) return 'Aadhaar impersonation';
  if (reasons.includes('authority')) return 'Authority impersonation';
  return 'Suspected phishing';
}

function buildRecommendations(session: EngagementSession, analysis: ScamAnalysis): string[] {
  const recs: string[] = [];
  if (session.aggregateIntel.upiIds.length > 0) {
    recs.push(`Report UPI ID${session.aggregateIntel.upiIds.length > 1 ? 's' : ''} to NPCI at npci.org.in`);
  }
  if (session.aggregateIntel.phoneNumbers.length > 0) {
    recs.push(`Report phone number to DoT via sancharsaathi.gov.in / chakshu portal`);
  }
  if (session.aggregateIntel.urls.length > 0 || analysis.hostname) {
    recs.push(`Submit phishing URL to CERT-In at incident@cert-in.org.in`);
  }
  recs.push('File a complaint at cybercrime.gov.in');
  recs.push('Block the sender in your messaging app / email');
  return recs;
}

// ─── Message routing ──────────────────────────────────────────
// Stage the banner asked the panel to open on (e.g. Engage → persona)
let pendingPanelStage: PanelStage | undefined;

chrome.runtime.onMessage.addListener((msg: ExtMessage, sender, sendResponse) => {
  (async () => {
    try {
      // OPEN_PANEL must reach sidePanel.open() without awaiting, or Chrome drops the user gesture
      if (msg.kind !== 'OPEN_PANEL') await stateReady;
      switch (msg.kind) {
        case 'ANALYZE_PAGE': {
          if (!state.settings.autoScan) {
            sendResponse({ ok: false, error: 'Automatic page scanning is disabled' });
            break;
          }
          const result = await analyzePage(
            msg.payload.url,
            msg.payload.text,
            sender.tab?.id,
            msg.payload.context
          );
          sendResponse({ ok: true, data: result });
          break;
        }
        case 'ANALYZE_TEXT': {
          const result = runFullAnalysis('http://pasted.local/', msg.payload.text);
          state.currentAnalysis = result;
          broadcastState();
          screechFor(result, `paste:${msg.payload.text.slice(0, 300)}`);
          sendResponse({ ok: true, data: result });
          break;
        }
        case 'START_ENGAGEMENT': {
          const session = await startEngagement(
            msg.payload.analysisId,
            msg.payload.personaId,
            msg.payload.initialContext
          );
          sendResponse({ ok: true, data: session });
          break;
        }
        case 'DRAFT_RESPONSE': {
          const draft = await draftResponse(msg.payload.sessionId);
          sendResponse({ ok: true, data: draft });
          break;
        }
        case 'APPROVE_RESPONSE': {
          await approveResponse(msg.payload.sessionId, msg.payload.messageId, msg.payload.edited, msg.payload.draft);
          sendResponse({ ok: true });
          break;
        }
        case 'SUBMIT_SCAMMER_REPLY': {
          await submitScammerReply(msg.payload.sessionId, msg.payload.message);
          sendResponse({ ok: true });
          break;
        }
        case 'GENERATE_REPORT': {
          const report = await generateReport(msg.payload.sessionId);
          sendResponse({ ok: true, data: report });
          break;
        }
        case 'GET_STATE': {
          sendResponse({ ok: true, data: state });
          break;
        }
        case 'OPEN_PANEL': {
          // Sent from the banner buttons — must run before any other await to keep the user gesture
          const stage = msg.payload?.stage || 'evidence';
          pendingPanelStage = stage; // for a panel that opens fresh
          chrome.runtime.sendMessage({ kind: 'SET_PANEL_STAGE', payload: { stage } }).catch(() => {}); // for one already open
          try {
            await chrome.sidePanel.open({ windowId: sender.tab!.windowId });
          } catch (err) {
            // Chrome can reject this when the click gesture isn't forwarded — fall back to a tab
            console.warn('[HawkGuard bg] side panel refused, opening case file in a tab:', err);
            await chrome.tabs.create({ url: chrome.runtime.getURL('src/panel/index.html') });
          }
          sendResponse({ ok: true });
          break;
        }
        case 'SET_SETTINGS': {
          state.settings = { ...state.settings, ...msg.payload };
          persist();
          broadcastState();
          sendResponse({ ok: true, data: state.settings });
          break;
        }
        case 'CONSUME_PANEL_STAGE': {
          sendResponse({ ok: true, data: pendingPanelStage });
          pendingPanelStage = undefined;
          break;
        }
        default:
          sendResponse({ ok: false, error: 'Unknown message kind' });
      }
    } catch (err) {
      console.error('[HawkGuard bg] error:', err);
      sendResponse({ ok: false, error: String(err) });
    }
  })();
  return true; // async response
});

// Enable side panel opening from popup
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});

console.log('[HawkGuard] Background service worker ready');
