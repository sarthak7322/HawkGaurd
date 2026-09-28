// HawkGuard content script — silent DOM observer that pings the background.

import type { ScamAnalysis, PanelStage, PageAnalysisContext } from '../shared/types';
import { extractFormMetadata, extractLinkMetadata, extractStaticPageText } from './form-metadata';
import { shouldRescanForMutations } from './mutation-filter';

const BANNER_ID = 'hawkguard-alert-banner';
const STYLE_ID = 'hawkguard-alert-style';
let scanVersion = 0;
let autoScanEnabled = true;
let pageObserver: MutationObserver | undefined;
let lastBannerSignature = '';
const ownedUiNodes = new WeakSet<Node>();
let bannerElement: HTMLElement | undefined;
let styleElement: HTMLStyleElement | undefined;
const autoScanReady = chrome.storage.local.get('settings').then((data) => {
  autoScanEnabled = data.settings?.autoScan !== false;
}).catch((err) => {
  console.warn('[HawkGuard] Could not read automatic-scan preference:', err);
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local' || !changes.settings) return;
  const enabled = changes.settings.newValue?.autoScan !== false;
  if (enabled === autoScanEnabled) return;
  autoScanEnabled = enabled;
  if (autoScanEnabled) {
    scheduleScan();
    observeDynamicContent();
  } else {
    scanVersion++;
    pageObserver?.disconnect();
    pageObserver = undefined;
    removeOwnedUi();
  }
});

function extractPageData(): { text: string; context: PageAnalysisContext } {
  const root = document.querySelector('main, [role="main"], article') || document.body;
  if (!root) return { text: '', context: { referenceContent: false, credentialForm: false, links: [], linkMetadata: [], forms: [] } };

  const ignored = 'script, style, noscript, svg, code, pre, kbd, nav, footer, [hidden], [aria-hidden="true"], [contenteditable]:not([contenteditable="false"])';
  const isVisible = (el: Element) => {
    if (el.closest(ignored)) return false;
    for (let current: Node | null = el; current; current = current.parentNode) {
      if (ownedUiNodes.has(current)) return false;
    }
    const style = getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.visibility !== 'collapse';
  };
  const pageTitle = document.title.trim();
  const description = document.querySelector('meta[name="description"]')?.getAttribute('content') || '';
  const brandMetadata = Array.from(document.querySelectorAll('img[alt], [aria-label]'))
    .filter(isVisible)
    .slice(0, 50)
    .map((el) => el.getAttribute('alt') || el.getAttribute('aria-label') || '')
    .filter(Boolean);
  const text = [pageTitle, description, extractStaticPageText(root, isVisible), ...brandMetadata].filter(Boolean).join('\n').slice(0, 12000);
  const { forms, credentialForm } = extractFormMetadata(document, location.href, isVisible);
  const linkMetadata = extractLinkMetadata(document, location.href, isVisible);
  const links = linkMetadata.map((link) => link.href);

  const codeLength = Array.from(root.querySelectorAll('pre, code'))
    .reduce((total, el) => total + (el.textContent?.length || 0), 0);
  const pathLooksDocumentary = /\/(?:docs?|documentation|wiki|blob|raw)\//i.test(location.pathname)
    || /\.md$/i.test(location.pathname)
    || /(?:documentation|source code|security advisory|research|scam awareness)/i.test(`${pageTitle} ${description}`);
  const codeHeavy = codeLength > 800 && codeLength / Math.max(root.textContent?.length || 1, 1) > 0.15;

  return {
    text,
    context: {
      referenceContent: pathLooksDocumentary || codeHeavy,
      credentialForm,
      links,
      linkMetadata,
      forms,
    },
  };
}

function removeOwnedUi() {
  bannerElement?.remove();
  styleElement?.remove();
  bannerElement = undefined;
  styleElement = undefined;
  lastBannerSignature = '';
}

function injectBanner(analysis: ScamAnalysis) {
  if (analysis.overallSeverity === 'safe') {
    removeOwnedUi();
    return;
  }
  const signature = JSON.stringify([
    analysis.overallSeverity,
    analysis.score,
    analysis.suspicionReasons.slice(0, 2),
  ]);
  if (signature === lastBannerSignature
    && bannerElement?.isConnected
    && styleElement?.isConnected) return;
  removeOwnedUi();

  const banner = document.createElement('div');
  banner.id = BANNER_ID;
  ownedUiNodes.add(banner);
  bannerElement = banner;
  banner.setAttribute('data-severity', analysis.overallSeverity);

  const style = document.createElement('style');
  style.id = STYLE_ID;
  ownedUiNodes.add(style);
  styleElement = style;
  style.textContent = `
    #${BANNER_ID} {
      position: fixed;
      top: 12px; left: 12px; right: 12px;
      z-index: 2147483647;
      font-family: 'Geist', -apple-system, system-ui, 'Segoe UI', sans-serif;
      color: #eef0f6;
      background: rgba(12, 14, 20, 0.92);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid rgba(255, 93, 108, 0.45);
      border-radius: 18px;
      box-shadow: 0 24px 60px -18px rgba(0,0,0,.6), 0 0 0 1px rgba(255,255,255,.04) inset;
      padding: 12px 14px 12px 12px;
      display: flex;
      align-items: center;
      gap: 14px;
      animation: hg-drop .35s cubic-bezier(.2,.9,.3,1.2);
    }
    #${BANNER_ID}[data-severity="caution"] { border-color: rgba(255, 181, 71, 0.45); }
    #${BANNER_ID}[data-severity="unknown"] { border-color: rgba(255, 255, 255, 0.14); }
    @keyframes hg-drop {
      from { transform: translateY(-24px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    #${BANNER_ID} .hg-mark {
      width: 40px; height: 40px; flex: 0 0 auto;
      border-radius: 12px;
      background: linear-gradient(135deg, #8b6cff 0%, #5b7cff 55%, #3ad6f0 100%);
      color: #fff;
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 8px 24px -8px rgba(139, 108, 255, .8);
    }
    #${BANNER_ID} .hg-body { flex: 1; min-width: 0; }
    #${BANNER_ID} .hg-title {
      font-weight: 600; font-size: 14.5px; margin-bottom: 2px; letter-spacing: -0.01em;
      display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    }
    #${BANNER_ID} .hg-title .hg-badge {
      display: inline-flex;
      padding: 2px 8px;
      font-family: ui-monospace, 'SF Mono', Menlo, monospace;
      font-size: 10.5px;
      font-weight: 600;
      background: rgba(255, 93, 108, 0.15);
      color: #ff5d6c;
      border-radius: 999px;
    }
    #${BANNER_ID}[data-severity="caution"] .hg-badge,
    #${BANNER_ID}[data-severity="unknown"] .hg-badge { background: rgba(255, 181, 71, .14); color: #ffb547; }
    #${BANNER_ID} .hg-sub {
      font-size: 12.5px; color: #b7bdcc; line-height: 1.4;
      max-height: 2.8em; overflow: hidden;
    }
    #${BANNER_ID} .hg-actions {
      display: flex; gap: 8px; flex: 0 0 auto; align-items: center;
    }
    #${BANNER_ID} button {
      font-family: inherit;
      font-size: 13px;
      font-weight: 500;
      padding: 9px 14px;
      border-radius: 11px;
      border: 1px solid rgba(255,255,255,.14);
      background: rgba(255,255,255,.05);
      color: #eef0f6;
      cursor: pointer;
      transition: transform .12s ease, background .15s;
    }
    #${BANNER_ID} button:hover { transform: translateY(-1px); background: rgba(255,255,255,.1); }
    #${BANNER_ID} .hg-btn-block { background: #eef0f6; color: #0b0c10; border-color: transparent; }
    #${BANNER_ID} .hg-btn-block:hover { background: #fff; }
    #${BANNER_ID} .hg-btn-engage {
      background: linear-gradient(135deg, #8b6cff 0%, #5b7cff 55%, #3ad6f0 100%);
      color: #fff; border-color: transparent;
    }
    #${BANNER_ID} .hg-btn-engage:hover { background: linear-gradient(135deg, #8b6cff 0%, #5b7cff 55%, #3ad6f0 100%); filter: brightness(1.08); }
    #${BANNER_ID} .hg-close {
      background: none; border: none; padding: 4px 8px;
      font-size: 20px; line-height: 1; color: #7d8497;
    }
    #${BANNER_ID} .hg-close:hover { color: #eef0f6; background: none; }
    @media (max-width: 720px) {
      #${BANNER_ID} { flex-wrap: wrap; }
      #${BANNER_ID} .hg-actions { width: 100%; }
      #${BANNER_ID} .hg-actions button:not(.hg-close) { flex: 1; }
    }
  `;
  document.head.appendChild(style);

  const severityLabel =
    analysis.overallSeverity === 'threat' ? 'THREAT' :
    analysis.overallSeverity === 'caution' ? 'CAUTION' : 'UNCLEAR';

  const title = analysis.overallSeverity === 'threat'
    ? 'This page shows signs of a scam'
    : 'This page needs a closer look';

  const reasons = analysis.suspicionReasons.slice(0, 2).join(' · ');

  banner.innerHTML = `
    <div class="hg-mark"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
    <div class="hg-body">
      <div class="hg-title">
        <span>${title}</span>
        <span class="hg-badge">${severityLabel} · ${analysis.score}/100</span>
      </div>
      <div class="hg-sub">${escapeHtml(reasons) || 'Multiple signals suggest caution.'}</div>
    </div>
    <div class="hg-actions">
      <button class="hg-btn-inspect">Open case file</button>
      <button class="hg-btn-block">Leave page</button>
      <button class="hg-btn-engage">Engage</button>
      <button class="hg-close" title="Dismiss">×</button>
    </div>
  `;

  document.documentElement.insertBefore(banner, document.body);
  lastBannerSignature = signature;

  banner.querySelector('.hg-close')?.addEventListener('click', () => banner.remove());
  banner.querySelector('.hg-btn-block')?.addEventListener('click', () => {
    banner.remove();
    history.back();
  });
  banner.querySelector('.hg-btn-inspect')?.addEventListener('click', () => openPanel(banner, 'evidence'));
  banner.querySelector('.hg-btn-engage')?.addEventListener('click', () => openPanel(banner, 'persona'));
}

function openPanel(banner: HTMLElement, stage: PanelStage) {
  const staleHint = () => {
    const sub = banner.querySelector('.hg-sub');
    if (sub) sub.textContent = 'HawkGuard was reloaded — refresh this page to reconnect.';
  };
  try {
    // Throws synchronously if the extension was reloaded after this page loaded
    chrome.runtime.sendMessage({ kind: 'OPEN_PANEL', payload: { stage } }).catch(staleHint);
  } catch {
    staleHint();
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function scan() {
  try {
    await autoScanReady;
    if (!autoScanEnabled) {
      removeOwnedUi();
      return;
    }
    const version = ++scanVersion;
    if (window.top !== window) return; // top frame only
    if (location.protocol.startsWith('chrome')) return;
    // HawkGuard's own honeypot pages (backend/src/honeypot.js) — don't scan the trap we set
    if (document.querySelector('meta[name="hawkguard"][content="decoy"]')) return;
    const { text, context } = extractPageData();
    if (!text) {
      removeOwnedUi();
      return;
    }
    const res = await chrome.runtime.sendMessage({
      kind: 'ANALYZE_PAGE',
      payload: { url: location.href, text, html: '', context },
    });
    if (version === scanVersion && res?.ok && res.data) {
      injectBanner(res.data);
    }
  } catch (err) {
    // Extension context may be gone during reload
  }
}

let scanTimer: number | undefined;
function scheduleScan() {
  window.clearTimeout(scanTimer);
  scanTimer = window.setTimeout(scan, 900);
}

function observeDynamicContent() {
  if (!autoScanEnabled || !document.body || pageObserver) return;
  pageObserver = new MutationObserver((records) => {
    if (shouldRescanForMutations(records, ownedUiNodes)) scheduleScan();
  });
  pageObserver.observe(document.body, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ['href', 'action', 'method', 'autocomplete', 'placeholder', 'aria-label', 'name', 'id', 'type', 'alt', 'title', 'hidden', 'aria-hidden', 'style'],
  });
}

async function startScanner() {
  await autoScanReady;
  await scan();
  observeDynamicContent();
}

// Scan after initial render, then debounce meaningful SPA / dynamic-content changes.
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  setTimeout(() => { void startScanner(); }, 400);
} else {
  window.addEventListener('load', () => setTimeout(() => { void startScanner(); }, 400), { once: true });
}
