// Scam detection heuristics — runs entirely in the browser.
// The LLM is used only for the engagement layer, never for detection.
//
// Approach: verb-anchored content signals (an "ask" verb next to a sensitive term, not the
// bare word) across many Indian scam playbooks, minus negative signals for legitimate bank
// SMS / warnings / transaction alerts, plus link + domain checks. Leetspeak is de-obfuscated
// before matching. Domain age (RDAP) is an optional async check used by the live page scanner.

import type { ForensicFinding, ScamAnalysis, Severity } from './types';

const rx = (s: string) => new RegExp(s, 'i');
const rxg = (s: string) => new RegExp(s, 'gi');

// Leetspeak substitutions applied only inside tokens that contain a letter, so amounts,
// years and phone numbers ("5000", "2026", "9876543210") are left intact.
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's' };
function deobfuscate(text: string): string {
  return text.split(/(\s+)/).map((tok) => (/[a-z]/i.test(tok) && /[013457@$8]/.test(tok) ? tok.replace(/[013457@$8]/g, (c) => LEET[c] ?? c) : tok)).join('');
}

// ── Building blocks ──────────────────────────────────────────
const ASK = '(?:please\\s+|kindly\\s+)*(?:share|send|give|tell|provide|enter|submit|verify|confirm|read\\s*out|forward|resend|reply\\s*with|type|update|renew|reactivate)';
const CRED = '(?:otp|one[\\s-]?time[\\s-]?password|cvv|c\\.v\\.v|\\bpin\\b|mpin|upi\\s*pin|password|passcode|aadhaar(?:\\s*(?:card|number))?|pan(?:\\s*(?:card|number))?|kyc|card\\s*(?:number|details)|(?:bank\\s*)?account\\s*(?:number|details)|net\\s*banking)';

// Positive categories. Each match adds `weight`; the finding's own severity drives display colour.
interface Cat { key: string; title: string; detail: string; severity: Severity; weight: number; res: RegExp[]; }
const CATEGORIES: Cat[] = [
  {
    key: 'credential', title: 'Credential solicitation', severity: 'threat', weight: 35,
    detail: 'Asks you to share an OTP, PIN, CVV, password, Aadhaar or card details. No legitimate service asks for these.',
    res: [
      rx(`${ASK}(?:\\s+(?:me|us|your|the|us\\s+your))?[^.?!\\n]{0,30}${CRED}`),
      rx(`${CRED}[^.?!\\n]{0,25}(?:to|for|and)\\s+(?:verify|confirm|unblock|un-?block|activate|reactivate|proceed|complete|process|receive|update|validate)`),
    ],
  },
  {
  key: 'payment', title: 'Payment demand', severity: 'threat', weight: 25,
  detail: 'Pressures you to pay, transfer or send money — especially when tied to a fee, penalty, threat, reward or account action.',
  res: [
  rx('\\b(?:pay|send|transfer|deposit|remit)\\b[^.?!\\n]{0,30}(?:₹|rs\\.?|inr)\\s*\\d{2,}[^.?!\\n]{0,30}(?:claim|receive|unlock|release|avoid|verify|reactivate|refund|reward|prize|penalty|fine|fee|charge)'),
  rx('(?:processing|registration|verification|clearance|refundable|security|activation|penalty|fine|customs?)\\s+(?:fee|charge|deposit|amount)'),
  ],
},
  {
    key: 'digital_arrest', title: '"Digital arrest" / courier fraud', severity: 'threat', weight: 40,
    detail: 'Classic "digital arrest" script: a fake courier or officer claims your parcel or identity is linked to a crime.',
    res: [
      rx('digital\\s+arrest'), rx('under\\s+(?:digital\\s+)?arrest'), rx('do\\s*n[o\']?t\\s+disconnect'),
      rx('(?:parcel|courier|package|consignment|shipment)[^.?!\\n]{0,40}(?:drugs?|illegal|passport|arrest|seized|customs|narcotic|money\\s*launder)'),
      rx('(?:fedex|dhl|blue\\s*dart|dtdc|indian\\s*post|customs)[^.?!\\n]{0,40}(?:illegal|drugs?|arrest|seized|detain|narcotic)'),
    ],
  },
  {
    key: 'lottery', title: 'Lottery / prize scam', severity: 'threat', weight: 30,
    detail: 'Tells you that you won a lottery, prize or lucky draw — then asks for a fee or details to "release" it.',
    res: [
      rx('(?:won|winner|winning|selected|lucky\\s*winner)[^.?!\\n]{0,35}(?:lottery|prize|lakh|crore|rs\\.?|₹|inr|lucky\\s*draw|reward|gift|kbc|jackpot|bumper)'),
      rx('\\b(?:kbc|kaun\\s*banega|lucky\\s*draw|jackpot|bumper\\s*(?:prize|offer)|lottery\\s*(?:winner|number))\\b'),
      rx('congratulation[^.?!\\n]{0,40}(?:won|winner|selected|prize|lottery|lucky|reward)'),
    ],
  },
  {
    key: 'remote_access', title: 'Remote-access tool', severity: 'threat', weight: 34,
    detail: 'Wants you to install screen-sharing or remote-control software, which hands over your device.',
    res: [
      rx('\\b(?:any\\s*desk|anydesk|team\\s*viewer|teamviewer|quick\\s*support|quicksupport|rustdesk|screen[\\s-]?shar|remote\\s+(?:access|control|assistance|desktop))\\b'),
      rx('install[^.?!\\n]{0,30}(?:app|application|software|apk)[^.?!\\n]{0,30}(?:bank|fix|help|resolve|support|verify|update)'),
    ],
  },
  {
    key: 'investment', title: 'Investment / crypto scam', severity: 'threat', weight: 28,
    detail: 'Promises guaranteed or unrealistic returns — a hallmark of investment and crypto fraud.',
    res: [
      rx('(?:guaranteed|assured|fixed|100%)[^.?!\\n]{0,20}(?:returns?|profit|income|doubl)'),
      rx('(?:double|triple|2x|3x)[^.?!\\n]{0,15}(?:your\\s+)?(?:money|investment|amount|capital)'),
      rx('\\d{2,3}\\s*%[^.?!\\n]{0,20}(?:return|profit|monthly|weekly|daily|guaranteed)'),
      rx('\\b(?:usdt|bitcoin|btc|crypto|forex|trading\\s*account)\\b[^.?!\\n]{0,30}(?:invest|profit|return|deposit|wallet|double)'),
    ],
  },
  {
    key: 'job', title: 'Fake job / task scam', severity: 'caution', weight: 22,
    detail: 'Work-from-home or "like and earn" task offers are a common front for advance-fee and money-mule scams.',
    res: [
      rx('(?:part[\\s-]?time|work\\s+from\\s+home|online|home[\\s-]?based)\\s+job'),
      rx('earn[^.?!\\n]{0,20}(?:rs\\.?|₹|inr|\\d{3,})[^.?!\\n]{0,12}(?:per\\s*day|/\\s*day|daily|per\\s*task|weekly|from\\s*home)'),
      rx('(?:like|subscribe|rate|review|complete)[^.?!\\n]{0,20}(?:videos?|youtube|tasks?|hotels?|apps?)[^.?!\\n]{0,25}(?:earn|paid|money|salary|telegram|whatsapp)'),
    ],
  },
  {
    key: 'refund', title: 'Fake refund / cashback bait', severity: 'caution', weight: 22,
    detail: 'A "pending refund" or "cashback" you must claim through a link is a common phishing hook.',
    res: [
      rx('(?:pending|claim\\s*(?:your)?|get\\s*(?:your)?)\\s*(?:refund|cashback)'),
      rx('(?:refund|cashback)[^.?!\\n]{0,20}(?:click|claim|link|verify|expire|pending)'),
    ],
  },
  {
    key: 'family', title: 'Family-impersonation scam', severity: 'caution', weight: 24,
    detail: 'A "new number" from a relative asking for urgent money is a widespread impersonation scam.',
    res: [
      rx('\\b(?:hi|hello|hey)\\s+(?:mom|mum|mummy|dad|papa|beta|son|uncle|aunty)\\b'),
      rx('(?:this\\s+is\\s+my\\s+new\\s+number|new\\s+number|changed\\s+my\\s+number|lost\\s+my\\s+phone|phone\\s+(?:broke|is\\s+broken|got\\s+damaged|not\\s+working))'),
    ],
  },
  {
    key: 'utility', title: 'Utility disconnection scam', severity: 'caution', weight: 26,
    detail: 'Threats to cut electricity, gas or a SIM unless you act immediately are a common pressure scam.',
    res: [
      rx('(?:electricity|power|gas|sim\\s*card)[^.?!\\n]{0,30}(?:disconnect|will\\s+be\\s+(?:cut|disconnected|deactivated|blocked)|deactivat)'),
    ],
  },
  {
    key: 'account_threat', title: 'Account block/expiry threat', severity: 'caution', weight: 20,
    detail: 'Warns that your account, card or KYC is blocked or expired to pressure you into acting.',
    res: [
      rx('(?:account|a/c|card|kyc|pan|aadhaar|wallet|sim)\\b[^.?!\\n]{0,25}(?:is|are|has\\s+been|will\\s+be)?[^.?!\\n]{0,10}(?:blocked|suspend|frozen|deactivat|expired|on\\s+hold|closed|de-?activat)'),
    ],
  },
  {
    key: 'link_bait', title: 'Click-the-link bait', severity: 'caution', weight: 15,
    detail: 'Urges you to click a link to verify, claim or update — the delivery mechanism for most phishing.',
    res: [
  rx('(?:click|tap|open|visit)[^.?!\\n]{0,20}(?:here|this\\s+link|the\\s+link|below)[^.?!\\n]{0,35}(?:verify|update|claim|login|log\s*in|kyc|refund|account)'),
  rx('(?:https?://|www\\.)[^\\s/]+(?:/[^\\s?]*)?(?:verify|update|claim|login|log[-_]?in|kyc|refund|payment|account)[^\\s]*'),
],
  },
];

// Negative signals — legitimate messages that share keywords with scams.
const NEGATIVE: { key: string; re: RegExp; weight: number }[] = [
  { key: 'otp_delivery', weight: 25, re: rx('(?:your|the)\\s+(?:otp|one[\\s-]?time[\\s-]?password|verification\\s+code|code)\\b[^.?!\\n]{0,40}(?:is|:)\\s*\\d{3,8}') },
  { key: 'otp_delivery2', weight: 25, re: rx('\\b\\d{3,8}\\s+is\\s+your\\s+(?:otp|code|verification|password)') },
  { key: 'disclaimer', weight: 22, re: rx('(?:do\\s*n[o\']?t|don[o\']?t|never|dont)\\s+(?:share|disclose|reveal|give)\\b[^.?!\\n]{0,35}(?:otp|pin|cvv|password|code|card|details|anyone|bank)') },
  { key: 'advisory', weight: 10, re: rx('\\b(?:fraud|scam|phishing|fraudulent|beware\\s+of)\\b') },
  { key: 'transaction', weight: 22, re: rx('\\b(?:debited|credited|received|withdrawn|spent|paid)\\b[^.?!\\n]{0,20}(?:rs\\.?|inr|₹|from|to|a/c|account|via)') },
];

const SENSITIVE_TERM = rx('\\b(?:otp|cvv|pin|mpin|kyc|aadhaar|net\\s*banking|upi\\s*pin)\\b');
const HAS_DEVANAGARI = /[ऀ-ॿ]/;
const URGENCY = [
  rx('\\bimmediately?\\b'), rx('\\bwithin\\s+\\d+\\s*(?:hours?|minutes?|min|hrs?|days?)\\b'),
  rx('\\b(?:expire|expiring|expires)\\b'), rx('\\b(?:last\\s+chance|final\\s+(?:notice|warning|reminder)|urgent(?:ly)?|act\\s+now|right\\s+now|hurry)\\b'),
  rx('\\bwill\\s+be\\s+(?:blocked|suspended|closed|deactivated|disconnected|cancelled)\\b'),
  rx('तुरंत|अभी|जल्दी|बंद\\s*हो|ब्लॉक'),
];
const AUTHORITY = [
  rx('\\brbi\\b|reserve\\s+bank'), rx('income\\s+tax|it\\s+department'), rx('\\bcbi\\b|central\\s+bureau'),
  rx('\\bpolice\\b|cyber\\s*(?:cell|crime|police)'), rx('supreme\\s+court|high\\s+court'), rx('\\bcustoms\\b'),
  rx('\\btrai\\b|\\bdot\\b|department\\s+of\\s+tele'), rx('enforcement\\s+directorate|\\bed\\s+department'),
  rx('narcotics|\\bncb\\b'), rx('aadhaar[^.?!\\n]{0,20}(?:office|dept|department|authority|uidai)'),
];
const BRANDS = [
  rx('\\bsbi\\b|state\\s+bank'), rx('\\bhdfc\\b'), rx('\\bicici\\b'), rx('axis\\s+bank'), rx('\\bkotak\\b'),
  rx('\\bpaytm\\b'), rx('\\bphonepe\\b'), rx('\\bgpay\\b|google\\s+pay'), rx('\\bamazon\\b'), rx('\\bflipkart\\b'),
  rx('\\bnetflix\\b'), rx('\\bwhatsapp\\b'), rx('\\bnpci\\b'), rx('\\bmyntra\\b'), rx('\\bpnb\\b|punjab\\s+national'),
];

// Extract intel patterns
export const INTEL_PATTERNS = {
  upi: /[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,15}/g,
  phone: /(?:\+91[-\s]?|\b0)?[6-9]\d{9}\b/g,
  url: /https?:\/\/[^\s"'<>]+|\bwww\.[^\s"'<>]+/gi,
  bankAccount: /\b\d{9,18}\b/g,
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
};

function anyHit(patterns: RegExp[], a: string, b: string): { hit: boolean; example: string } {
  for (const p of patterns) {
    const m = a.match(p) || b.match(p);
    if (m) return { hit: true, example: m[0].trim().slice(0, 60) };
  }
  return { hit: false, example: '' };
}
function countHits(patterns: RegExp[], text: string): number {
  return patterns.reduce((n, p) => n + (p.test(text) ? 1 : 0), 0);
}

export function analyzeContent(text: string): { score: number; findings: ForensicFinding[]; reasons: string[] } {
  const findings: ForensicFinding[] = [];
  const reasons: string[] = [];
  const deob = deobfuscate(text);
  let score = 0;
  const finding = (category: ForensicFinding['category'], title: string, severity: Severity, detail: string, evidence: Record<string, string | number>) =>
    findings.push({ id: crypto.randomUUID(), category, title, severity, detail, evidence, timestamp: Date.now() });

  // Negative signals first (legitimate-message markers)
  let credit = 0;
  const neg = new Set<string>();
  for (const n of NEGATIVE) if (n.re.test(text)) { credit += n.weight; neg.add(n.key); }
  const advisory = neg.has('advisory');
  const otpDelivery = neg.has('otp_delivery') || neg.has('otp_delivery2');

  // Positive categories
  for (const c of CATEGORIES) {
    // An OTP-delivery message ("your OTP is 1234") must not count as credential solicitation
    if (c.key === 'credential' && otpDelivery) continue;
    const { hit, example } = anyHit(c.res, text, deob);
    if (hit) {
      score += c.weight;
      reasons.push(c.title);
      finding('content', c.title, c.severity, c.detail, { match: example });
    }
  }

  // Urgency (supporting signal)
  const urgencyCount = countHits(URGENCY, text) + countHits(URGENCY, deob);
  if (urgencyCount > 0) {
    score += Math.min(urgencyCount * 2, 6);
    reasons.push(`Urgency / time pressure (${urgencyCount})`);
    finding('content', 'Urgency pressure language', urgencyCount > 2 ? 'threat' : 'caution',
      'Artificial time pressure is a core social-engineering tactic; real institutions rarely demand instant action.', { count: urgencyCount });
  }
  // Strong combination: credential collection + account threat is much more
  // suspicious than either signal alone.
  const hasCredential = findings.some((f) => f.title === 'Credential solicitation');
  const hasAccountThreat = findings.some((f) => f.title === 'Account block/expiry threat');

  if (hasCredential && hasAccountThreat) {
    score += 20;
    reasons.push('Credential request + account threat');
    finding(
      'content',
      'High-risk credential + account threat combination',
      'threat',
      'Requests sensitive credentials while threatening account suspension, closure or blocking.',
      { combination: 'credential + account threat' }
    );
  }
  // Sensitive term under pressure, incl. Hindi/Hinglish (catches non-English asks like "OTP बताएं")
  // if (!findings.some((f) => f.title === 'Credential solicitation') && !otpDelivery && !neg.has('disclaimer') && SENSITIVE_TERM.test(text) && (urgencyCount > 0 || HAS_DEVANAGARI.test(text))) {
  //   score += 20;
  //   reasons.push('Sensitive credential requested under pressure');
  //   finding('content', 'Credential solicitation', 'threat',
  //     'A message pushes for an OTP / PIN / KYC alongside urgency — a hallmark of phishing.', { term: (text.match(SENSITIVE_TERM) || [''])[0] });
  // }


  // Authority impersonation — only counts alongside a threat/pressure signal, so a neutral
  // "Income Tax Dept: your ITR was processed" doesn't get flagged.
  const authority = anyHit(AUTHORITY, text, deob);
  if (authority.hit && (score > 0 || urgencyCount > 0)) {
    score += 18;
    reasons.push(`Authority impersonation (${authority.example})`);
    finding('content', 'Impersonation of authority', 'threat',
      'Invokes a government body or regulator to intimidate — legitimate agencies do not demand money or codes over chat.', { match: authority.example });
  }

  // Brand impersonation — only alongside credential/payment/link activity
  const brand = anyHit(BRANDS, text, deob);
  const activity = findings.some((f) => ['Credential solicitation', 'Payment demand', 'Click-the-link bait', 'Fake refund / cashback bait'].includes(f.title));
  if (brand.hit && activity) {
    score += 10;
    reasons.push('Impersonated brand + suspicious activity');
    finding('content', 'Brand impersonation', 'threat', 'References a well-known brand next to a credential, payment or link request.', { brand: brand.example });
  }

  // Obfuscated / leetspeak text (e.g. "0TP", "y0ur acc0unt susp3nded")
    // Obfuscated scam-related words only
  if (deob !== text) {
    const leetWords = (text.match(/\b\w*[013457@]\w*\b/gi) || [])
      .filter((w) => /[a-z]/i.test(w))
      .filter((w) => {
        const normalized = w
          .toLowerCase()
          .replace(/0/g, 'o')
          .replace(/1/g, 'i')
          .replace(/3/g, 'e')
          .replace(/4/g, 'a')
          .replace(/5/g, 's')
          .replace(/7/g, 't')
          .replace(/@/g, 'a');

        return /(otp|account|verify|password|passcode|login|secure|suspend|blocked|confirm|payment|refund|bank|wallet|urgent)/i.test(normalized);
      });

    if (leetWords.length >= 1) {
      score += 10;
      reasons.push('Obfuscated (leetspeak) text');
      finding(
        'content',
        'Character-substituted text',
        'caution',
        'Scam-related words appear disguised with character substitutions.',
        { examples: leetWords.slice(0, 4).join(', ') }
      );
    }
  }

  score = Math.max(0, score - credit);
  return { score: Math.min(score, 100), findings, reasons };
}

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link', '.info', '.buzz', '.rest', '.live', '.online', '.shop', '.cyou', '.work'];
const SHORTENERS = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rebrand\.ly|ow\.ly|shorturl\.at|rb\.gy|t\.ly)\b/i;
const BRAND_LOOKALIKE = /(sbi|hdfc|icici|axis|kotak|paytm|phonepe|gpay|amazon|amzn|flipkart|myntra|netflix|google|apple|microsoft|whatsapp|npci|uidai|irctc)[-_]/i;
const BRAND_DOMAIN_RULES = [
  { name: 'PayPal', pattern: /\bpaypal\b/i, domains: ['paypal.com'] },

  { name: 'SBI', pattern: /\bsbi\b|state\s+bank\s+of\s+india/i, domains: ['sbi.bank.in', 'sbi.co.in'] },
  { name: 'HDFC Bank', pattern: /\bhdfc\b/i, domains: ['hdfc.bank.in', 'hdfcbank.com'] },
  { name: 'ICICI Bank', pattern: /\bicici\b/i, domains: ['icici.bank.in', 'icicibank.com'] },
  { name: 'Axis Bank', pattern: /\baxis\s+bank\b/i, domains: ['axis.bank.in', 'axisbank.com'] },
  { name: 'Kotak', pattern: /\bkotak\b/i, domains: ['kotak.bank.in', 'kotak.com'] },
  { name: 'PNB', pattern: /\bpnb\b|punjab\s+national\s+bank/i, domains: ['pnb.bank.in', 'pnbindia.in'] },

  { name: 'Paytm', pattern: /\bpaytm\b/i, domains: ['paytm.com'] },
  { name: 'PhonePe', pattern: /\bphonepe\b/i, domains: ['phonepe.com'] },

  { name: 'Amazon', pattern: /\bamazon\b/i, domains: ['amazon.com', 'amazon.in'] },
  { name: 'Flipkart', pattern: /\bflipkart\b/i, domains: ['flipkart.com'] },
  { name: 'Myntra', pattern: /\bmyntra\b/i, domains: ['myntra.com'] },
  { name: 'Netflix', pattern: /\bnetflix\b/i, domains: ['netflix.com'] },

  { name: 'WhatsApp', pattern: /\bwhatsapp\b/i, domains: ['whatsapp.com'] },
  { name: 'Google', pattern: /\bgoogle\b/i, domains: ['google.com'] },
  { name: 'Google Pay', pattern: /\bgpay\b|\bgoogle\s+pay\b/i, domains: ['google.com', 'pay.google.com'] },
  { name: 'Apple', pattern: /\bapple\b/i, domains: ['apple.com'] },
  { name: 'Microsoft', pattern: /\bmicrosoft\b/i, domains: ['microsoft.com'] },
  { name: 'Instagram', pattern: /\binstagram\b/i, domains: ['instagram.com'] },
  { name: 'Facebook', pattern: /\bfacebook\b/i, domains: ['facebook.com'] },
  { name: 'LinkedIn', pattern: /\blinkedin\b/i, domains: ['linkedin.com'] },

  { name: 'NPCI', pattern: /\bnpci\b/i, domains: ['npci.org.in'] },
  { name: 'IRCTC', pattern: /\birctc\b/i, domains: ['irctc.co.in'] },
];
function detectBrandDomainMismatch(
  hostname: string,
  text: string,
  findings: ForensicFinding[]
): { brand: string; domain: string } | null {
  const suspiciousActivity = findings.some((f) =>
    [
      'Credential solicitation',
      'Payment demand',
      'Click-the-link bait',
      'Fake refund / cashback bait',
      'Account block/expiry threat',
      'Digital arrest / authority threat',
      'Remote-access request',
      'Lottery / prize bait',
      'Investment / trading bait',
      'Job / recruitment bait',
    ].includes(f.title)
  );

  if (!suspiciousActivity) return null;

  const domain = hostname.replace(/^www\./, '').toLowerCase();

  for (const rule of BRAND_DOMAIN_RULES) {
    if (!rule.pattern.test(text)) continue;

    const belongsToBrand = rule.domains.some(
      (officialDomain) =>
        domain === officialDomain ||
        domain.endsWith(`.${officialDomain}`)
    );

    if (!belongsToBrand) {
      return {
        brand: rule.name,
        domain,
      };
    }
  }

  return null;
}
export function analyzeDomain(hostname: string, source: 'page' | 'link' = 'page'): { score: number; findings: ForensicFinding[]; reasons: string[] } {
  const findings: ForensicFinding[] = [];
  const reasons: string[] = [];
  let score = 0;
  const where = source === 'link' ? 'Link in message' : 'Page domain';
  const add = (title: string, severity: Severity, detail: string, weight: number, reason: string) => {
    score += weight;
    reasons.push(reason);
    findings.push({ id: crypto.randomUUID(), category: 'domain', title, severity, detail, evidence: { hostname, source: where }, timestamp: Date.now() });
  };

  if (SUSPICIOUS_TLDS.some((t) => hostname.endsWith(t)))
    add('Suspicious TLD', 'caution', 'Top-level domain frequently used by short-lived phishing pages.', 20, `Uncommon TLD (${where.toLowerCase()})`);
  if (BRAND_LOOKALIKE.test(hostname))
    add('Brand-lookalike domain', 'threat', 'Combines a real brand name with extra words — a classic phishing pattern.', 25, 'Domain mimics a known brand');
  if (SHORTENERS.test(hostname))
    add('URL shortener', 'caution', 'Shortened links hide the real destination and are common in phishing.', 15, 'Shortened link hides destination');
  if ((hostname.match(/-/g) || []).length > 2)
    add('Hyphen-heavy hostname', 'caution', 'Many hyphens often spell out a brand in a fake domain.', 10, 'Excessive hyphens in hostname');
  if (/^\d+\.\d+\.\d+\.\d+/.test(hostname))
    add('Raw IP address', 'threat', 'Legitimate services use a domain name, not a raw IP.', 30, 'Raw IP address in URL');

  return { score: Math.min(score, 100), findings, reasons };
}

// Domains that legitimately use punycode / long labels shouldn't be re-flagged endlessly
function hostFromUrl(u: string): string | null {
  try {
    return new URL(/^https?:\/\//i.test(u) ? u : `http://${u}`).hostname.replace(/^www\./, '');
  } catch {
    return null;
  }
}

function analyzeLinks(text: string): { score: number; findings: ForensicFinding[]; reasons: string[] } {
  const urls = Array.from(new Set(text.match(INTEL_PATTERNS.url) || [])).map((u) => u.replace(/[),.;:]+$/, ''));
  const seen = new Set<string>();
  let score = 0;
  const findings: ForensicFinding[] = [];
  const reasons: string[] = [];
  for (const u of urls.slice(0, 10)) {
    const host = hostFromUrl(u);
    if (!host || seen.has(host)) continue;
    seen.add(host);
    const r = analyzeDomain(host, 'link');
    score += r.score;
    findings.push(...r.findings);
    reasons.push(...r.reasons);
  }
  return { score: Math.min(score, 60), findings, reasons };
}

export function classifySeverity(score: number): Severity {
  if (score >= 40) return 'threat';
  if (score >= 20) return 'caution';
  if (score >= 12) return 'unknown';
  return 'safe';
}

export function runFullAnalysis(url: string, text: string): ScamAnalysis {
  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {}
  const isRealPage = /^https?:/i.test(url) && hostname && hostname !== 'pasted.local';

  const content = analyzeContent(text);
  const links = analyzeLinks(text);
const domain = isRealPage ? analyzeDomain(hostname, 'page') : { score: 0, findings: [], reasons: [] };
  if (isRealPage) {
  const mismatch = detectBrandDomainMismatch(
    hostname,
    text,
    content.findings
  );

  if (mismatch) {
    domain.score += 25;
    domain.reasons.push(
      `${mismatch.brand} mentioned on non-${mismatch.brand} domain`
    );

    domain.findings.push({
      id: crypto.randomUUID(),
      category: 'domain',
      title: 'Brand-domain mismatch',
      severity: 'threat',
      detail: `The page references ${mismatch.brand}, but the current domain is ${mismatch.domain}, not an official ${mismatch.brand} domain.`,
      evidence: {
        hostname,
        brand: mismatch.brand,
      },
      timestamp: Date.now(),
    });
  }
}
  const combinedScore = Math.min(content.score + links.score + domain.score, 100);

  return {
    url,
    hostname: hostname || 'message',
    overallSeverity: classifySeverity(combinedScore),
    score: combinedScore,
    findings: [...content.findings, ...domain.findings, ...links.findings],
    suspicionReasons: [...content.reasons, ...domain.reasons, ...links.reasons],
    timestamp: Date.now(),
  };
}

// ── Domain age via RDAP (optional, async) — used by the live page scanner ──
// RDAP servers send `Access-Control-Allow-Origin: *`, so this works from the extension with
// no backend. A domain registered days ago is one of the strongest phishing signals there is.
const FREE_TLDS_ALWAYS_FLAG = /\.(tk|ml|ga|cf|gq)$/i;
export async function checkDomainAge(hostname: string): Promise<ForensicFinding | null> {
  if (!hostname || /^\d+\.\d+\.\d+\.\d+/.test(hostname)) return null;
  const domain = hostname.replace(/^www\./, '');
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(6000) });
    if (!res.ok) {
      // Free TLDs often have no RDAP record at all — itself a red flag
      return FREE_TLDS_ALWAYS_FLAG.test(domain)
        ? mkAgeFinding('Free-TLD domain, no registry record', 'caution', 'This domain uses a free TLD with no public registration record — common for throwaway phishing sites.', { hostname: domain })
        : null;
    }
    const data = await res.json();
    const reg = (data.events || []).find((e: any) => e.eventAction === 'registration');
    if (!reg?.eventDate) return null;
    const days = Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86400000);
    if (days < 0) return null;
    if (days <= 30)
      return mkAgeFinding(`Domain registered ${days} day${days === 1 ? '' : 's'} ago`, 'threat',
        'This domain is brand new. The vast majority of newly registered domains that reach users this fast are phishing.', { hostname: domain, ageDays: days, registered: reg.eventDate.slice(0, 10) });
    if (days <= 180)
      return mkAgeFinding(`Recently registered domain (${days} days)`, 'caution',
        'The domain is only a few months old — worth extra caution for a site handling money or credentials.', { hostname: domain, ageDays: days, registered: reg.eventDate.slice(0, 10) });
    return null;
  } catch {
    return null; // offline / RDAP down — detection still works without it
  }
}
function mkAgeFinding(title: string, severity: Severity, detail: string, evidence: Record<string, string | number>): ForensicFinding {
  return { id: crypto.randomUUID(), category: 'domain', title, severity, detail, evidence, timestamp: Date.now() };
}

export function extractIntel(text: string) {
  const emails = Array.from(new Set(text.match(INTEL_PATTERNS.email) || []));
  const phones = Array.from(new Set(text.match(INTEL_PATTERNS.phone) || []));
  const phoneDigits = phones.map((p) => p.replace(/\D/g, '').slice(-10));
  return {
    upiIds: Array.from(new Set(text.match(INTEL_PATTERNS.upi) || [])).filter(
      (s) => !/@(gmail|yahoo|outlook|hotmail|icloud|proton|live|rediff)/i.test(s) && !emails.some((e) => e.startsWith(s + '.'))
    ),
    phoneNumbers: phones,
    urls: Array.from(new Set((text.match(INTEL_PATTERNS.url) || []).map((u) => u.replace(/[),.;:]+$/, '')))),
    bankAccounts: Array.from(new Set(text.match(INTEL_PATTERNS.bankAccount) || [])).filter((a) => {
      const d = a.replace(/\D/g, '');
      if (/^[6-9]\d{9}$/.test(d)) return false; // looks like a mobile number, not an account
      return !phoneDigits.some((p) => d.endsWith(p) || p.endsWith(d));
    }),
    emailAddresses: emails,
    names: [] as string[],
  };
}
