// Scam detection heuristics — runs entirely in the browser.
// The LLM is used only for the engagement layer, never for detection.
//
// Approach: verb-anchored content signals (an "ask" verb next to a sensitive term, not the
// bare word) across many Indian scam playbooks, minus negative signals for legitimate bank
// SMS / warnings / transaction alerts, plus link + domain checks. Leetspeak is de-obfuscated
// before matching. Domain age (RDAP) is an optional async check used by the live page scanner.

import type { ForensicFinding, ScamAnalysis, Severity, FormMetadata, LinkMetadata } from './types';

export interface AnalysisContext {
  referenceContent?: boolean;
  credentialForm?: boolean;
  links?: string[];
  linkMetadata?: LinkMetadata[];
  forms?: FormMetadata[];
  trustedCredentialSite?: boolean;
}

function toAsciiHostname(hostname: string): string {
  try {
    return new URL(`https://${hostname}`).hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return hostname.toLowerCase().replace(/\.$/, '');
  }
}

const rx = (s: string) => new RegExp(s, 'i');
const ZERO_WIDTH_AND_FORMAT = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b\u200e\u200f\u202a-\u202e\u2060-\u206f\ufeff\ufff9-\ufffb]/g;
const PUNCTUATION_MAP: Record<string, string> = {
  '\u2010': '-', '\u2011': '-', '\u2012': '-', '\u2013': '-', '\u2014': '-', '\u2212': '-',
  '\u2018': "'", '\u2019': "'", '\u201a': "'", '\u201c': '"', '\u201d': '"',
  '\u2024': '.', '\u3002': '.', '\uff0e': '.', '\u00a0': ' ',
};
const CONFUSABLES: Record<string, string> = {
  '\u0430': 'a', '\u03b1': 'a', '\u0435': 'e', '\u03b5': 'e', '\u043e': 'o', '\u03bf': 'o',
  '\u0440': 'p', '\u03c1': 'p', '\u0441': 'c', '\u03f2': 'c', '\u0445': 'x', '\u03c7': 'x',
  '\u0456': 'i', '\u03b9': 'i', '\u0458': 'j', '\u043a': 'k', '\u03ba': 'k',
  '\u043c': 'm', '\u03bc': 'm', '\u0442': 't', '\u03c4': 't', '\u0443': 'y', '\u03c5': 'y',
  '\u0432': 'b', '\u03b2': 'b', '\u043d': 'h', '\u0433': 'r',
};
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's' };
const OBFUSCATED_WORDS = new Set([
  'otp', 'pin', 'pay', 'password', 'passcode', 'verify', 'account', 'login', 'secure',
  'suspend', 'blocked', 'confirm', 'payment', 'refund', 'bank', 'wallet', 'urgent',
  'recovery', 'backup', 'code', 'kyc', 'share', 'send', 'access', 'approve',
]);

export function normalizeUnicode(text: string): string {
  return text.normalize('NFKC')
    .replace(ZERO_WIDTH_AND_FORMAT, '')
    .replace(/([A-Za-z])[\u200c\u200d]+(?=[A-Za-z])/g, '$1')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, ' ')
    .replace(/[\u2010-\u2015\u2212\u2024\u3002\uff0e\u2018-\u201f\u00a0]/g, (char) => PUNCTUATION_MAP[char] ?? char)
    .replace(/[^\S\n]+/g, ' ')
    .split('\n')
    .map((line) => line.trim())
    .join('\n');
}

function normalizeSpacedWords(text: string): string {
  return text.replace(/\b([a-z])(?:[ \t._\-']+([a-z])){1,}\b/gi, (match) => {
    const joined = match.replace(/[\s._\-']/g, '').toLowerCase();
    return OBFUSCATED_WORDS.has(joined) ? joined : match;
  });
}

function deobfuscate(text: string): string {
  const normalized = normalizeSpacedWords(normalizeUnicode(text));
  return normalized.replace(/[a-z0-9@$]+/gi, (token) => {
    if (!/[a-z]/i.test(token) || !/[013457@$8]/.test(token)) return token;
    const decoded = token.toLowerCase().replace(/[013457@$8]/g, (char) => LEET[char] ?? char);
    return OBFUSCATED_WORDS.has(decoded) ? decoded : token;
  });
}

function normalizeConfusables(text: string): string {
  return text.split(/(\s+)/).map((token) => {
    if (!hasMixedScriptToken(token)) return token;
    return token.replace(/[\u0430\u03b1\u0435\u03b5\u043e\u03bf\u0440\u03c1\u0441\u03f2\u0445\u03c7\u0456\u03b9\u0458\u043a\u03ba\u043c\u03bc\u0442\u03c4\u0443\u0432\u03b2\u043d\u0433]/gi,
      (char) => CONFUSABLES[char.toLowerCase()] ?? char);
  }).join('');
}

function hasMixedScriptToken(text: string): boolean {
  return text.split(/[\s/.:_-]+/).some((token) => {
    let latin = false;
    let nonLatin = false;
    for (const char of token) {
      if (/\p{Script=Latin}/u.test(char)) latin = true;
      else if (/\p{Letter}/u.test(char)) nonLatin = true;
    }
    return latin && nonLatin && token.length >= 4;
  });
}

function detectionText(text: string): string {
  return deobfuscate(normalizeConfusables(text));
}

// ── Building blocks ──────────────────────────────────────────
const ASK = '(?:please\\s+|kindly\\s+)*(?:share|send|give|tell|provide|enter|submit|verify|confirm|read\\s*out|forward|resend|reply\\s*with|type|update|renew|reactivate)';
const CRED = '(?:otp|one[\\s-]?time[\\s-]?password|cvv|c\\.v\\.v|\\bpin\\b|mpin|upi\\s*pin|password|passcode|aadhaar(?:\\s*(?:card|number))?|pan(?:\\s*(?:card|number))?|kyc|card\\s*(?:number|details)|(?:bank\\s*)?account\\s*(?:number|details)|net\\s*banking)';
const SENSITIVE_FIELD_PATTERN = /(?:password|passcode|otp|one[- ]time|cvv|c\.v\.v|pin|card|account|aadhaar|pan|cc-(?:number|exp(?:-month|-year)?|csc))/i;
const PAYMENT_FIELD_PATTERN = /(?:cvv|c\.v\.v|card|cc-(?:number|exp(?:-month|-year)?|csc))/i;

// Positive categories. Each match adds `weight`; the finding's own severity drives display colour.
interface Cat { key: string; title: string; detail: string; severity: Severity; weight: number; res: RegExp[]; }
const CATEGORIES: Cat[] = [
  {
    key: 'credential', title: 'Credential solicitation', severity: 'threat', weight: 40,
    detail: 'Asks you to share an OTP, PIN, CVV, password, Aadhaar or card details. No legitimate service asks for these.',
    res: [
      rx(`${ASK}(?:\\s+(?:me|us|your|the|us\\s+your))?[^.?!\\n]{0,30}${CRED}`),
      rx(`${CRED}[^.?!\\n]{0,25}(?:to|for|and)\\s+(?:verify|confirm|unblock|un-?block|activate|reactivate|proceed|complete|process|receive|update|validate)`),
    ],
  },
  {
    key: 'oauth', title: 'Suspicious authorization request', severity: 'caution', weight: 24,
    detail: 'An authorization or app-permission prompt is paired with an account action or pressure to continue.',
    res: [
      rx('(?:grant|allow|approve|authorize)[^.?!\\n]{0,45}(?:unknown|untrusted|unverified|third[ -]?party|external|suspicious|malicious)[^.?!\\n]{0,25}(?:app|application)[^.?!\\n]{0,50}(?:access|permission)[^.?!\\n]{0,40}(?:account|email|drive|files|data)'),
      rx('(?:grant|allow|approve|authorize)[^.?!\\n]{0,45}(?:app|application)[^.?!\\n]{0,60}(?:access|permission|account)[^.?!\\n]{0,60}(?:password|otp|recovery\\s+code|credentials|suspend|blocked|urgent|immediately|within\\s+\\d+)'),
    ],
  },
  {
    key: 'recovery_code', title: 'Recovery-code theft', severity: 'threat', weight: 40,
    detail: 'Requests a backup or recovery code, which can be used to take over an account.',
    res: [
      rx(`${ASK}[^.?!\\n]{0,40}(?:recovery|backup|authentication)\\s*code`),
      rx('(?:send|provide|give|share|read\\s*out)[^.?!\\n]{0,30}(?:your\\s+)?(?:backup|recovery)\\s*code'),
    ],
  },
  {
    key: 'mfa_approval', title: 'Authentication approval pressure', severity: 'caution', weight: 25,
    detail: 'Pressures you to approve or confirm an authentication request, especially one you did not initiate.',
    res: [
      rx('(?:approve|confirm|accept)[^.?!\\n]{0,35}(?:this\\s+)?(?:sign[ -]?in|login|authentication|mfa|push\\s+request)[^.?!\\n]{0,55}(?:or|otherwise|not\\s+you|did\\s+not\\s+initiate|blocked|suspend|urgent)'),
      rx('(?:repeated|multiple|several)[^.?!\\n]{0,35}(?:sign[ -]?in|login|mfa|authentication)[^.?!\\n]{0,35}(?:approve|confirm|request|prompt)'),
      rx('(?:approve|confirm|accept)[^.?!\\n]{0,25}(?:sign[ -]?in|login|mfa|authentication)[^.?!\\n]{0,20}(?:immediately|now|within\\s+\\d+\\s+minutes?)'),
    ],
  },
  {
    key: 'fake_captcha', title: 'Suspicious CAPTCHA verification', severity: 'threat', weight: 40,
    detail: 'A human-verification prompt is used to trigger a download, run a command, or disclose credentials.',
    res: [
      rx('(?:captcha|verify\\s+you(?:\\s+are|\\x27re)\\s+human)[^.?!\\n]{0,100}(?:download|install|run\\s+(?:this|the)|paste\\s+(?:this|the)|press\\s+win\\s*\\+\\s*r|open\\s+(?:powershell|terminal)|enter\\s+(?:your\\s+)?(?:password|otp|code))'),
    ],
  },
  {
    key: 'shared_document_login', title: 'Shared-document credential bait', severity: 'threat', weight: 40,
    detail: 'A shared file or invoice is paired with an unexpected sign-in or credential request.',
    res: [
      rx('(?:shared|sent|invited you to view|received)[^.?!\\n]{0,50}(?:document|file|invoice|voicemail|sharepoint|onedrive|drive)[^.?!\\n]{0,70}(?:sign[ -]?in|log[ -]?in|verify|enter\\s+(?:your\\s+)?(?:email|password|otp)|credentials)'),
      rx('(?:document|invoice|sharepoint|onedrive|google\\s+drive)[^.?!\\n]{0,45}(?:requires?|need)[^.?!\\n]{0,25}(?:sign[ -]?in|log[ -]?in|password|otp|verify\\s+your\\s+account)'),
    ],
  },
  {
    key: 'callback', title: 'Suspicious callback request', severity: 'caution', weight: 28,
    detail: 'Uses an urgent account or payment claim to direct you to an unverified support number.',
    res: [
      rx('(?:call|dial|phone)[^.?!\\n]{0,40}(?:\\+?\\d[\\d ()-]{7,}\\d)[^.?!\\n]{0,80}(?:cancel|dispute|refund|charge|payment|account|blocked|suspend|urgent|immediately)'),
      rx('(?:unauthorized|suspicious|unknown)[^.?!\\n]{0,25}(?:charge|payment|debit)[^.?!\\n]{0,70}(?:call|dial|contact)[^.?!\\n]{0,35}(?:support|agent|number|\\d{7,})'),
    ],
  },
  {
    key: 'qr_payment', title: 'QR-code payment deception', severity: 'threat', weight: 40,
    detail: 'Pairs scanning a QR code with receiving a refund/payment or with account verification and sensitive details.',
    res: [
      rx('(?:scan|use)[^.?!\\n]{0,30}(?:qr\\s*(?:code)?)[^.?!\\n]{0,70}(?:receive|get|claim|collect)[^.?!\\n]{0,35}(?:refund|money|payment|cashback|prize)'),
      rx('(?:scan|use)[^.?!\\n]{0,30}qr\\s*(?:code)?[^.?!\\n]{0,70}(?:verify|unlock|reactivate|receive\\s+money|refund)[^.?!\\n]{0,50}(?:otp|pin|payment|account|bank)?'),
    ],
  },
  {
  key: 'payment', title: 'Payment demand', severity: 'threat', weight: 40,
  detail: 'Pressures you to pay, transfer or send money — especially when tied to a fee, penalty, threat, reward or account action.',
  res: [
  rx('\\b(?:pay|send|transfer|deposit|remit)\\b[^.?!\\n]{0,60}(?:processing|registration|verification|clearance|security|activation|customs?)\\s+(?:fee|charge|deposit)[^.?!\\n]{0,70}(?:refund|receive|claim|withdraw|unlock|release|reward|prize|job|investment|parcel|account)'),
  rx('(?:processing|registration|security|activation|withdrawal|training|customs?)\\s+(?:fee|charge|deposit)[^.?!\\n]{0,70}(?:pay|transfer|send|receive|refund|withdraw|unlock|job|investment|parcel|account)'),
  rx('\\b(?:pay|send|transfer|deposit|remit)\\b[^.?!\\n]{0,30}(?:₹|rs\\.?|inr)\\s*\\d{2,}[^.?!\\n]{0,30}(?:claim|receive|unlock|release|avoid|verify|reactivate|refund|reward|prize|penalty|fine|fee|charge)'),
  ],
},
  {
    key: 'digital_arrest', title: '"Digital arrest" / courier fraud', severity: 'threat', weight: 40,
    detail: 'Classic "digital arrest" script: a fake courier or officer claims your parcel or identity is linked to a crime.',
    res: [
      rx('digital\\s+arrest[^.?!\\n]{0,45}(?:police|cbi|customs|officer|video\\s*call|arrest|crime|money|account|transfer|do\\s*n[o\']?t\\s+disconnect)'),
      rx('under\\s+(?:digital\\s+)?arrest[^.?!\\n]{0,35}(?:police|officer|court|crime|money|account|transfer)'),
      rx('do\\s*n[o\']?t\\s+disconnect[^.?!\\n]{0,45}(?:police|officer|arrest|crime|video|call|money)'),
      rx('(?:parcel|courier|package|consignment|shipment)[^.?!\\n]{0,40}(?:drugs?|illegal|passport|arrest|seized|customs|narcotic|money\\s*launder)'),
      rx('(?:fedex|dhl|blue\\s*dart|dtdc|indian\\s*post|customs)[^.?!\\n]{0,40}(?:illegal|drugs?|arrest|seized|detain|narcotic)'),
    ],
  },
  {
    key: 'lottery', title: 'Lottery / prize scam', severity: 'threat', weight: 30,
    detail: 'Tells you that you won a lottery, prize or lucky draw — then asks for a fee or details to "release" it.',
    res: [
      rx('(?:won|winner|winning|selected|lucky\\s*winner)[^.?!\\n]{0,35}(?:lottery|prize|lakh|crore|rs\\.?|₹|inr|lucky\\s*draw|reward|gift|kbc|jackpot|bumper)'),
      rx('\\b(?:kbc|kaun\\s*banega|lucky\\s*draw|jackpot|bumper\\s*(?:prize|offer)|lottery\\s*(?:winner|number))\\b[^.?!\\n]{0,50}(?:won|winner|selected|claim|fee|pay|send|prize|reward|account|bank)'),
      rx('congratulation[^.?!\\n]{0,40}(?:won|winner|selected|prize|lottery|lucky|reward)'),
    ],
  },
  {
    key: 'remote_access', title: 'Remote-access tool', severity: 'threat', weight: 40,
    detail: 'Wants you to install screen-sharing or remote-control software, which hands over your device.',
    res: [
      rx('(?:install|download|open|connect|share|grant|give)[^.?!\\n]{0,40}\\b(?:any\\s*desk|anydesk|team\\s*viewer|teamviewer|quick\\s*support|quicksupport|rustdesk|screen[\\s-]?shar|remote\\s+(?:access|control|assistance|desktop))\\b'),
      rx('\\b(?:any\\s*desk|anydesk|team\\s*viewer|teamviewer|quick\\s*support|quicksupport|rustdesk)\\b[^.?!\\n]{0,50}(?:install|download|connect|share\\s+(?:your\\s+)?screen|grant\\s+(?:access|permission))'),
      rx('install[^.?!\\n]{0,30}(?:app|application|software|apk)[^.?!\\n]{0,30}(?:bank|fix|help|resolve|support|verify|update)'),
    ],
  },
  {
    key: 'investment', title: 'Investment / crypto scam', severity: 'threat', weight: 28,
    detail: 'Promises guaranteed or unrealistic returns — a hallmark of investment and crypto fraud.',
    res: [
      rx('(?:guaranteed|assured|fixed|100%)[^.?!\\n]{0,20}(?:returns?|profit|income|doubl)[^.?!\\n]{0,60}(?:invest|deposit|send|transfer|wallet|withdrawal|limited\\s+time)'),
      rx('(?:double|triple|2x|3x)[^.?!\\n]{0,15}(?:your\\s+)?(?:money|investment|amount|capital)[^.?!\\n]{0,50}(?:invest|deposit|send|transfer|wallet|limited\\s+time)'),
      rx('\\d{2,3}\\s*%[^.?!\\n]{0,30}(?:return|profit|monthly|weekly|daily|guaranteed)[^.?!\\n]{0,55}(?:invest|deposit|send|transfer|wallet|withdrawal)'),
      rx('\\b(?:usdt|bitcoin|btc|crypto|forex|trading\\s*account)\\b[^.?!\\n]{0,45}(?:invest|profit|return)[^.?!\\n]{0,40}(?:deposit|send|transfer|wallet|withdrawal)'),
    ],
  },
  {
    key: 'job', title: 'Fake job / task scam', severity: 'caution', weight: 22,
    detail: 'Work-from-home or "like and earn" task offers are a common front for advance-fee and money-mule scams.',
    res: [
      rx('(?:part[\\s-]?time|work\\s+from\\s+home|online|home[\\s-]?based)\\s+job[^.?!\\n]{0,70}(?:registration\\s+fee|training\\s+fee|security\\s+deposit|pay\\s+to\\s+start|telegram|whatsapp|like\\s+and\\s+earn)'),
      rx('earn[^.?!\\n]{0,20}(?:rs\\.?|₹|inr|\\d{3,})[^.?!\\n]{0,12}(?:per\\s*day|/\\s*day|daily|per\\s*task|weekly|from\\s*home)'),
      rx('(?:like|subscribe|rate|review|complete)[^.?!\\n]{0,20}(?:videos?|youtube|tasks?|hotels?|apps?)[^.?!\\n]{0,25}(?:earn|paid|money|salary|telegram|whatsapp)'),
    ],
  },
  {
    key: 'refund', title: 'Fake refund / cashback bait', severity: 'caution', weight: 22,
    detail: 'A "pending refund" or "cashback" you must claim through a link is a common phishing hook.',
    res: [
      rx('(?:pending|claim\\s*(?:your)?|get\\s*(?:your)?)\\s*(?:refund|cashback)[^.?!\\n]{0,65}(?:pay|fee|charge|deposit|otp|pin|password|click|link|verify|account)'),
      rx('(?:refund|cashback)[^.?!\\n]{0,35}(?:pay|fee|charge|deposit|otp|pin|password|click|claim|link|verify|expire|pending)'),
      rx('(?:pay|send|transfer)[^.?!\\n]{0,40}(?:fee|charge|deposit)[^.?!\\n]{0,55}(?:refund|cashback|claim your refund)'),
    ],
  },
  {
    key: 'family', title: 'Family-impersonation scam', severity: 'caution', weight: 24,
    detail: 'A "new number" from a relative asking for urgent money is a widespread impersonation scam.',
    res: [
      rx('\\b(?:hi|hello|hey)\\s+(?:mom|mum|mummy|dad|papa|beta|son|uncle|aunty)\\b[^\\n]{0,100}(?:send|transfer|pay)[^\\n]{0,45}(?:money|₹|rs\\.?|\\d{3,}|hospital|accident|emergency)'),
      rx('(?:this\\s+is\\s+my\\s+new\\s+number|new\\s+number|changed\\s+my\\s+number|lost\\s+my\\s+phone|phone\\s+(?:broke|is\\s+broken|got\\s+damaged|not\\s+working))[^\\n]{0,100}(?:send|transfer|pay)[^\\n]{0,45}(?:money|₹|rs\\.?|\\d{3,}|hospital|accident|emergency)'),
    ],
  },
  {
    key: 'utility', title: 'Utility disconnection scam', severity: 'caution', weight: 26,
    detail: 'Threats to cut electricity, gas or a SIM unless you act immediately are a common pressure scam.',
    res: [
      rx('(?:electricity|power|gas|sim\\s*card)[^.?!\\n]{0,30}(?:disconnect|will\\s+be\\s+(?:cut|disconnected|deactivated|blocked)|deactivat)[^.?!\\n]{0,100}(?:pay|immediately|urgent|within\\s+\\d+|click|update)'),
      rx('(?:electricity|power|gas|sim\\s*card)[^.?!\\n]{0,35}(?:disconnect|will\\s+be\\s+(?:cut|disconnected|deactivated|blocked)|deactivat)[^\\n]{0,100}(?:pay|immediately|urgent|within\\s+\\d+|click|update)'),
    ],
  },
  {
    key: 'account_threat', title: 'Account block/expiry threat', severity: 'caution', weight: 20,
    detail: 'Warns that your account, card or KYC is blocked or expired to pressure you into acting.',
    res: [
      rx('(?:account|a/c|card|kyc|pan|aadhaar|wallet|sim)\\b[^.?!\\n]{0,25}(?:is|are|has\\s+been|will\\s+be)?[^.?!\\n]{0,10}(?:blocked|suspend|frozen|deactivat|expired|on\\s+hold|closed|de-?activat)[^.?!\\n]{0,55}(?:update|verify|click|call|contact|immediately|urgent|within\\s+\\d+|otp|password)'),
    ],
  },
  {
    key: 'link_bait', title: 'Click-the-link bait', severity: 'caution', weight: 15,
    detail: 'Urges you to click a link to verify, claim or update — the delivery mechanism for most phishing.',
    res: [
  rx('(?:click|tap|open|visit)[^.?!\\n]{0,20}(?:here|this\\s+link|the\\s+link|below)[^.?!\\n]{0,35}(?:verify|update|claim|login|log\s*in|kyc|refund|account)'),
],
  },
];

const REFERENCE_CUES = [
  /\b(?:how to (?:spot|identify|avoid|report|recognize)|protect yourself from|scam awareness|fraud awareness|phishing awareness|security advisory|security research|training material|educational resource|scam[- ]?(?:detection|classifier|scenario|playbook))\b/i,
  /\b(?:awareness|security|safety)\s+(?:guide|article|training|resource)\b/i,
  /\b(?:scam|fraud|phishing)\s+(?:examples?|patterns?|indicators?|tactics?|scripts?|warnings?)\b/i,
  /\b(?:this|the)\s+(?:article|guide|document|report|repository|project)\s+(?:explains?|describes?|documents?|demonstrates?|contains?)\b/i,
];
const REFERENCE_TERMS = /\b(?:article|guide|documentation|docs|research|tutorial|awareness|training|educational|examples?|sample|repository|source code|security report|warning|advisory)\b/gi;

export function isReferenceContent(text: string): boolean {
  if (REFERENCE_CUES.some((pattern) => pattern.test(text))) return true;
  const terms = text.match(REFERENCE_TERMS)?.length ?? 0;
  return terms >= 3 && /\b(?:scam|fraud|phishing|security|credential|otp)\b/i.test(text);
}

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
  phone: /(?<!\d)(?:\+91[-\s]?|0)?[6-9]\d{9}(?!\d)/g,
  url: /(?:https?(?::|%3a)(?:\/|%2f){2}|(?:https?:)?\/\/)[^\s"'<>]+|\bwww\.[^\s"'<>]+/gi,
  bankAccount: /(?<!\d)\d{9,18}(?!\d)/g,
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

export function analyzeContent(text: string, context: AnalysisContext = {}): { score: number; findings: ForensicFinding[]; reasons: string[] } {
  const findings: ForensicFinding[] = [];
  const reasons: string[] = [];
  const normalizedOriginal = normalizeUnicode(text);
  const normalized = detectionText(normalizedOriginal);
  const deob = normalized;
  const referenceContent = context.referenceContent ?? isReferenceContent(normalized);
  let score = 0;
  const finding = (category: ForensicFinding['category'], title: string, severity: Severity, detail: string, evidence: Record<string, string | number>) =>
    findings.push({ id: crypto.randomUUID(), category, title, severity, detail, evidence, timestamp: Date.now() });

  // Negative signals first (legitimate-message markers)
  let credit = 0;
  const neg = new Set<string>();
  for (const n of NEGATIVE) if (n.re.test(normalized)) { credit += n.weight; neg.add(n.key); }
  const otpDelivery = neg.has('otp_delivery') || neg.has('otp_delivery2');

  // Positive categories
  for (const c of CATEGORIES) {
    // An OTP-delivery message ("your OTP is 1234") must not count as credential solicitation
    if (c.key === 'credential' && otpDelivery) continue;
    const routineCredentialEntry = c.key === 'credential'
      && context.trustedCredentialSite
      && /(?:enter|submit|type|input|provide|update)[^.?!\n]{0,35}(?:otp|one[\s-]?time|cvv|pin|password|passcode|kyc|aadhaar|card\s*(?:number|details)|account\s*(?:number|details))/i.test(deob);
    const credentialTransfer = /(?:share|send|give|tell|read\s*out|reply\s*with)[^.?!\n]{0,45}(?:otp|one[\s-]?time|cvv|pin|password|passcode|kyc|aadhaar|card\s*(?:number|details)|account\s*(?:number|details))/i.test(deob);
    if (routineCredentialEntry && !credentialTransfer) continue;
    const { hit } = anyHit(c.res, normalized, deob);
    if (hit) {
      score += c.weight;
      reasons.push(c.title);
      finding('content', c.title, c.severity, c.detail, { signal: c.key });
    }
  }

  // Urgency (supporting signal)
  const urgencyCount = countHits(URGENCY, normalized);
  if (urgencyCount > 0) {
    score += Math.min(urgencyCount * 2, 6);
    reasons.push(`Urgency / time pressure (${urgencyCount})`);
    finding('content', 'Urgency pressure language', urgencyCount > 2 ? 'threat' : 'caution',
      'Artificial time pressure is a core social-engineering tactic; real institutions rarely demand instant action.', { count: urgencyCount });
  }
  // Strong combination: credential collection + account threat is much more
  // suspicious than either signal alone.
  const hasCredential = findings.some((f) => f.title === 'Credential solicitation');
  const hasAccountThreat = findings.some((f) => f.title === 'Account block/expiry threat')
    || (hasCredential && /(?:account|a\/c|card|kyc|wallet|sim)[^.?!\n]{0,55}(?:blocked|suspend|frozen|deactivat|expired|on\s+hold|closed)/i.test(normalized));

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
  // Authority impersonation — only counts alongside a threat/pressure signal, so a neutral
  // "Income Tax Dept: your ITR was processed" doesn't get flagged.
  const authority = anyHit(AUTHORITY, normalized, deob);
  if (authority.hit && (score > 0 || urgencyCount > 0)) {
    score += 18;
    reasons.push('Authority impersonation');
    finding('content', 'Impersonation of authority', 'threat',
      'Invokes a government body or regulator to intimidate — legitimate agencies do not demand money or codes over chat.', { signal: 'authority-mention' });
  }

  // Brand impersonation — only alongside credential/payment/link activity
  const brand = anyHit(BRANDS, normalized, deob);
  const activity = findings.some((f) => ['Credential solicitation', 'Payment demand', 'Click-the-link bait', 'Fake refund / cashback bait', 'Recovery-code theft', 'Suspicious authorization request', 'Shared-document credential bait'].includes(f.title));
  if (brand.hit && activity) {
    score += 10;
    reasons.push('Impersonated brand + suspicious activity');
    finding('content', 'Brand impersonation', 'threat', 'References a well-known brand next to a credential, payment or link request.', { brand: brand.example });
  }

  const directSensitiveAsk = normalized.split(/[.?!\n]+/).some((sentence) => {
    const requestPattern = /(?:share|send|give|tell|provide|enter|submit|read\s*out|reply\s*with|बताएं|भेजें|डालें|साझा|दर्ज)[^.?!\n]{0,45}(?:otp|one[\s-]?time|pin|cvv|password|kyc|aadhaar|खाता|ओटीपी)/gi;
    let match: RegExpExecArray | null;
    while ((match = requestPattern.exec(sentence))) {
      const preceding = sentence.slice(Math.max(0, match.index - 35), match.index);
      if (!/(?:never|don't|do\s+not|dont)\s*$/i.test(preceding)) return true;
    }
    return false;
  });
  const separateExplicitRequest = /\bbut\b[^.?!\n]{0,20}(?:send|give|tell|provide|submit|read\s*out|reply\s*with|share)[^.?!\n]{0,45}(?:otp|one[\s-]?time|pin|cvv|password|kyc|aadhaar|account)/i.test(normalized);
  const unambiguousSensitiveTransfer = /\b(?:send|give|provide|tell|read\s*out|reply\s*with)\b[^.?!\n]{0,45}(?:otp|one[\s-]?time|pin|cvv|password|kyc|aadhaar|account|recovery\s*code|backup\s*code)/i.test(normalized);
  const hasActiveSensitiveAsk = directSensitiveAsk || separateExplicitRequest || unambiguousSensitiveTransfer;
  const hasUnquotedSensitiveRequest = normalized.split(/[.?!\n]+/).some((sentence) => {
    const explanatoryContext = /\b(?:example|sample|quote|scammers?|attackers?|criminals?|fraudsters?)\b/i.test(sentence);
    return !explanatoryContext && /(?:share|send|give|tell|provide|enter|submit|read\s*out|reply\s*with)\b[^.?!\n]{0,45}(?:otp|one[\s-]?time|pin|cvv|password|kyc|aadhaar|account|recovery\s*code|backup\s*code)/i.test(sentence);
  });
  const explicitWarning = /\b(?:never|do\s+not|don't|dont)\s+(?:share|disclose|reveal|give|send)\b[^.?!\n]{0,45}\b(?:otp|pin|cvv|password|code|card|kyc|bank|details)\b/i.test(normalized)
    || /\b(?:warns?|warning|advisory|beware|awareness|protect yourself)\b[^.?!\n]{0,90}\b(?:fraud|scam|phishing|otp|pin|kyc)\b/i.test(normalized);
  if (explicitWarning && !hasActiveSensitiveAsk) {
    score = 0;
    findings.length = 0;
    reasons.length = 0;
  } else if (referenceContent && !hasUnquotedSensitiveRequest) {
    if (!context.credentialForm) {
      score = 0;
      findings.length = 0;
      reasons.length = 0;
    } else {
      score = Math.round(score * 0.35);
    }
  } else {
    score = Math.max(0, score - (hasActiveSensitiveAsk ? 0 : Math.min(credit, 25)));
  }
  if (score === 0) {
    findings.length = 0;
    reasons.length = 0;
  }

  // Hindi/Hinglish solicitations combine the sensitive term with a request verb rather
  // than English word order; the ordinary category patterns don't cover those inflections.
  if (!referenceContent && (!explicitWarning || hasActiveSensitiveAsk) && HAS_DEVANAGARI.test(normalized) && SENSITIVE_TERM.test(deob) && /(?:बताएं|बताओ|भेजें|भेजो|डालें|डालो|साझा|दर्ज|अपडेट\s*करें|करें)/.test(normalized) && !findings.some((f) => f.title === 'Credential solicitation')) {
    score += 40;
    reasons.push('Credential solicitation');
    finding('content', 'Credential solicitation', 'threat',
      'Requests a sensitive code or account detail in Hindi/Hinglish.', { signal: 'localized-credential-request' });
  }
  const detectionLines = normalized.split('\n');
  const originalLines = normalizedOriginal.split('\n');
  const mixedScriptInSuspiciousUnit = detectionLines.some((line, index) =>
    hasMixedScriptToken(originalLines[index] ?? '')
      && CATEGORIES.some((category) =>
        ['credential', 'payment', 'refund'].includes(category.key)
          && anyHit(category.res, line, line).hit
      )
  );
  if (mixedScriptInSuspiciousUnit && findings.some((f) => f.title === 'Credential solicitation' || f.title === 'Brand impersonation' || f.title === 'Fake refund / cashback bait')) {
    score += 3;
    finding('content', 'Mixed-script text in suspicious request', 'caution',
      'A suspicious request contains visually confusable characters from multiple writing systems.', { signal: 'mixed-script-supporting' });
  }
  if (referenceContent && context.credentialForm && score > 0) {
    const effectiveSeverity = classifySeverity(score);
    const severityRank: Record<Severity, number> = { safe: 0, unknown: 1, caution: 2, threat: 3 };
    for (const item of findings) {
      if (severityRank[item.severity] > severityRank[effectiveSeverity]) item.severity = effectiveSeverity;
    }
  }
  return { score: Math.min(score, 100), findings, reasons };
}

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.buzz', '.rest', '.cyou'];
const LOWER_SIGNAL_TLDS = ['.link', '.info', '.live', '.online', '.shop', '.work'];
const SHORTENERS = /\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rebrand\.ly|ow\.ly|shorturl\.at|rb\.gy|t\.ly)\b/i;
const BRAND_DOMAIN_RULES = [
  { name: 'PayPal', pattern: /\bpaypal\b/i, domains: ['paypal.com', 'paypal.co.uk', 'paypal.com.au', 'paypal.ca', 'paypal.de', 'paypal.fr', 'paypal.it', 'paypal.es', 'paypal.jp'] },

  { name: 'SBI', pattern: /\bsbi\b|state\s+bank\s+of\s+india/i, domains: ['sbi.bank.in', 'sbi.co.in', 'onlinesbi.sbi'] },
  { name: 'HDFC Bank', pattern: /\bhdfc\b/i, domains: ['hdfc.bank.in', 'hdfcbank.com'] },
  { name: 'ICICI Bank', pattern: /\bicici\b/i, domains: ['icici.bank.in', 'icicibank.com'] },
  { name: 'Axis Bank', pattern: /\baxis\s+bank\b/i, domains: ['axis.bank.in', 'axisbank.com'] },
  { name: 'Kotak', pattern: /\bkotak\b/i, domains: ['kotak.bank.in', 'kotak.com'] },
  { name: 'PNB', pattern: /\bpnb\b|punjab\s+national\s+bank/i, domains: ['pnb.bank.in', 'pnbindia.in'] },

  { name: 'Paytm', pattern: /\bpaytm\b/i, domains: ['paytm.com'] },
  { name: 'PhonePe', pattern: /\bphonepe\b/i, domains: ['phonepe.com'] },

  { name: 'Amazon', pattern: /\bamazon\b/i, domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.com.au', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.co.jp'] },
  { name: 'Flipkart', pattern: /\bflipkart\b/i, domains: ['flipkart.com'] },
  { name: 'Myntra', pattern: /\bmyntra\b/i, domains: ['myntra.com'] },
  { name: 'Netflix', pattern: /\bnetflix\b/i, domains: ['netflix.com'] },

  { name: 'WhatsApp', pattern: /\bwhatsapp\b/i, domains: ['whatsapp.com'] },
  { name: 'Google', pattern: /\bgoogle\b/i, domains: ['google.com', 'google.co.uk', 'google.co.in', 'google.com.au', 'google.ca', 'google.de', 'google.fr', 'google.co.jp', 'google.co.nz', 'google.com.br'] },
  { name: 'Google Pay', pattern: /\bgpay\b|\bgoogle\s+pay\b/i, domains: ['google.com', 'pay.google.com', 'google.co.in'] },
  { name: 'Apple', pattern: /\bapple\b/i, domains: ['apple.com'] },
  { name: 'Microsoft', pattern: /\bmicrosoft\b/i, domains: ['microsoft.com'] },
  { name: 'Instagram', pattern: /\binstagram\b/i, domains: ['instagram.com'] },
  { name: 'Facebook', pattern: /\bfacebook\b/i, domains: ['facebook.com'] },
  { name: 'LinkedIn', pattern: /\blinkedin\b/i, domains: ['linkedin.com'] },

  { name: 'NPCI', pattern: /\bnpci\b/i, domains: ['npci.org.in'] },
  { name: 'IRCTC', pattern: /\birctc\b/i, domains: ['irctc.co.in'] },
];
const BRAND_DOMAIN_ALIASES: Record<string, string[]> = {
  SBI: ['onlinesbi'],
};
function brandRuleForText(text: string) {
  return BRAND_DOMAIN_RULES.find((rule) => rule.pattern.test(text));
}

function isOfficialDomainForBrand(hostname: string, rule: typeof BRAND_DOMAIN_RULES[number]): boolean {
  const domain = toAsciiHostname(hostname);
  return rule.domains.some((official) => domain === official || domain.endsWith(`.${official}`));
}

function isOfficialBrandDomain(hostname: string, text: string): boolean {
  return BRAND_DOMAIN_RULES.some((rule) =>
    rule.pattern.test(text) && isOfficialDomainForBrand(hostname, rule)
  );
}

function editDistanceAtMostOne(a: string, b: string): boolean {
  if (Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  let j = 0;
  let edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      i++;
      j++;
      continue;
    }
    if (++edits > 1) return false;
    if (a.length > b.length) i++;
    else if (b.length > a.length) j++;
    else {
      i++;
      j++;
    }
  }
  return edits + Number(i < a.length || j < b.length) <= 1;
}

function brandHostnameEvidence(hostname: string, rule?: typeof BRAND_DOMAIN_RULES[number]): string[] {
  const allowedRules = rule ? [rule] : BRAND_DOMAIN_RULES;
  const labels = canonicalHostname(hostname).split('.');
  const candidates = labels.flatMap((label) => normalizeConfusables(label).split('-').filter(Boolean).map((token) => token.replace(/1/g, 'l').replace(/0/g, 'o')));
  const joinedLabels = labels.map((label) => normalizeConfusables(label).replace(/-/g, '').replace(/1/g, 'l').replace(/0/g, 'o'));
  const matched: string[] = [];
  for (const brandRule of allowedRules) {
    const brand = brandRule.name.toLowerCase().replace(/[^a-z0-9]/g, '');
    const aliases = (BRAND_DOMAIN_ALIASES[brandRule.name] || []).map((alias) => alias.toLowerCase());
    const official = isOfficialDomainForBrand(hostname, brandRule);
    const exactOrTypo = candidates.some((candidate) => editDistanceAtMostOne(candidate, brand));
    const deceptiveSuffix = joinedLabels.some((label) =>
      [brand, ...aliases].some((name) =>
        label.startsWith(name) && label.length > name.length
          && /^(?:login|secure|security|verify|account|support|service|online|payment|signin|update|bank|-)/.test(label.slice(name.length))
      )
    );
    const separatedBrandClaim = labels.some((label) =>
      [brand, ...aliases].some((name) => label.startsWith(`${name}-`) || label === name)
    );
    const hyphenJoinedBrand = joinedLabels.some((label) =>
      [brand, ...aliases].some((name) => label.startsWith(name) && label !== name)
    );
    if (!official && (exactOrTypo || deceptiveSuffix || separatedBrandClaim || hyphenJoinedBrand)) matched.push(brandRule.name);
  }
  return matched;
}

function detectBrandDomainMismatch(
  hostname: string,
  text: string,
  findings: ForensicFinding[],
  context: AnalysisContext,
): { brand: string; domain: string; strong: boolean }[] {
  const mismatches: { brand: string; domain: string; strong: boolean }[] = [];
  const pageDomain = getDomainParts(hostname).registrableDomain;
  const actionableTitles = new Set([
    'Credential solicitation', 'Payment demand', 'Click-the-link bait',
    'Fake refund / cashback bait', 'Account block/expiry threat',
  ]);
  const hasActionableFinding = findings.some((finding) => actionableTitles.has(finding.title));
  const trustedProviders = ['stripe.com', 'paypal.com', 'adyen.com', 'checkout.com', 'google.com', 'microsoftonline.com'];

  for (const rule of BRAND_DOMAIN_RULES) {
    if (isOfficialDomainForBrand(hostname, rule)) continue;
    const hostnameClaim = brandHostnameEvidence(hostname, rule).length > 0;
    let strong = false;
    for (const form of context.forms || []) {
      if (!form.fields.some((field) => SENSITIVE_FIELD_PATTERN.test(field))) continue;
      const localContexts = form.sensitiveContexts !== undefined
        ? form.sensitiveContexts
          .filter((item) => SENSITIVE_FIELD_PATTERN.test(item.field))
          .map((item) => item.identityText)
        : [form.identityText !== undefined
          ? form.identityText
          : [
            ...(form.contextScope === 'section' || form.contextScope === 'article' ? [] : [form.contextText || '']),
            form.buttonText,
            form.labelText,
            ...form.fields,
          ].filter(Boolean).join('\n')];

      for (const localText of localContexts) {
        const localBrandClaim = rule.pattern.test(localText)
          && /\b(?:login|log\s*in|sign[ -]?in|verify|verification|account|password|passcode|otp|pin|cvv|card|suspended|blocked|restore|reactivate)\b/i.test(localText);
        if (!localBrandClaim) continue;
        if (hostnameClaim) {
          strong = true;
          break;
        }

        const destination = hostFromUrl(cleanUrl(form.action));
        if (!destination) continue;
        const destinationDomain = getDomainParts(destination).registrableDomain;
        if (!destinationDomain || destinationDomain === pageDomain
          || trustedProviders.some((provider) => destinationDomain === provider || destinationDomain.endsWith(`.${provider}`))) continue;
        const destinationSignals = analyzeDomain(destination, 'link').findings;
        if (brandHostnameEvidence(destination, rule).length > 0
          || destinationSignals.some((finding) => ['Suspicious TLD', 'URL shortener', 'Raw IP address'].includes(finding.title))) {
          strong = true;
          break;
        }
      }
      if (strong) break;
    }

    const relatedTextAction = text.split('\n').some((line) =>
      rule.pattern.test(line)
        && /\b(?:share|send|give|enter|submit|verify|update|log\s*in|login|sign[ -]?in|suspended|blocked|restore|reactivate)\b/i.test(line)
        && /\b(?:account|password|passcode|otp|pin|cvv|card|payment|refund|kyc)\b/i.test(line)
    );
    if (strong || (hasActionableFinding && relatedTextAction)) {
      mismatches.push({ brand: rule.name, domain: canonicalHostname(hostname), strong });
    }
  }
  return mismatches;
}

function decodePunycodeLabel(label: string): string {
  if (!label.startsWith('xn--')) return label;
  const input = label.slice(4);
  const output: number[] = [];
  const delimiter = input.lastIndexOf('-');
  let index = 0;
  if (delimiter >= 0) {
    for (const char of input.slice(0, delimiter)) output.push(char.codePointAt(0)!);
    index = delimiter + 1;
  }
  let n = 128;
  let bias = 72;
  let insertion = 0;
  while (index < input.length) {
    const oldIndex = insertion;
    let accumulator = insertion;
    let weight = 1;
    for (let k = 36; ; k += 36) {
      if (index >= input.length) return label;
      const code = input.charCodeAt(index++);
      const digit = code >= 48 && code <= 57 ? code - 22 : code >= 65 && code <= 90 ? code - 65 : code >= 97 && code <= 122 ? code - 97 : 36;
      if (digit >= 36) return label;
      if (digit > Math.floor((0x7fffffff - accumulator) / weight)) return label;
      accumulator += digit * weight;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) {
        const points = output.length + 1;
        let adapted = oldIndex === 0 ? Math.floor((accumulator - oldIndex) / 700) : Math.floor((accumulator - oldIndex) / 2);
        adapted += Math.floor(adapted / points);
        let threshold = 0;
        while (adapted > 455) {
          adapted = Math.floor(adapted / 35);
          threshold += 36;
        }
        bias = threshold + Math.floor(36 * adapted / (adapted + 38));
        n += Math.floor(accumulator / points);
        accumulator %= points;
        output.splice(accumulator, 0, n);
        insertion = accumulator + 1;
        break;
      }
      weight *= 36 - t;
    }
  }
  try {
    return String.fromCodePoint(...output);
  } catch {
    return label;
  }
}

function canonicalHostname(hostname: string): string {
  const host = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  return host.split('.').map(decodePunycodeLabel).join('.');
}

const MULTI_LABEL_SUFFIXES = new Set([
  'co.in', 'com.in', 'net.in', 'org.in', 'gen.in', 'firm.in',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
  'co.jp', 'co.nz', 'com.br', 'com.sg', 'com.mx', 'co.za',
]);

export function getDomainParts(hostname: string): { hostname: string; subdomain: string; registrableDomain: string } {
  const normalized = canonicalHostname(hostname);
  const labels = normalized.split('.').filter(Boolean);
  const suffix = labels.slice(-2).join('.');
  const multiLabelSuffix = MULTI_LABEL_SUFFIXES.has(suffix);
  const domainLabels = labels.length <= (multiLabelSuffix ? 2 : 1)
    ? []
    : labels.slice(-(multiLabelSuffix ? 3 : 2));
  const registrableDomain = domainLabels.join('.');
  return {
    hostname: normalized,
    registrableDomain,
    subdomain: labels.slice(0, Math.max(0, labels.length - domainLabels.length)).join('.'),
  };
}

export function analyzeDomain(hostname: string, source: 'page' | 'link' = 'page'): { score: number; findings: ForensicFinding[]; reasons: string[] } {
  const findings: ForensicFinding[] = [];
  const reasons: string[] = [];
  let score = 0;
  const normalizedHostname = canonicalHostname(hostname);
  const where = source === 'link' ? 'Link in message' : 'Page domain';
  const add = (title: string, severity: Severity, detail: string, weight: number, reason: string) => {
    score += weight;
    reasons.push(reason);
    findings.push({ id: crypto.randomUUID(), category: 'domain', title, severity, detail, evidence: { hostname: normalizedHostname, source: where }, timestamp: Date.now() });
  };

  if (SUSPICIOUS_TLDS.some((t) => normalizedHostname.endsWith(t)))
    add('Suspicious TLD', 'unknown', 'Top-level domain is disproportionately used by short-lived phishing pages; this is a supporting signal only.', 12, `Uncommon TLD (${where.toLowerCase()})`);
  else if (LOWER_SIGNAL_TLDS.some((t) => normalizedHostname.endsWith(t)))
    add('Less-common TLD', 'unknown', 'This top-level domain is less common but is not suspicious by itself.', 4, `Less-common TLD (${where.toLowerCase()})`);
  const brandEvidence = brandHostnameEvidence(normalizedHostname);
  if (brandEvidence.length)
    add('Brand-lookalike domain', 'unknown', 'A hostname label resembles a known brand; this is a supporting signal until page identity or activity corroborates it.', 8, 'Potential brand-lookalike hostname');
  if (SHORTENERS.test(normalizedHostname))
    add('URL shortener', 'unknown', 'Shortened links obscure their destination; this is supporting evidence only.', 8, 'Shortened link hides destination');
  if ((normalizedHostname.match(/-/g) || []).length > 2)
    add('Hyphen-heavy hostname', 'unknown', 'Many hyphens can obscure a hostname; this is supporting evidence only.', 4, 'Excessive hyphens in hostname');
  const octets = normalizedHostname.split('.');
  if (octets.length === 4 && octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255))
    add('Raw IP address', 'unknown', 'A raw IP address is unusual for a public login/payment site; this is supporting evidence only.', 10, 'Raw IP address in URL');

  return { score: Math.min(score, 18), findings, reasons };
}

function hostnameInfrastructureScore(findings: ForensicFinding[]): number {
  const weights: Record<string, number> = {
    'Suspicious TLD': 12,
    'Less-common TLD': 4,
    'URL shortener': 8,
    'Hyphen-heavy hostname': 4,
    'Raw IP address': 10,
  };
  return findings.reduce((total, finding) => total + (weights[finding.title] || 0), 0);
}

// Domains that legitimately use punycode / long labels shouldn't be re-flagged endlessly
function hostFromUrl(u: string): string | null {
  try {
    return new URL(u.startsWith('//') ? `https:${u}` : /^https?:\/\//i.test(u) ? u : `https://${u}`).hostname;
  } catch {
    return null;
  }
}

function decodeUrlEncoding(value: string): string {
  let decoded = value;
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

function urlsInText(text: string): string[] {
  const direct = text.match(INTEL_PATTERNS.url) || [];
  const encoded = (text.match(/(?:%[0-9a-f]{2}){3,}[^\s"'<>]*/gi) || [])
    .map(decodeUrlEncoding)
    .filter((value) => /^(?:https?:\/\/|\/\/|www\.)/i.test(value));
  return [...direct, ...encoded];
}

function cleanUrl(value: string): string {
  try {
    const trimmed = decodeUrlEncoding(value).replace(/[),.;:!?'"'<>]+$/, '');
    const url = new URL(trimmed.startsWith('//') ? `https:${trimmed}` : /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return value.replace(/[)\]},.;:!?'"'<>]+$/, '');
  }
}

function analyzeLinks(text: string, linkUrls: string[] = [], pageHostname = '', linkMetadata: LinkMetadata[] = []): { score: number; findings: ForensicFinding[]; reasons: string[] } {
  const urls = Array.from(new Set([
    ...urlsInText(text),
    ...linkUrls,
  ].map(cleanUrl)));
  const seen = new Set<string>();
  let score = 0;
  const findings: ForensicFinding[] = [];
  const reasons: string[] = [];
  for (const u of urls.slice(0, 30)) {
    const host = hostFromUrl(u);
    const normalizedHost = host ? canonicalHostname(host) : '';
    const currentHost = pageHostname ? canonicalHostname(pageHostname) : '';
    if (!normalizedHost || seen.has(normalizedHost) || normalizedHost === currentHost) continue;
    seen.add(normalizedHost);
    const r = analyzeDomain(normalizedHost, 'link');
    if (currentHost) {
      const currentRegistrable = getDomainParts(currentHost).registrableDomain;
      const linkRegistrable = getDomainParts(normalizedHost).registrableDomain;
      const sameSite = currentRegistrable && currentRegistrable === linkRegistrable;
      const meaningfulSubdomainRisk = r.findings.some((f) =>
        f.title === 'Brand-lookalike domain' || f.title === 'URL shortener'
      );
      if (sameSite && !meaningfulSubdomainRisk) continue;
    }
    score += r.score;
    findings.push(...r.findings);
    reasons.push(...r.reasons);
  }
  for (const link of linkMetadata.slice(0, 30)) {
    const rule = brandRuleForText(link.label);
    if (!rule) continue;
    const href = hostFromUrl(cleanUrl(link.href));
    if (!href || isOfficialDomainForBrand(href, rule)) continue;
    const destination = analyzeDomain(href, 'link');
    const identityText = /\b(?:login|log\s*in|sign[ -]?in|account|verification|verify|support|payment|wallet)\b/i.test(link.label);
    const riskyDestination = brandHostnameEvidence(href, rule).length > 0
      || destination.findings.some((finding) => ['Suspicious TLD', 'URL shortener', 'Raw IP address'].includes(finding.title));
    if (!identityText || !riskyDestination) continue;
    score += 16;
    reasons.push(`${rule.name} link points to a suspicious destination`);
    findings.push({
      id: crypto.randomUUID(),
      category: 'domain',
      title: 'Brand-destination mismatch',
      severity: 'caution',
      detail: `A link presented as ${rule.name} login or account content points to a non-official suspicious destination.`,
      evidence: { brand: rule.name, hostname: canonicalHostname(href), label: link.label.slice(0, 100) },
      timestamp: Date.now(),
    });
  }
  return { score: Math.min(score, 20), findings, reasons };
}

function sensitiveFields(forms: FormMetadata[] = []): string[] {
  return Array.from(new Set(forms.flatMap((form) => form.fields).filter((field) =>
    SENSITIVE_FIELD_PATTERN.test(field)
  ))).slice(0, 20);
}

function formSignals(forms: FormMetadata[] = [], pageUrl: string): { score: number; findings: ForensicFinding[]; reasons: string[]; fields: string[]; externalDestinations: string[]; paymentFields: boolean } {
  const fields = sensitiveFields(forms);
  const findings: ForensicFinding[] = [];
  const reasons: string[] = [];
  const externalDestinations = new Set<string>();
  let score = 0;
  if (fields.length) {
    score += 3;
    reasons.push('Sensitive form fields detected');
    findings.push({
      id: crypto.randomUUID(),
      category: 'content',
      title: 'Sensitive form fields',
      severity: 'unknown',
      detail: 'The page contains fields whose labels or metadata indicate sensitive information; entered values are not inspected.',
      evidence: { fieldCount: fields.length, fieldTypes: Array.from(new Set(fields.map((field) =>
        field.match(SENSITIVE_FIELD_PATTERN)?.[0].toLowerCase() || 'sensitive'
      ))).join(', ') },
      timestamp: Date.now(),
    });
  }
  let pageOrigin = '';
  try {
    pageOrigin = new URL(pageUrl).origin;
  } catch {}
  for (const form of forms) {
    if (!form.fields.some((field) => SENSITIVE_FIELD_PATTERN.test(field))) continue;
    let action: URL;
    try {
      action = new URL(form.action || pageUrl, pageUrl);
      if (!['http:', 'https:'].includes(action.protocol)) continue;
    } catch {
      continue;
    }
    if (!pageOrigin || action.origin === pageOrigin) continue;
    const destinationHost = canonicalHostname(action.hostname);
    const destinationDomain = getDomainParts(destinationHost).registrableDomain;
    const pageDomain = getDomainParts(new URL(pageUrl).hostname).registrableDomain;
    if (!destinationDomain || destinationDomain === pageDomain) continue;
    const trustedPaymentProviders = ['stripe.com', 'paypal.com', 'adyen.com', 'checkout.com', 'google.com', 'microsoftonline.com'];
    if (trustedPaymentProviders.some((provider) => destinationDomain === provider || destinationDomain.endsWith(`.${provider}`))) continue;
    externalDestinations.add(destinationHost);
  }
  if (externalDestinations.size) {
    score += 12;
    reasons.push('Sensitive form submits to an unrelated external destination');
    findings.push({
      id: crypto.randomUUID(),
      category: 'domain',
      title: 'Sensitive form external destination',
      severity: 'caution',
      detail: 'A form with sensitive fields submits to an unrelated external host; external processing can be legitimate, so this is supporting evidence.',
      evidence: { destinations: Array.from(externalDestinations).slice(0, 3).join(', ') },
      timestamp: Date.now(),
    });
  }
  const paymentFields = fields.some((field) => PAYMENT_FIELD_PATTERN.test(field));
  return { score, findings, reasons, fields, externalDestinations: Array.from(externalDestinations), paymentFields };
}

export function classifySeverity(score: number): Severity {
  if (score >= 40) return 'threat';
  if (score >= 20) return 'caution';
  if (score >= 12) return 'unknown';
  return 'safe';
}

export function runFullAnalysis(url: string, text: string, context: AnalysisContext = {}): ScamAnalysis {
  let hostname = '';
  try {
    hostname = canonicalHostname(new URL(url).hostname);
  } catch {}
  const isRealPage = /^https?:/i.test(url) && hostname && hostname !== 'pasted.local';

  const normalizedText = detectionText(text);
  const referenceContent = context.referenceContent ?? isReferenceContent(normalizedText);
  let asciiHostname = hostname;
  try {
    asciiHostname = new URL(url).hostname;
  } catch {}
  const detectedSensitiveForm = !!context.credentialForm || sensitiveFields(context.forms).length > 0;
  const trustedCredentialSite = !!(isRealPage && detectedSensitiveForm && isOfficialBrandDomain(asciiHostname, normalizedText));
  const content = analyzeContent(text, { ...context, credentialForm: detectedSensitiveForm, trustedCredentialSite });
  const links = analyzeLinks(text, context.links, hostname, context.linkMetadata);
  const domain = isRealPage ? analyzeDomain(hostname, 'page') : { score: 0, findings: [], reasons: [] };
  const forms = formSignals(context.forms, url);
  if (isRealPage) {
    const mismatches = detectBrandDomainMismatch(hostname, normalizedText, content.findings, { ...context, credentialForm: detectedSensitiveForm });
    if (mismatches.length) {
      const strongMismatch = mismatches.some((mismatch) => mismatch.strong);
      const identityScore = strongMismatch ? 38 : 14;
      const infrastructureScore = Math.min(hostnameInfrastructureScore(domain.findings), strongMismatch ? 4 : 6);
      domain.score = identityScore + infrastructureScore;
      domain.reasons.push(`${mismatches.map((mismatch) => mismatch.brand).join(', ')} identity does not match the page domain`);
      if (infrastructureScore) {
        domain.reasons.push(`Hostname infrastructure evidence grouped and capped at ${infrastructureScore} points`);
      }
      for (const mismatch of mismatches) {
        domain.findings.push({
          id: crypto.randomUUID(),
          category: 'domain',
          title: 'Brand-domain mismatch',
          severity: mismatch.strong ? 'threat' : 'caution',
          detail: `The page presents ${mismatch.brand} account or verification identity on ${mismatch.domain}, which is not an official ${mismatch.brand} domain.`,
          evidence: { hostname, brand: mismatch.brand, registrableDomain: getDomainParts(hostname).registrableDomain },
          timestamp: Date.now(),
        });
        if (mismatch.strong) {
          domain.findings.push({
            id: crypto.randomUUID(),
            category: 'domain',
            title: 'Brand impersonation with sensitive form',
            severity: 'threat',
            detail: 'A non-official domain claims a known brand identity while requesting sensitive information.',
            evidence: { brand: mismatch.brand, fieldCount: forms.fields.length },
            timestamp: Date.now(),
          });
        }
      }
    }
    if (forms.paymentFields && content.findings.some((finding) =>
      ['Payment demand', 'Fake refund / cashback bait', 'QR-code payment deception'].includes(finding.title)
    )) {
      forms.score += 14;
      forms.reasons.push('Payment lure paired with card/CVV form fields');
      forms.findings.push({
        id: crypto.randomUUID(),
        category: 'content',
        title: 'Payment lure with card form',
        severity: 'threat',
        detail: 'A payment or refund lure appears alongside card or CVV fields.',
        evidence: { fieldCount: forms.fields.length },
        timestamp: Date.now(),
      });
    }
  }
  const combinedScore = Math.min(content.score + links.score + domain.score + forms.score, 100);

  return {
    url,
    hostname: hostname || 'message',
    overallSeverity: classifySeverity(combinedScore),
    score: combinedScore,
    findings: [...content.findings, ...domain.findings, ...links.findings, ...forms.findings],
    suspicionReasons: [...content.reasons, ...domain.reasons, ...links.reasons, ...forms.reasons],
    timestamp: Date.now(),
  };
}

// ── Domain age via RDAP (optional, async) — used by the live page scanner ──
// Only the hostname is sent to the public RDAP service. Cache successes and failures to avoid
// repeating lookups while a dynamic page is being rescanned.
const ageCache = new Map<string, { expiresAt: number; finding: ForensicFinding | null }>();
const ageRequests = new Map<string, Promise<ForensicFinding | null>>();

function registrableDomain(hostname: string): string {
  return toAsciiHostname(getDomainParts(hostname).registrableDomain);
}

export async function checkDomainAge(hostname: string): Promise<ForensicFinding | null> {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  const octets = normalized.split('.');
  if (!normalized || (octets.length === 4 && octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255))
    || (normalized.startsWith('[') && normalized.endsWith(']'))
    || !normalized.includes('.') || /\.(?:local|localhost|test)$/i.test(normalized)) return null;
  const domain = registrableDomain(normalized);
  if (!domain || !domain.includes('.')) return null;
  const cached = ageCache.get(domain);
  if (cached && cached.expiresAt > Date.now()) return cached.finding;
  const pending = ageRequests.get(domain);
  if (pending) return pending;

  const request = lookupDomainAge(domain);
  ageRequests.set(domain, request);
  try {
    const finding = await request;
    ageCache.set(domain, { expiresAt: Date.now() + (finding ? 6 * 60 * 60 * 1000 : 10 * 60 * 1000), finding });
    if (ageCache.size > 500) ageCache.delete(ageCache.keys().next().value!);
    return finding;
  } finally {
    ageRequests.delete(domain);
  }
}

async function lookupDomainAge(domain: string): Promise<ForensicFinding | null> {
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(6000) });
    if (!res.ok) {
      return null;
    }
    const data = await res.json();
    const reg = (data.events || []).find((e: any) => e.eventAction === 'registration');
    if (!reg?.eventDate) return null;
    const days = Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86400000);
    if (days < 0) return null;
    if (days <= 30)
      return mkAgeFinding(`Domain registered ${days} day${days === 1 ? '' : 's'} ago`, 'caution',
        'This domain is newly registered. Age is a supporting signal, not proof of malicious activity.', { hostname: domain, ageDays: days, registered: reg.eventDate.slice(0, 10) });
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
  const accountContext = /\b(?:bank\s*)?(?:account|a\/c|acct|beneficiary)\b/i;
  const urlValues = urlsInText(text).map(cleanUrl);
  const upiCandidates = text.match(INTEL_PATTERNS.upi) || [];
  return {
    upiIds: Array.from(new Set(upiCandidates)).filter((s) => {
      const email = emails.some((e) => e.toLowerCase() === s.toLowerCase() || e.toLowerCase().startsWith(`${s.toLowerCase()}.`));
      return !email && !/@(gmail|yahoo|outlook|hotmail|icloud|proton|live|rediff)\b/i.test(s);
    }),
    phoneNumbers: phones,
    urls: Array.from(new Set(urlValues)),
    bankAccounts: Array.from(new Set((text.match(INTEL_PATTERNS.bankAccount) || []).filter((a) => {
      const index = text.indexOf(a);
      const surrounding = text.slice(Math.max(0, index - 45), index + a.length + 20);
      const d = a.replace(/\D/g, '');
      return accountContext.test(surrounding) && !/^[6-9]\d{9}$/.test(d) && !phoneDigits.some((p) => d.endsWith(p) || p.endsWith(d));
    }))),
    emailAddresses: emails,
    names: [] as string[],
  };
}
