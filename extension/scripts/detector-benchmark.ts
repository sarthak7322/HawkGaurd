import { checkDomainAge, getDomainParts, normalizeUnicode, runFullAnalysis, extractIntel } from '../src/shared/detection';
import { parseHTML } from 'linkedom';
import { extractFormMetadata, extractLinkMetadata, extractStaticPageText } from '../src/content/form-metadata';
import { shouldRescanForMutations } from '../src/content/mutation-filter';
import { createBoundedDebouncedScan, createSerialScanRunner, createTrackedTimer, type TimerHost } from '../src/content/scan-scheduler';
import { isAnalysisTextPayload, isPageAnalysisPayload } from '../src/shared/message-validation';
import { analysisIdentity, TabAnalysisStore } from '../src/shared/tab-analysis-store';

const SCAMS = [
  'Dear customer your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc.xyz',
  'Your electricity connection will be disconnected tonight at 9.30pm. Contact officer 9876543210 immediately',
  'Congratulations! You won Rs 25,00,000 in KBC lottery. Pay processing fee of Rs 5000 to claim',
  'FedEx: parcel in your name contains drugs. CBI officer will call. Do not disconnect.',
  'Part time job! Earn 5000/day by liking YouTube videos. WhatsApp 9123456780',
  'Your PAN card is blocked. Update now at http://pan-update.top or account will be suspended',
  'Dear user, your Paytm KYC expired. Share OTP to reactivate wallet within 24 hours',
  'Income Tax refund of Rs 15,490 approved. Submit bank account number and IFSC to receive',
  'Hi mom, my phone broke, this is my new number. Please send 20000 urgently for hospital',
  'Your Netflix subscription failed. Update card details here: http://netflix-billing-help.com',
  'Install AnyDesk so our bank executive can help you fix your net banking issue',
  'आपका बैंक खाता बंद हो जाएगा। तुरंत KYC अपडेट करें और OTP बताएं',
  'Dear customer, y0ur acc0unt is susp3nded. Share 0TP n0w',
  'Invest in crypto with guaranteed 30% monthly returns, send USDT to our wallet',
  'Amazon: You have a pending refund of Rs 2,999. Click here to claim http://amzn-refund.click',
];
const LEGIT = [
  'Your OTP for login to HDFC NetBanking is 482913. Do not share it with anyone. Valid for 5 mins.',
  'Rs 2,500.00 debited from A/c XX1234 on 23-Sep via UPI to swiggy@icici. Not you? Call 1800-202-6161',
  'Your Amazon order #402-1234567 has been shipped and will arrive tomorrow.',
  'SBI: Your account statement for September is ready. Log in to onlinesbi.sbi to view.',
  'Reminder: your electricity bill of Rs 1,240 is due on 5 Oct. Pay via BESCOM app.',
  'News: RBI warns citizens about KYC fraud calls asking for OTP. Never share your PIN or CVV.',
  'Hey, are we still meeting for lunch tomorrow at 1?',
  'Your Flipkart refund of Rs 499 has been credited to your original payment method.',
  'Income Tax Department: your ITR for AY 2026-27 has been processed successfully.',
  'Google Pay: you received Rs 200 from Rahul Sharma.',
  'Your one-time password for sign-in is 123456. Never share this verification code.',
];
const verdict = (text: string) => runFullAnalysis('https://sms.local/', text);
let passed = 0;
let failed = 0;

function assertCase(label: string, actual: boolean, detail = '') {
  if (actual) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    console.error(`  ✗ ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

function analyzeDomFixture(url: string, html: string) {
  const { document } = parseHTML(html);
  const ignored = 'script, style, noscript, svg, code, pre, kbd, nav, footer, [hidden], [aria-hidden="true"], [contenteditable]:not([contenteditable="false"])';
  const isVisible = (element: Element) => {
    if (element.closest(ignored)) return false;
    const style = element.getAttribute('style') || '';
    return !/(?:^|;)\s*(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse))/i.test(style);
  };
  const root = document.querySelector('main, [role="main"], article') || document.body;
  const { forms, credentialForm } = extractFormMetadata(document, url, isVisible);
  const linkMetadata = extractLinkMetadata(document, url, isVisible);
  const text = [
    document.querySelector('title')?.textContent || '',
    extractStaticPageText(root, isVisible),
  ].filter(Boolean).join('\n');
  const analysis = runFullAnalysis(url, text, {
    referenceContent: /\/(?:docs?|documentation|wiki|research)\b/i.test(new URL(url).pathname),
    forms,
    credentialForm,
    links: linkMetadata.map((link) => link.href),
    linkMetadata,
  });
  return { document, text, forms, linkMetadata, analysis };
}

console.log('Scam-message corpus (should be caution/threat):');
let scamHits = 0;
for (const text of SCAMS) {
  const result = verdict(text);
  if (result.overallSeverity === 'threat' || result.overallSeverity === 'caution') scamHits++;
  else console.error(`  missed scam: ${text} (${result.score} ${result.overallSeverity})`);
}
assertCase(`detects ${scamHits}/${SCAMS.length} scam messages`, scamHits === SCAMS.length);

console.log('Legitimate-message corpus (should be safe/unknown):');
let falseAlarms = 0;
for (const text of LEGIT) {
  const result = verdict(text);
  if (result.overallSeverity === 'threat' || result.overallSeverity === 'caution') falseAlarms++;
}
assertCase(`has ${falseAlarms}/${LEGIT.length} false alarms`, falseAlarms === 0);

const repositoryText = [
  'HawkGuard is a scam-detection project and security research repository.',
  'This guide documents examples of digital arrest, OTP, KYC, phishing, and fraud tactics.',
  'The examples explain how scammers try to request credentials and why users should report them.',
].join(' ');
const repositoryAnalysis = runFullAnalysis('https://github.com/sarthak7322/HawkGuard', repositoryText);
const unrelatedDocsAnalysis = runFullAnalysis('https://docs.example.org/security/guide', repositoryText);
assertCase('reference material on GitHub is not treated as a scam', repositoryAnalysis.overallSeverity === 'safe');
assertCase('reference material on an unrelated host is also not treated as a scam', unrelatedDocsAnalysis.overallSeverity === 'safe');
assertCase('GitHub has no special safe-domain exemption', repositoryAnalysis.score === unrelatedDocsAnalysis.score);
assertCase('quoted Hindi scam examples in reference material are contextualized',
  runFullAnalysis('https://source.example.org/docs', 'Security research guide example: तुरंत KYC अपडेट करें और OTP बताएं.', { referenceContent: true }).overallSeverity === 'safe');
assertCase('security-awareness warning remains safe beside reference wording',
  runFullAnalysis('https://security.example.org/guide', 'Never share your OTP. This is a security awareness article.').overallSeverity === 'safe');
assertCase('reference wording does not suppress a direct OTP theft threat',
  runFullAnalysis('https://security.example.org/guide', 'Security research: send your OTP or your account will be blocked.').overallSeverity === 'threat');
assertCase('explanatory security research remains safe',
  runFullAnalysis('https://security.example.org/guide', 'Security research explains why attackers ask victims for OTPs.').overallSeverity === 'safe');
const otpExampleBlock = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository. Example messages include:\nSend me your OTP or your account will be blocked.',
);
const refundExampleBlock = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository. Example messages include:\nPay a processing fee to claim your refund.',
);
const anydeskExampleBlock = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository. Example messages include:\nInstall AnyDesk so our bank executive can help you fix your net banking issue.',
);
assertCase('separated reference cue suppresses illustrative OTP/account-block examples',
  otpExampleBlock.score === 0 && otpExampleBlock.overallSeverity === 'safe');
assertCase('separated reference cue suppresses illustrative refund-fee examples',
  refundExampleBlock.score === 0 && refundExampleBlock.overallSeverity === 'safe');
assertCase('separated reference cue suppresses illustrative AnyDesk examples',
  anydeskExampleBlock.score === 0 && anydeskExampleBlock.overallSeverity === 'safe');
const multipleReferenceExamples = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository. Sample messages:\nSend me your OTP or your account will be blocked.\nPay a processing fee to claim your refund.\nInstall AnyDesk so our bank executive can help you.',
);
assertCase('multiple newline-separated examples under one reference heading remain safe',
  multipleReferenceExamples.score === 0 && multipleReferenceExamples.overallSeverity === 'safe');
const sentenceSeparatedExamples = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository. Examples: Send me your OTP or your account will be blocked. Pay a processing fee to claim your refund. Install AnyDesk so our bank executive can help you.',
);
assertCase('sentence-separated examples after an explicit examples cue remain safe',
  sentenceSeparatedExamples.score === 0 && sentenceSeparatedExamples.overallSeverity === 'safe');
const standaloneExampleCue = runFullAnalysis(
  'https://ordinary.example.net/page',
  'Examples: Send me your OTP or your account will be blocked.',
);
assertCase('an explicit examples block is contextualized without broad page-wide reference suppression',
  standaloneExampleCue.score === 0 && standaloneExampleCue.overallSeverity === 'safe');
const sampleMessagesHeading = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository.\nSample messages\nSend me your OTP or your account will be blocked.',
);
assertCase('punctuation-free Sample messages heading suppresses its OTP/account-block example',
  sampleMessagesHeading.score === 0 && sampleMessagesHeading.overallSeverity === 'safe');
const exampleMessagesHeading = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository.\nExample messages\nPay a processing fee to claim your refund.',
);
assertCase('punctuation-free Example messages heading suppresses its refund-fee example',
  exampleMessagesHeading.score === 0 && exampleMessagesHeading.overallSeverity === 'safe');
const sampleCasesHeading = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository.\nSample cases\nInstall AnyDesk so our bank executive can help you.',
);
assertCase('punctuation-free Sample cases heading suppresses its remote-access example',
  sampleCasesHeading.score === 0 && sampleCasesHeading.overallSeverity === 'safe');
const referenceBlockThenDirectRequest = runFullAnalysis(
  'https://github.com/example/research',
  'Security research repository. Example messages include:\nSend me your OTP or your account will be blocked.\nPay a processing fee to claim your refund.\n\nSend me your OTP now or your account will be blocked.',
);
assertCase('a genuine direct scam request after the reference block remains detectable',
  referenceBlockThenDirectRequest.overallSeverity === 'threat'
    && referenceBlockThenDirectRequest.findings.some((finding) => finding.title === 'Credential solicitation'));
const exampleWordDirectRequest = runFullAnalysis(
  'https://security.example.org/guide',
  'Security research discusses this example. This is a live request: send me your OTP or your account will be blocked.',
  { referenceContent: true },
);
assertCase('a direct request containing the word example is not suppressed',
  exampleWordDirectRequest.overallSeverity === 'threat'
    && exampleWordDirectRequest.findings.some((finding) => finding.title === 'Credential solicitation'));
const sampleWordDirectRequest = runFullAnalysis(
  'https://security.example.org/guide',
  'This sample request is live: send me your OTP or your account will be blocked.',
  { referenceContent: true },
);
assertCase('a direct request containing sample wording is not suppressed',
  sampleWordDirectRequest.overallSeverity === 'threat'
    && sampleWordDirectRequest.findings.some((finding) => finding.title === 'Credential solicitation'));
const referenceThreat = runFullAnalysis(
  'https://security.example.org/guide',
  'Security research: send your OTP or your account will be blocked.',
  { referenceContent: true, credentialForm: true },
);
assertCase('strong credential theft in reference context retains threat severity',
  referenceThreat.score >= 40
    && referenceThreat.findings.some((finding) => finding.title === 'Credential solicitation' && finding.severity === 'threat'));
const softenedReferenceFinding = runFullAnalysis(
  'https://security.example.org/guide',
  'Security research CAPTCHA: download the file to continue.',
  { referenceContent: true, credentialForm: true },
);
assertCase('reference-context score reduction also downgrades finding severity',
  softenedReferenceFinding.score < 20
    && softenedReferenceFinding.findings.every((finding) => finding.severity !== 'threat'));

const awarenessText = 'This awareness guide explains why scammers ask victims to install AnyDesk and share an OTP.';
assertCase('educational explanation of scam tactics is contextualized',
  runFullAnalysis('https://news.example.org/article', awarenessText).overallSeverity === 'safe');
assertCase('direct remote-access solicitation remains detectable',
  verdict('Install AnyDesk and share your screen so I can fix your bank account.').overallSeverity === 'threat');
assertCase('direct OTP solicitation crosses the threat threshold',
  verdict('Please share your OTP to unlock your bank account.').overallSeverity === 'threat');
const directOtpRequest = verdict('Send me your OTP.');
const threatenedOtpRequest = verdict('Send me your OTP or your account will be blocked.');
assertCase('account-block threat strengthens an existing OTP-theft finding',
  threatenedOtpRequest.score > directOtpRequest.score
    && threatenedOtpRequest.findings.some((f) => f.title === 'High-risk credential + account threat combination'));
assertCase('normal OTP entry on the genuine brand site is not a scam',
  runFullAnalysis('https://www.hdfcbank.com/login', 'HDFC Bank: enter your OTP to sign in.', { credentialForm: true }).overallSeverity === 'safe');
assertCase('a direct OTP-transfer request on the genuine brand site remains suspicious',
  runFullAnalysis('https://www.hdfcbank.com/login', 'HDFC Bank agent: share your OTP now.', { credentialForm: true }).overallSeverity === 'threat');
assertCase('suspicious account message remains detectable',
  runFullAnalysis('https://sbi-kyc.xyz/login', 'Your SBI account is blocked. Share your OTP now.').overallSeverity === 'threat');
assertCase('a suspicious TLD alone is only an unknown-risk signal',
  runFullAnalysis('https://unknown-domain.xyz/', '').overallSeverity === 'unknown');
assertCase('mentioning a digital-arrest scam without a solicitation stays benign',
  verdict('Digital arrest scams are a threat; report suspicious calls to the authorities.').overallSeverity === 'safe');
assertCase('a routine family greeting is not mistaken for impersonation',
  verdict('Hi mom, are we still meeting for lunch tomorrow?').overallSeverity === 'safe');

console.log('Unicode and obfuscation regressions:');
const obfuscatedThreats = [
  ['zero-width OTP theft', 'Send me your o\u200bt\u200bp'],
  ['zero-width password theft', 'Send me your p\u200ba\u200bs\u200bs\u200bw\u200bo\u200br\u200bd'],
  ['zero-width verification plus credential theft', 'v\u200berify your account by sending me your OTP'],
  ['spaced OTP theft', 'Send me your O T P or your account will be blocked'],
  ['hyphenated OTP theft', 'Send me your O-T-P or your account will be blocked'],
  ['hyphen-separated password theft', 'Send me your p-a-s-s-w-o-r-d or your account will be blocked'],
  ['punctuated password theft', 'Send me your p.a.s.s.w.o.r.d or your account will be blocked'],
  ['NFKC full-width credential theft', 'Ｓｅｎｄ ｍｅ ｙｏｕｒ ＯＴＰ ｏｒ ｙｏｕｒ ａｃｃｏｕｎｔ ｗｉｌｌ ｂｅ ｂｌｏｃｋｅｄ'],
  ['confusable brand plus credential theft', 'pаypal support says send me your password or your account will be blocked'],
  ['leetspeak OTP theft', 'Send me your 0TP or your account will be blocked'],
  ['leetspeak verification and password theft', 'v3rify your @ccount: send me your p@ssword or it will be blocked'],
  ['leetspeak payment fee scam', 'p4y a registration fee to start this job and receive your salary'],
  ['spaced payment action and fee scam', 'p a y a processing fee to receive your refund'],
  ['leetspeak account request', 'Send your @ccount number and password now or access will be blocked'],
] as const;
for (const [label, text] of obfuscatedThreats) {
  assertCase(label, verdict(text).overallSeverity === 'threat', verdict(text).overallSeverity);
}
assertCase('never-share directive remains protective after spacing normalization',
  verdict('Never share your O T P.').overallSeverity === 'safe');
assertCase('protective wording does not suppress a separate credential theft request',
  verdict('Never share your OTP, but send me your OTP or the account will be blocked.').overallSeverity === 'threat',
  JSON.stringify(verdict('Never share your OTP, but send me your OTP or the account will be blocked.')));
assertCase('a separate sentence with an explicit send request overrides a warning',
  verdict('Never share your OTP. Send me your OTP now.').overallSeverity === 'threat');
assertCase('security-awareness guidance remains safe with zero-width text',
  runFullAnalysis('https://security.example.org/guide', 'Security awareness: never share your o\u200bt\u200bp with anyone.').overallSeverity === 'safe');
assertCase('legitimate Hindi text remains safe', verdict('नमस्ते, आज मौसम बहुत अच्छा है।').overallSeverity === 'safe');
assertCase('legitimate Kannada text remains safe', verdict('ನಮಸ್ಕಾರ, ಇಂದು ಹವಾಮಾನ ಚೆನ್ನಾಗಿದೆ.').overallSeverity === 'safe');
assertCase('legitimate Greek text remains safe', verdict('Καλημέρα, ο καιρός είναι όμορφος σήμερα.').overallSeverity === 'safe');
assertCase('legitimate Cyrillic text remains safe', verdict('Здравствуйте, сегодня хорошая погода.').overallSeverity === 'safe');
assertCase('OTP delivery with leetspeak is not credential theft',
  verdict('Your 0TP is your verification code 123456. Never share it.').overallSeverity === 'safe');
assertCase('mixed-script brand request receives supporting mixed-script evidence',
  verdict('pаypal says send me your password immediately.').findings.some((f) => f.title === 'Mixed-script text in suspicious request'));
assertCase('mixed-script credential request is associated with its suspicious text unit',
  verdict('pаypal support says send me your password immediately.').findings.some((f) => f.title === 'Mixed-script text in suspicious request'));
assertCase('unrelated Hindi section is not cited as mixed-script suspicious evidence',
  verdict('नमस्ते, आपका दिन शुभ हो।\nSend me your password immediately.').findings.every((f) => f.title !== 'Mixed-script text in suspicious request'));
assertCase('legitimate multilingual page has no mixed-script suspicion',
  verdict('ನಮಸ್ಕಾರ, ಇಂದು ಹವಾಮಾನ ಚೆನ್ನಾಗಿದೆ.\nمرحبا بكم في صفحة المعلومات.').findings.every((f) => f.title !== 'Mixed-script text in suspicious request'));
assertCase('mixed-script content without suspicious behavior remains benign',
  verdict('The word pаypal appears in this discussion of Unicode typography.').overallSeverity === 'safe');
assertCase('leetspeak-looking tokens alone do not raise risk',
  verdict('The word v3rify appears next to version 2026 and code 0TP in this sample.').overallSeverity === 'safe');
assertCase('ordinary separated letters do not become suspicious',
  verdict('A nice day and a sunny sky.').overallSeverity === 'safe');
assertCase('Unicode control characters normalize between request words',
  verdict('Send me\u0000 your OTP or the account will be blocked.').overallSeverity === 'threat');
assertCase('Latin ZWJ-separated OTP remains detectable',
  verdict('Send me O\u200dT\u200dP or your account will be blocked.').overallSeverity === 'threat');
assertCase('Latin ZWNJ-separated password remains detectable',
  verdict('Send me your p\u200ca\u200cs\u200cs\u200cw\u200co\u200cr\u200cd or your account will be blocked.').overallSeverity === 'threat');
assertCase('Indic ZWJ and Persian ZWNJ are preserved by Unicode normalization',
  normalizeUnicode('क्\u200dष और می\u200cخواهم') === 'क्\u200dष और می\u200cخواهم');
assertCase('legitimate numeric-heavy content is not decoded as a scam',
  verdict('Reference 5000-2026, order 9876543210, version 0.1.0.').overallSeverity === 'safe');
assertCase('password required for normal login is not credential theft',
  verdict('Password required for your normal login.').overallSeverity === 'safe');
assertCase('request within a single text block remains detectable',
  verdict('Send me your OTP or your account will be blocked.').overallSeverity === 'threat');
assertCase('unrelated sentences separated by paragraphs do not combine into a request',
  verdict('Send me.\n\nyour OTP is used for account verification.').overallSeverity === 'safe');
assertCase('unrelated DOM sections separated by line boundaries do not combine',
  verdict('Please send me\n\nThe one-time password protects your login.').overallSeverity === 'safe');

console.log('URL and hostname normalization regressions:');
const encodedSuspiciousUrl = '%68%74%74%70%73%3A%2F%2Fsbi-kyc.xyz%2Flogin';
assertCase('encoded suspicious URL is decoded for hostname analysis',
  runFullAnalysis('https://message.example/', `Open ${encodedSuspiciousUrl}`).findings.some((f) => f.title === 'Suspicious TLD'),
  JSON.stringify({ extracted: extractIntel(`Open ${encodedSuspiciousUrl}`).urls, analysis: runFullAnalysis('https://message.example/', `Open ${encodedSuspiciousUrl}`).findings }));
const confusableHost = new URL('https://pаypal-login.xyz/verify').hostname;
assertCase('confusable IDN brand hostname is detected as a lookalike',
  runFullAnalysis(`https://${confusableHost}/verify`, 'PayPal says share your password now.').findings.some((f) => f.title === 'Brand-lookalike domain'));
const exactConfusableBrandHost = new URL('https://pаypal.com/login').hostname;
assertCase('exact homoglyph brand hostname is not mistaken for the official site',
  runFullAnalysis(`https://${exactConfusableBrandHost}/login`, 'PayPal says share your password now.', { credentialForm: true }).findings.some((f) => f.title === 'Brand-domain mismatch'));
assertCase('legitimate IDN hostname is not inherently suspicious',
  runFullAnalysis('https://xn--e1afmkfd.xn--p1ai/', 'Добро пожаловать на официальный информационный сайт.').score === 0);
assertCase('trailing-dot hostname is normalized for domain analysis',
  runFullAnalysis('https://sbi-kyc.xyz./login', 'Your account is blocked. Share your OTP.').findings.some((f) => f.title === 'Brand-lookalike domain' || f.title === 'Suspicious TLD'));
assertCase('protocol-relative URL destination is analyzed',
  runFullAnalysis('https://message.example/', 'Open //sbi-kyc.xyz/login').findings.some((f) => f.title === 'Suspicious TLD'));
assertCase('brand in URL path does not make the hostname suspicious',
  runFullAnalysis('https://example.com/paypal/login', 'Sign in to continue').score === 0);
assertCase('brand terms in URL query and fragment are not treated as hostname indicators',
  runFullAnalysis('https://example.com/login?brand=paypal#account', 'Sign in to continue').score === 0);
assertCase('legitimate brand subdomain is not a lookalike',
  runFullAnalysis('https://login.hdfcbank.com/', 'HDFC Bank login.').findings.every((f) => f.title !== 'Brand-lookalike domain'));
assertCase('deceptive brand subdomain is detected',
  runFullAnalysis('https://hdfcbank.com.attacker.xyz/', 'HDFC Bank: share your OTP now.').findings.some((f) => f.title === 'Brand-domain mismatch'));
assertCase('brand-owned subdomain remains legitimate',
  runFullAnalysis('https://login.paypal.com/', 'PayPal account sign in.', { credentialForm: true }).findings.every((finding) => finding.title !== 'Brand-domain mismatch'));
assertCase('paypal.example.com does not inherit PayPal ownership',
  runFullAnalysis('https://paypal.example.com/login', 'PayPal account login', {
    forms: [{ fields: ['password'], action: 'https://paypal.example.com/login', method: 'post', buttonText: 'Sign in', labelText: 'PayPal account password' }],
  }).findings.some((finding) => finding.title === 'Brand-domain mismatch'));
assertCase('paypal.com.example.com is not treated as PayPal-owned',
  runFullAnalysis('https://paypal.com.example.com/login', 'PayPal account login', {
    forms: [{ fields: ['password'], action: 'https://paypal.com.example.com/login', method: 'post', buttonText: 'Sign in', labelText: 'PayPal account password' }],
  }).findings.some((finding) => finding.title === 'Brand-domain mismatch'));
const parsedDomainParts = getDomainParts('login.example.co.in.');
assertCase('hostname, subdomain, and registrable domain are separated',
  parsedDomainParts.hostname === 'login.example.co.in' && parsedDomainParts.subdomain === 'login' && parsedDomainParts.registrableDomain === 'example.co.in');
assertCase('example.co.uk uses the expected registrable domain',
  getDomainParts('example.co.uk').registrableDomain === 'example.co.uk');
assertCase('a government hostname does not collapse to the shared gov.uk suffix',
  getDomainParts('service.example.gov.uk').registrableDomain === 'example.gov.uk'
    && getDomainParts('gov.uk').registrableDomain === '');
assertCase('ordinary .com hostname uses its registrable domain',
  getDomainParts('login.example.com').registrableDomain === 'example.com');
assertCase('unknown suffix keeps its preceding site label as registrable domain',
  getDomainParts('service.example.newtld').registrableDomain === 'example.newtld'
    && getDomainParts('newtld').registrableDomain === '');
assertCase('ordinary same-site subdomain navigation is not flagged',
  runFullAnalysis('https://www.example.com/', '', { links: ['https://login.example.com/account'] }).findings.length === 0);
assertCase('suspicious lookalike subdomain of the current site is analyzed',
  runFullAnalysis('https://www.example.com/', '', { links: ['https://paypal-login.example.com/account'] }).findings.some((finding) => finding.title === 'Brand-lookalike domain'));
assertCase('unrelated external domain remains analyzed',
  runFullAnalysis('https://www.example.com/', '', { links: ['https://attacker.xyz/login'] }).findings.some((finding) => finding.title === 'Suspicious TLD'));
assertCase('shortener alone remains supporting evidence',
  runFullAnalysis('https://message.example/', 'Open https://bit.ly/abc').findings.some((finding) => finding.title === 'URL shortener')
    && runFullAnalysis('https://message.example/', 'Open https://bit.ly/abc').overallSeverity !== 'threat');
assertCase('raw IP destination remains supporting evidence',
  runFullAnalysis('https://message.example/', 'Open https://192.0.2.1/login').findings.some((finding) => finding.title === 'Raw IP address')
    && runFullAnalysis('https://message.example/', 'Open https://192.0.2.1/login').overallSeverity !== 'threat');
assertCase('punycode lookalike hostname is detected',
  runFullAnalysis(new URL('https://pаypal.example/login').href, 'PayPal account login: share your password.', {
    credentialForm: true,
    forms: [{ fields: ['password'], action: 'https://pаypal.example/collect', method: 'post', buttonText: 'Sign in', labelText: 'PayPal account password' }],
  }).findings.some((finding) => finding.title === 'Brand-domain mismatch'));

console.log('DOM extraction and dynamic form fixtures:');
const domNormalLogin = analyzeDomFixture('https://www.paypal.com/signin', `
  <main><form action="/signin" method="post"><fieldset><legend>PayPal sign in</legend>
  <label>Email <input type="email" name="email"></label>
  <label>Password <input type="password" name="password"></label>
  <button>Log in</button></fieldset></form></main>`);
assertCase('DOM fixture: official-domain normal login remains safe',
  domNormalLogin.analysis.overallSeverity === 'safe'
    && domNormalLogin.forms[0]?.contextScope === 'fieldset');

const domArticleUnrelatedLogin = analyzeDomFixture('https://paypal-security-example.com/research', `
  <main><section><article><h1>Security advice</h1>
  <p>Beware of fake PayPal login pages. Never enter your password.</p></article>
  <form action="/session"><label>Newsletter password <input type="password" name="newsletter"></label>
  <button>Subscribe</button></form></section></main>`);
assertCase('DOM fixture: security article plus unrelated login is not strong impersonation',
  domArticleUnrelatedLogin.analysis.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));

const domRemotePayPalText = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><article><h2>PayPal account verification</h2><p>PayPal security information.</p></article>
  <form action="/session"><label>Password <input type="password" name="password"></label>
  <button>Continue</button></form></main>`);
assertCase('DOM fixture: PayPal text elsewhere plus unrelated password form is not local identity',
  domRemotePayPalText.analysis.findings.every((finding) =>
    finding.title !== 'Brand impersonation with sensitive form'
      && !(finding.title === 'Brand-domain mismatch' && finding.evidence?.brand === 'PayPal')));

const domRemoteLabel = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form id="other"><label for="remote-password">PayPal account verification</label></form>
  <form action="/session"><input id="remote-password" type="password" name="password">
  <button>Continue</button></form></main>`);
assertCase('DOM fixture: label in another form cannot identify a sensitive field',
  !domRemoteLabel.forms[1]?.identityText?.includes('PayPal')
    && domRemoteLabel.analysis.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));

const domDuplicateFieldId = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><label for="duplicate-password">PayPal verification</label>
  <div id="duplicate-password"></div>
  <form action="/session"><input id="duplicate-password" type="password" name="password">
  <button>Continue</button></form></main>`);
assertCase('DOM fixture: duplicate field ID does not guess an explicit label association',
  !domDuplicateFieldId.forms[0]?.identityText?.includes('PayPal')
    && domDuplicateFieldId.analysis.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));

const domPayPalOtherFieldset = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/session">
  <fieldset><legend>PayPal account verification</legend><label>Password <input type="password" name="password"></label></fieldset>
  <fieldset><legend>Unrelated security code</legend><label>One-time code <input type="text" name="otp"></label></fieldset>
  <button>Continue</button></form></main>`);
assertCase('DOM fixture: separate sensitive fieldsets do not merge into a larger PayPal context',
  domPayPalOtherFieldset.forms[0]?.sensitiveContexts?.length === 2
    && domPayPalOtherFieldset.forms[0]?.sensitiveContexts?.[0].identityText.includes('PayPal')
    && !domPayPalOtherFieldset.forms[0]?.sensitiveContexts?.[1].identityText.includes('PayPal')
    && domPayPalOtherFieldset.analysis.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form'));

const domPayPalLabelOtherSensitiveField = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/session">
  <fieldset><label>PayPal account verification</label><input type="text" name="information"></fieldset>
  <fieldset><label>Password <input type="password" name="password"></label></fieldset>
  <button>Continue</button></form></main>`);
assertCase('DOM fixture: PayPal field label cannot identify another sensitive field in a separate fieldset',
  domPayPalLabelOtherSensitiveField.forms[0]?.sensitiveContexts?.length === 1
    && !domPayPalLabelOtherSensitiveField.forms[0]?.sensitiveContexts?.[0].identityText.includes('PayPal')
    && domPayPalLabelOtherSensitiveField.analysis.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));

const domMultipleBrandFieldsets = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/session">
  <fieldset><legend>PayPal account verification</legend><label>Password <input type="password" name="password"></label><button>Verify PayPal</button></fieldset>
  <fieldset><legend>HDFC account verification</legend><label>OTP <input type="text" name="otp"></label><button>Verify HDFC</button></fieldset>
  </form></main>`);
assertCase('DOM fixture: brand claims in separate fieldsets remain independently associated',
  domMultipleBrandFieldsets.forms[0]?.sensitiveContexts?.length === 2
    && domMultipleBrandFieldsets.forms[0]?.sensitiveContexts?.[0].identityText.includes('PayPal')
    && domMultipleBrandFieldsets.forms[0]?.sensitiveContexts?.[1].identityText.includes('HDFC')
    && domMultipleBrandFieldsets.analysis.findings.some((finding) =>
      finding.title === 'Brand impersonation with sensitive form' && finding.evidence?.brand === 'PayPal')
    && domMultipleBrandFieldsets.analysis.findings.every((finding) =>
      finding.title !== 'Brand impersonation with sensitive form' || finding.evidence?.brand !== 'HDFC'));

const domUnrelatedFormLabel = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/session">
  <label>PayPal account verification</label>
  <div><label>Password <input type="password" name="password"></label></div>
  <button>Continue</button></form></main>`);
assertCase('DOM fixture: unrelated form-wide label does not become sensitive-field identity evidence',
  !domUnrelatedFormLabel.forms[0]?.sensitiveContexts?.[0]?.identityText.includes('PayPal')
    && domUnrelatedFormLabel.analysis.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));

const domExplicitPaypalLabel = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/session"><fieldset>
  <label for="paypal-password">PayPal password</label>
  <input id="paypal-password" type="password" name="password">
  <button>Verify account</button></fieldset></form></main>`);
assertCase('DOM fixture: unique explicit label for the exact sensitive field establishes local identity',
  domExplicitPaypalLabel.forms[0]?.identityText?.includes('PayPal')
    && domExplicitPaypalLabel.analysis.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form'));

const domFieldsetPaypalLabel = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/session"><fieldset>
  <legend>PayPal account verification</legend>
  <label>PayPal password <input type="password" name="password"></label>
  <button>Continue</button></fieldset></form></main>`);
assertCase('DOM fixture: wrapping PayPal label and same-fieldset identity remain effective',
  domFieldsetPaypalLabel.forms[0]?.identityText?.includes('PayPal')
    && domFieldsetPaypalLabel.analysis.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form'));

const domLocalPaypalAction = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/session"><div role="group">
  <label>Password <input type="password" name="password"></label>
  <button>Verify PayPal account</button></div></form></main>`);
assertCase('DOM fixture: PayPal action inside the sensitive field logical group establishes identity',
  domLocalPaypalAction.forms[0]?.identityText?.includes('Verify PayPal account')
    && domLocalPaypalAction.analysis.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form'));

const domTrustedPayment = analyzeDomFixture('https://shop.example.com/checkout', `
  <main><form action="https://checkout.stripe.com/pay" method="post">
  <label>Card number <input autocomplete="cc-number" name="card"></label>
  <label>Security code <input autocomplete="cc-csc" name="code"></label>
  <button>Pay</button></form></main>`);
assertCase('DOM fixture: payment form to trusted external provider stays low risk',
  domTrustedPayment.analysis.overallSeverity !== 'threat'
    && domTrustedPayment.analysis.findings.every((finding) => finding.title !== 'Sensitive form external destination'));

const domMultiBrandInfo = analyzeDomFixture('https://finance.example.org/articles', `
  <main><article><h1>HDFC and PayPal account security</h1>
  <p>This informational article compares Google Pay and PayPal features.</p>
  <a href="https://docs.example.org/security">Read documentation</a>
  <a href="https://news.example.net/">More information</a></article>
  <form action="/newsletter"><label>Email <input type="email" name="email"></label>
  <button>Subscribe</button></form></main>`);
assertCase('DOM fixture: multi-brand information and unrelated form stays safe',
  domMultiBrandInfo.analysis.overallSeverity === 'safe'
    && domMultiBrandInfo.analysis.findings.every((finding) => finding.title !== 'Brand-domain mismatch'));

const domInformationalPage = analyzeDomFixture('https://www.example.org/about', `
  <main><article><h1>About our service</h1><p>We provide account security guidance and customer support resources.</p></article></main>`);
assertCase('DOM fixture: ordinary informational page remains low risk',
  domInformationalPage.analysis.overallSeverity === 'safe' && domInformationalPage.analysis.score === 0);

const domGitHubAmazonReference = analyzeDomFixture('https://github.com/example/project', `
  <main><article><h1>Security examples</h1><p>Examples mention Amazon refunds, PayPal verification, OTPs, and fake credentials for awareness training.</p>
  <pre><code>https://amazon-refund.example.xyz/login</code></pre></article></main>`);
assertCase('DOM fixture: GitHub-style security documentation with scam examples stays safe',
  domGitHubAmazonReference.analysis.overallSeverity !== 'threat'
    && domGitHubAmazonReference.analysis.findings.every((finding) =>
      finding.title !== 'Brand impersonation with sensitive form'));

const domMultiSensitiveLogin = analyzeDomFixture('https://accounts.example.org/signin', `
  <main><form action="/signin" method="post"><fieldset><legend>Sign in to your account</legend>
  <label>Email <input type="email" name="email" autocomplete="username"></label>
  <label>Password <input type="password" name="password" autocomplete="current-password"></label>
  <button>Sign in</button></fieldset></form></main>`);
assertCase('DOM fixture: legitimate multi-field login metadata stays low risk',
  domMultiSensitiveLogin.forms[0]?.sensitiveContexts?.length === 1
    && domMultiSensitiveLogin.analysis.overallSeverity !== 'threat'
    && domMultiSensitiveLogin.analysis.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));

const domDynamicLegitimate = parseHTML('<html><body><main><div id="mount"></div></main></body></html>');
const dynamicLegitimateForm = domDynamicLegitimate.document.createElement('form');
dynamicLegitimateForm.setAttribute('action', 'https://checkout.stripe.com/session');
dynamicLegitimateForm.innerHTML = '<fieldset><legend>Secure payment</legend><label>Card number <input autocomplete="cc-number" name="card"></label><button>Pay securely</button></fieldset>';
domDynamicLegitimate.document.querySelector('#mount')?.appendChild(dynamicLegitimateForm);
const dynamicLegitimateMetadata = extractFormMetadata(
  domDynamicLegitimate.document,
  'https://shop.example.com/checkout',
  (element) => !element.closest('[hidden], [contenteditable]:not([contenteditable="false"])'),
);
const dynamicLegitimateAnalysis = runFullAnalysis('https://shop.example.com/checkout', 'Secure payment', {
  forms: dynamicLegitimateMetadata.forms,
  credentialForm: dynamicLegitimateMetadata.credentialForm,
});
assertCase('dynamic DOM fixture: inserted legitimate payment form remains low risk',
  dynamicLegitimateMetadata.forms.length === 1
    && dynamicLegitimateAnalysis.overallSeverity !== 'threat'
    && dynamicLegitimateAnalysis.findings.every((finding) => finding.title !== 'Sensitive form external destination'));
const editableContentFixture = analyzeDomFixture('https://news.example.org/article', `
  <main><p>Read the article.</p>
  <a href="https://docs.example.org/guide"><span contenteditable="true">PRIVATE DRAFT CANARY</span> documentation</a>
  <textarea name="draft">PRIVATE TEXTAREA CANARY</textarea>
  <form><label>Password <input type="password" name="password"></label></form></main>`);
assertCase('DOM fixture: editable drafts and textarea contents are excluded from page text and link labels',
  !editableContentFixture.text.includes('PRIVATE DRAFT CANARY')
    && !editableContentFixture.text.includes('PRIVATE TEXTAREA CANARY')
    && editableContentFixture.linkMetadata.every((link) => !link.label.includes('PRIVATE DRAFT CANARY')),
  `${editableContentFixture.text} | ${editableContentFixture.linkMetadata.map((link) => link.label).join(', ')}`);

const domPaypalVerification = analyzeDomFixture('https://paypal-security-example.com/login', `
  <main><form action="/collect" method="post"><fieldset>
  <legend>Verify your PayPal account</legend>
  <label>Password <input type="password" name="password"></label>
  <button>Verify PayPal account</button>
  </fieldset></form></main>`);
assertCase('DOM fixture: deceptive PayPal verification form is detected',
  domPaypalVerification.analysis.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form')
    && domPaypalVerification.analysis.overallSeverity === 'threat');

const domLocalContainer = analyzeDomFixture('https://paypal-security-example.com/verify', `
  <main><div><h2>Verify your PayPal account</h2>
  <form action="/collect"><label>Password <input type="password" name="password"></label>
  <button>Verify PayPal account</button></form></div></main>`);
assertCase('DOM fixture: local form container associates brand claim with sensitive form',
  domLocalContainer.forms[0]?.contextScope === 'local'
    && domLocalContainer.analysis.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form'));

const domSuspiciousAction = analyzeDomFixture('https://secure-shop.example.com/login', `
  <main><form action="https://collector.example.xyz/submit" method="post"><fieldset>
  <legend>PayPal account verification</legend>
  <label>Password <input type="password" name="password"></label>
  <button>Verify account</button></fieldset></form></main>`);
assertCase('DOM fixture: related PayPal form with suspicious external action is detected',
  domSuspiciousAction.analysis.findings.some((finding) => finding.title === 'Brand-domain mismatch')
    && domSuspiciousAction.analysis.overallSeverity === 'threat');

const dynamicDom = parseHTML('<html><body><main><article>PayPal security information</article></main></body></html>');
const dynamicUrl = 'https://paypal-security-example.com/research';
const dynamicVisible = (element: Element) => !element.closest('[hidden], [contenteditable]:not([contenteditable="false"])');
const dynamicBefore = extractFormMetadata(dynamicDom.document, dynamicUrl, dynamicVisible);
const dynamicForm = dynamicDom.document.createElement('form');
dynamicForm.setAttribute('action', 'https://collector.example.xyz/collect');
dynamicForm.innerHTML = '<fieldset><legend>Verify your PayPal account</legend><label>Password <input type="password" name="password"></label><button>Verify</button></fieldset>';
dynamicDom.document.querySelector('main')?.appendChild(dynamicForm);
const dynamicAfterForms = extractFormMetadata(dynamicDom.document, dynamicUrl, dynamicVisible);
const dynamicAfterText = extractStaticPageText(dynamicDom.document.body, dynamicVisible);
const dynamicAfter = runFullAnalysis(dynamicUrl, dynamicAfterText, {
  referenceContent: true,
  forms: dynamicAfterForms.forms,
  credentialForm: dynamicAfterForms.credentialForm,
});
assertCase('dynamic DOM fixture: inserted suspicious form is present in fresh extraction and detected',
  dynamicBefore.forms.length === 0
    && dynamicAfterForms.forms.length === 1
    && dynamicAfter.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form')
    && dynamicAfter.overallSeverity === 'threat');

const mutationDom = parseHTML('<html><body></body></html>').document;
const ownedUiNodes = new WeakSet<Node>();
const ownedBanner = mutationDom.createElement('div');
ownedBanner.id = 'hawkguard-alert-banner';
ownedUiNodes.add(ownedBanner);
const ownedBannerChild = mutationDom.createElement('span');
ownedBanner.appendChild(ownedBannerChild);
const ownedStyle = mutationDom.createElement('style');
ownedStyle.id = 'hawkguard-alert-style';
ownedUiNodes.add(ownedStyle);
const pageForm = mutationDom.createElement('form');
const pageOwnedIdBanner = mutationDom.createElement('div');
pageOwnedIdBanner.id = 'hawkguard-alert-banner';
const pageOwnedIdStyle = mutationDom.createElement('div');
pageOwnedIdStyle.id = 'hawkguard-alert-style';
const pageFormUnderOwnedId = mutationDom.createElement('form');
const fakeMutation = (target: Node, addedNodes: Node[] = [], removedNodes: Node[] = []) => ({
  target, addedNodes, removedNodes,
});
let scheduledMutationScans = 0;
for (const mutation of [
  fakeMutation(mutationDom.body, [ownedBanner]),
  fakeMutation(ownedBannerChild, [mutationDom.createTextNode('updated banner text')]),
  fakeMutation(mutationDom.head, [ownedStyle]),
  fakeMutation(mutationDom.body, [], [ownedBanner]),
]) {
  if (shouldRescanForMutations([mutation], ownedUiNodes)) scheduledMutationScans++;
}
const dynamicPageMutationSchedulesScan = shouldRescanForMutations(
  [fakeMutation(mutationDom.body, [pageForm])],
  ownedUiNodes,
);
const mixedMutationSchedulesScan = shouldRescanForMutations(
  [fakeMutation(mutationDom.body, [ownedBanner, pageForm])],
  ownedUiNodes,
);
const spoofedBannerIdSchedulesScan = shouldRescanForMutations(
  [fakeMutation(mutationDom.body, [pageOwnedIdBanner])],
  ownedUiNodes,
);
const spoofedStyleIdSchedulesScan = shouldRescanForMutations(
  [fakeMutation(mutationDom.body, [pageOwnedIdStyle])],
  ownedUiNodes,
);
pageOwnedIdBanner.appendChild(pageFormUnderOwnedId);
const formUnderSpoofedIdSchedulesScan = shouldRescanForMutations(
  [fakeMutation(pageOwnedIdBanner, [pageFormUnderOwnedId])],
  ownedUiNodes,
);
assertCase('mutation filter: actual HawkGuard banner/style node mutations are ignored',
  scheduledMutationScans === 0);
assertCase('mutation filter: page-created matching IDs are not treated as HawkGuard-owned',
  spoofedBannerIdSchedulesScan && spoofedStyleIdSchedulesScan && formUnderSpoofedIdSchedulesScan);
assertCase('mutation filter: new page forms and mixed page/UI changes still schedule rescans',
  dynamicPageMutationSchedulesScan && mixedMutationSchedulesScan);

class FakeClock implements TimerHost {
  private now = 0;
  private nextId = 1;
  private readonly timers = new Map<number, { due: number; callback: () => void }>();

  setTimeout(callback: () => void, delay: number): number {
    const id = this.nextId++;
    this.timers.set(id, { due: this.now + delay, callback });
    return id;
  }

  clearTimeout(id: number): void {
    this.timers.delete(id);
  }

  advance(milliseconds: number): void {
    const target = this.now + milliseconds;
    while (true) {
      let nextId: number | undefined;
      let nextDue = Infinity;
      for (const [id, timer] of this.timers) {
        if (timer.due < nextDue) {
          nextId = id;
          nextDue = timer.due;
        }
      }
      if (nextId === undefined || nextDue > target) break;
      this.now = nextDue;
      const timer = this.timers.get(nextId);
      this.timers.delete(nextId);
      timer?.callback();
    }
    this.now = target;
  }
}

const singleMutationClock = new FakeClock();
let singleMutationScans = 0;
const singleMutationScheduler = createBoundedDebouncedScan(
  () => singleMutationScans++,
  singleMutationClock,
);
singleMutationScheduler.schedule();
singleMutationClock.advance(899);
const singleMutationDebounced = singleMutationScans === 0;
singleMutationClock.advance(1);
assertCase('scan scheduler: a single mutation uses the normal 900 ms debounce',
  singleMutationDebounced && singleMutationScans === 1);

const coalescedClock = new FakeClock();
let coalescedScans = 0;
const coalescedScheduler = createBoundedDebouncedScan(() => coalescedScans++, coalescedClock);
coalescedScheduler.schedule();
coalescedClock.advance(500);
coalescedScheduler.schedule();
coalescedClock.advance(500);
const mutationsCoalesced = coalescedScans === 0;
coalescedClock.advance(400);
assertCase('scan scheduler: mutations within the debounce interval coalesce into one scan',
  mutationsCoalesced && coalescedScans === 1);

const continuousClock = new FakeClock();
let continuousScans = 0;
const continuousScheduler = createBoundedDebouncedScan(() => continuousScans++, continuousClock);
for (let elapsed = 0; elapsed < 5000; elapsed += 500) {
  continuousScheduler.schedule();
  continuousClock.advance(500);
}
const burstWasBounded = continuousScans >= 1;
continuousScheduler.schedule();
continuousClock.advance(900);
assertCase('scan scheduler: continuous mutations trigger by the 5 s maximum wait and a later burst scans normally',
  burstWasBounded && continuousScans === 2);

let releaseScan: (() => void) | undefined;
let concurrentScanCalls = 0;
let activeScanCalls = 0;
let maximumActiveScanCalls = 0;
const serialRunner = createSerialScanRunner(() => {
  concurrentScanCalls++;
  activeScanCalls++;
  maximumActiveScanCalls = Math.max(maximumActiveScanCalls, activeScanCalls);
  return new Promise<void>((resolve) => {
    releaseScan = () => {
      activeScanCalls--;
      resolve();
    };
  });
});
serialRunner.run();
serialRunner.run();
const duplicateWasSuppressed = concurrentScanCalls === 1;
releaseScan?.();
await Promise.resolve();
await Promise.resolve();
const queuedScanRanSerially = concurrentScanCalls === 2 && maximumActiveScanCalls === 1;
releaseScan?.();
await Promise.resolve();
assertCase('scan scheduler: an in-flight scan serializes a coalesced follow-up without concurrency',
  duplicateWasSuppressed && queuedScanRanSerially);

const startupClock = new FakeClock();
let startupScans = 0;
const startupTimer = createTrackedTimer(() => startupScans++, startupClock, 400);
startupTimer.schedule();
startupTimer.cancel();
startupClock.advance(400);
const pagehideCanceledStartup = startupScans === 0;
startupTimer.schedule();
startupClock.advance(399);
const pageshowWaitedForStartupDelay = startupScans === 0;
startupClock.advance(1);
assertCase('lifecycle: pagehide cancels startup timer and a fresh pageshow schedule runs once',
  pagehideCanceledStartup && pageshowWaitedForStartupDelay && startupScans === 1);

const fakeAnalysis = (score: number, hostname: string) => ({
  url: `https://${hostname}/`,
  hostname,
  overallSeverity: score >= 40 ? 'threat' as const : 'safe' as const,
  score,
  findings: [],
  suspicionReasons: [],
  timestamp: score,
});
const tabStore = new TabAnalysisStore(3);
const tabAAnalysis = fakeAnalysis(55, 'refund-test.example');
const tabBAnalysis = fakeAnalysis(3, 'legitimate-login.example');
tabStore.set(101, tabAAnalysis);
tabStore.set(202, tabBAnalysis);
assertCase('tab analysis store keeps independent analyses for two tabs',
  tabStore.get(101)?.score === 55 && tabStore.get(202)?.score === 3);
const openedTabA = tabStore.select(101);
const openedTabB = tabStore.select(202);
assertCase('opening the panel from each tab selects that tab analysis',
  openedTabA?.score === 55 && openedTabB?.score === 3);
const switchedBackToTabA = tabStore.select(101);
const switchedToUnanalyzedTab = tabStore.select(606);
const switchedBackToTabB = tabStore.select(202);
assertCase('active-tab switching selects the matching analysis and clears missing-tab case',
  switchedBackToTabA?.score === 55
    && switchedToUnanalyzedTab === undefined
    && switchedBackToTabB?.score === 3);
const immutableCase = { ...tabAAnalysis, caseId: 'case-a' };
const caseIdentity = analysisIdentity(immutableCase);
immutableCase.score = 60;
immutableCase.findings.push({
  id: 'rdap-enrichment',
  category: 'domain',
  title: 'Recently registered domain',
  severity: 'caution',
  detail: 'Optional enrichment',
  timestamp: Date.now(),
});
assertCase('engagement identity remains stable when optional enrichment updates a case',
  analysisIdentity(immutableCase) === caseIdentity);
tabStore.select(101);
tabStore.setPasted(fakeAnalysis(70, 'pasted.local'));
assertCase('pasted-text analysis does not overwrite stored page analysis',
  tabStore.current?.score === 70 && tabStore.get(101)?.score === 55);
tabStore.select(202);
const removedTabSelected = tabStore.remove(202);
assertCase('tab removal clears its analysis and selection',
  removedTabSelected && tabStore.get(202) === undefined && tabStore.current === undefined);
tabStore.set(303, fakeAnalysis(19, 'banking.example'));
tabStore.set(404, fakeAnalysis(17, 'delivery.example'));
tabStore.set(505, fakeAnalysis(22, 'newest.example'));
assertCase('tab analysis store remains bounded and evicts the oldest tab',
  tabStore.get(101) === undefined && tabStore.get(303)?.score === 19 && tabStore.get(505)?.score === 22);
const evictionStore = new TabAnalysisStore(3);
const evictionTabA = { ...fakeAnalysis(55, 'selected-refund.example'), caseId: 'eviction-a-old' };
evictionStore.set(11, evictionTabA);
evictionStore.set(22, fakeAnalysis(3, 'other-login.example'));
evictionStore.set(33, fakeAnalysis(19, 'other-bank.example'));
evictionStore.select(11);
evictionStore.set(44, fakeAnalysis(17, 'new-delivery.example'));
assertCase('evicting the selected tab clears selection without substituting another case',
  evictionStore.get(11) === undefined
    && evictionStore.selectedTab === undefined
    && evictionStore.current === undefined
    && evictionStore.get(22)?.score === 3);
const reactivatedMissingTab = evictionStore.select(11);
assertCase('reactivating an evicted tab with no stored analysis leaves no active case',
  reactivatedMissingTab === undefined && evictionStore.current === undefined);
const evictionTabANew = { ...fakeAnalysis(58, 'selected-refund.example'), caseId: 'eviction-a-new' };
evictionStore.set(11, evictionTabANew);
assertCase('reanalyzing an evicted active tab selects its new case normally',
  evictionStore.current === evictionTabANew
    && evictionStore.current.caseId === 'eviction-a-new'
    && evictionStore.selectedTab === 11);

const repeatedBrandLinkText = 'Read PayPal login information.';
const repeatedBrandLinks = Array.from({ length: 10 }, () => ({
  href: 'https://paypal-login.example.xyz/account',
  label: repeatedBrandLinkText,
}));
const oneBrandLinkAnalysis = runFullAnalysis('https://news.example.org/', repeatedBrandLinkText, {
  linkMetadata: [repeatedBrandLinks[0]],
});
const repeatedBrandLinkAnalysis = runFullAnalysis('https://news.example.org/', repeatedBrandLinkText, {
  linkMetadata: repeatedBrandLinks,
});
assertCase('duplicate branded links to the same destination do not multiply mismatch evidence',
  repeatedBrandLinkAnalysis.score === oneBrandLinkAnalysis.score
    && repeatedBrandLinkAnalysis.findings.filter((finding) => finding.title === 'Brand-destination mismatch').length === 1);

assertCase('message validation accepts bounded page-analysis payloads',
  isPageAnalysisPayload({
    url: 'https://example.org/',
    text: 'Informational content',
    context: { forms: [], links: [], linkMetadata: [] },
  }));
assertCase('message validation rejects unsupported schemes and oversized page payloads',
  !isPageAnalysisPayload({ url: 'javascript:alert(1)', text: 'x' })
    && !isPageAnalysisPayload({ url: 'https://example.org/', text: 'x'.repeat(12001) })
    && !isPageAnalysisPayload({ url: 'https://example.org/', text: 'x', html: '<html>raw page source</html>' }));
assertCase('pasted text analysis is bounded before detection processing',
  isAnalysisTextPayload({ text: 'x'.repeat(12000) })
    && !isAnalysisTextPayload({ text: 'x'.repeat(12001) }));

console.log('Branch 2 domain, form, and scoring regressions:');
assertCase('legitimate PayPal domain with login form remains low risk',
  runFullAnalysis('https://www.paypal.com/signin', 'PayPal account sign in.', {
    credentialForm: true,
    forms: [{ fields: ['password current-password'], action: 'https://www.paypal.com/signin', method: 'post', buttonText: 'Log in', labelText: 'Password' }],
  }).score < 12);
assertCase('legitimate regional Google domain is recognized as brand-owned',
  runFullAnalysis('https://accounts.google.co.uk/signin', 'Google account sign in.', {
    forms: [{ fields: ['password'], action: 'https://accounts.google.co.uk/signin', method: 'post', buttonText: 'Next', labelText: 'Password' }],
  }).findings.every((finding) => finding.title !== 'Brand-domain mismatch'));
for (const hostname of ['onlinesbi.sbi', 'sbi.co.in', 'sbi.bank.in']) {
  const sbiLogin = runFullAnalysis(`https://${hostname}/login`, 'SBI account login', {
    credentialForm: true,
    forms: [{ fields: ['password current-password'], action: `https://${hostname}/login`, method: 'post', buttonText: 'Login', labelText: 'SBI account password' }],
  });
  assertCase(`legitimate SBI domain ${hostname} remains low risk`,
    sbiLogin.score < 12 && sbiLogin.findings.every((finding) => finding.title !== 'Brand-domain mismatch'));
}
for (const hostname of ['sbi-login-example.com', 'onlinesbi-example.com']) {
  const sbiLookalike = runFullAnalysis(`https://${hostname}/login`, 'SBI account login: enter your password.', {
    credentialForm: true,
    forms: [{ fields: ['password'], action: `https://${hostname}/collect`, method: 'post', buttonText: 'Login', labelText: 'SBI account password' }],
  });
  assertCase(`${hostname} is not trusted as SBI infrastructure`,
    sbiLookalike.findings.some((finding) => finding.title === 'Brand-domain mismatch')
      && sbiLookalike.overallSeverity === 'threat');
}
assertCase('legitimate PayPal mention in an article is not a brand mismatch',
  runFullAnalysis('https://example.com/article', 'Read about PayPal account security and payment protection.').findings.every((finding) => finding.title !== 'Brand-domain mismatch'));
assertCase('legitimate Google mention is not domain impersonation',
  runFullAnalysis('https://example.org/news', 'Google announced a new product today.').findings.every((finding) => finding.title !== 'Brand-domain mismatch'));
assertCase('legitimate bank mention is not domain impersonation',
  runFullAnalysis('https://finance.example.org/article', 'The bank compared HDFC and SBI interest rates.').findings.every((finding) => finding.title !== 'Brand-domain mismatch'));
assertCase('hyphenated PayPal lookalike is supporting evidence without page activity',
  runFullAnalysis('https://paypal-security-example.com/', 'Welcome to the online information page.').score < 20
    && runFullAnalysis('https://paypal-security-example.com/', 'Welcome to the online information page.').overallSeverity !== 'threat');
assertCase('single-character PayPal substitution is detected conservatively',
  runFullAnalysis('https://paypa1.com/', 'PayPal account login: share your password.', {
    credentialForm: true,
    forms: [{ fields: ['password'], action: 'https://paypa1.com/collect', method: 'post', buttonText: 'Sign in', labelText: 'PayPal account password' }],
  }).findings.some((finding) => finding.title === 'Brand-domain mismatch' || finding.title === 'Brand impersonation with sensitive form'));
assertCase('Google lookalike with account activity is detected',
  runFullAnalysis('https://google-security-login.example/', 'Google account verification: send your password now.', {
    credentialForm: true,
    forms: [{ fields: ['password'], action: 'https://google-security-login.example/collect', method: 'post', buttonText: 'Sign in', labelText: 'Google account password' }],
  }).findings.some((finding) => finding.title === 'Brand-domain mismatch'));
const unrelatedPaypalForm = runFullAnalysis(
  'https://example.com/article',
  'PayPal account security information\nWeekly newsletter',
  { forms: [{ fields: ['password'], action: 'https://example.com/newsletter', method: 'post', buttonText: 'Subscribe', labelText: 'Newsletter password' }] },
);
assertCase('static PayPal wording plus unrelated password form is not impersonation',
  unrelatedPaypalForm.score < 12
    && unrelatedPaypalForm.findings.every((finding) => finding.title !== 'Brand-domain mismatch' && finding.title !== 'Brand impersonation with sensitive form'));
const unrelatedPaypalSuspiciousForm = runFullAnalysis(
  'https://example.com/article',
  'PayPal account security information\nWeekly newsletter',
  { forms: [{ fields: ['password'], action: 'https://collector.example.xyz/submit', method: 'post', buttonText: 'Continue', labelText: 'Newsletter password' }] },
);
assertCase('unrelated PayPal mention plus suspicious sensitive form is not impersonation',
  unrelatedPaypalSuspiciousForm.findings.every((finding) => finding.title !== 'Brand-domain mismatch' && finding.title !== 'Brand impersonation with sensitive form'));
const articleContextPaypalForm = runFullAnalysis(
  'https://paypal-security-example.com/article',
  '',
  { forms: [{
    fields: ['password'],
    action: 'https://paypal-security-example.com/session',
    method: 'post',
    buttonText: 'Subscribe',
    labelText: 'Newsletter password',
    contextText: 'PayPal account security is important. Subscribe to our newsletter.',
    contextScope: 'section',
  }] },
);
assertCase('article PayPal wording in broad section does not claim unrelated password form',
  articleContextPaypalForm.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));
const articleContextPaypalSuspiciousForm = runFullAnalysis(
  'https://paypal-security-example.com/article',
  '',
  { forms: [{
    fields: ['password'],
    action: 'https://collector.example.xyz/submit',
    method: 'post',
    buttonText: 'Continue',
    labelText: 'Newsletter password',
    contextText: 'PayPal account security is important. Subscribe to our newsletter.',
    contextScope: 'article',
  }] },
);
assertCase('article PayPal wording does not combine with unrelated suspicious form destination',
  articleContextPaypalSuspiciousForm.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));
const articleWithLoginForm = runFullAnalysis(
  'https://example.com/article',
  'This article discusses PayPal account security and payment protection.\nSign up for our newsletter.',
  { forms: [{ fields: ['password'], action: 'https://example.com/newsletter', method: 'post', buttonText: 'Sign up', labelText: 'Newsletter password' }] },
);
assertCase('PayPal article mention with unrelated normal login form remains low risk',
  articleWithLoginForm.score < 12
    && articleWithLoginForm.findings.every((finding) => finding.title !== 'Brand-domain mismatch'));
const paypalVerifyForm = runFullAnalysis('https://paypal-security-example.com/login', 'Verify your PayPal account', {
  credentialForm: true,
  forms: [{ fields: ['password', 'cc-number'], action: 'https://random-example.xyz/collect', method: 'post', buttonText: 'Verify account', labelText: 'PayPal account password card number' }],
});
assertCase('Verify PayPal account with sensitive fields and unrelated destination is strong',
  paypalVerifyForm.overallSeverity === 'threat'
    && paypalVerifyForm.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form')
    && paypalVerifyForm.findings.some((finding) => finding.title === 'Sensitive form external destination'));
const suspendedPaypalForm = runFullAnalysis(
  'https://paypal-security-example.com/login',
  'PayPal account suspended. Verify your account.',
  { forms: [{ fields: ['password'], action: 'https://collector.example.xyz/submit', method: 'post', buttonText: 'Verify', labelText: 'PayPal account password' }] },
);
assertCase('PayPal suspension claim, verification action, and credential form is strong',
  suspendedPaypalForm.overallSeverity === 'threat'
    && suspendedPaypalForm.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form'));
const sectionLinkedPaypalForm = runFullAnalysis(
  'https://paypal-security-example.com/login',
  'Verify your PayPal account',
  { forms: [{
    fields: ['password', 'card number'],
    action: 'https://collector.example.xyz/submit',
    method: 'post',
    buttonText: 'Verify account',
    labelText: 'Password card number',
    contextText: 'Verify your PayPal account',
  }] },
);
assertCase('same-section PayPal claim, sensitive form, and suspicious action is strong',
  sectionLinkedPaypalForm.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form')
    && sectionLinkedPaypalForm.overallSeverity === 'threat');
const hdfcBeforePaypalForm = runFullAnalysis(
  'https://paypal-security-example.com/login',
  'HDFC Bank offers account security guidance.',
  { forms: [{
    fields: ['password'],
    action: 'https://collector.example.xyz/submit',
    method: 'post',
    buttonText: 'Verify',
    labelText: 'PayPal account password',
    contextText: 'Verify your PayPal account',
    contextScope: 'fieldset',
  }] },
);
assertCase('HDFC mention before related PayPal form does not mask PayPal mismatch',
  hdfcBeforePaypalForm.findings.some((finding) => finding.title === 'Brand-domain mismatch' && finding.evidence?.brand === 'PayPal')
    && hdfcBeforePaypalForm.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form' && finding.evidence?.brand === 'PayPal'));
const paypalMentionHdfcForm = runFullAnalysis(
  'https://paypal-security-example.com/login',
  'PayPal is discussed in this unrelated article.',
  { forms: [{
    fields: ['password'],
    action: 'https://paypal-security-example.com/session',
    method: 'post',
    buttonText: 'Sign in',
    labelText: 'HDFC Bank account password',
    contextText: 'Sign in to your HDFC Bank account',
    contextScope: 'fieldset',
  }] },
);
assertCase('unrelated PayPal mention does not associate an HDFC form with PayPal',
  paypalMentionHdfcForm.findings.every((finding) => finding.title !== 'Brand-domain mismatch' || finding.evidence?.brand !== 'PayPal'));
assertCase('multiple legitimate brand mentions on official PayPal login remain safe',
  runFullAnalysis('https://www.paypal.com/signin',
    'HDFC Bank and PayPal account security information.',
    { forms: [{ fields: ['password'], action: 'https://www.paypal.com/signin', method: 'post', buttonText: 'Log in', labelText: 'PayPal account password', contextText: 'PayPal sign in', contextScope: 'form' }] },
  ).findings.every((finding) => finding.title !== 'Brand-domain mismatch' && finding.title !== 'Brand impersonation with sensitive form'));
const longPaypalReferencePage = runFullAnalysis(
  'https://news.example.org/research',
  `${'This reference article discusses PayPal security history and online payment safety. '.repeat(24)}\nSign in to our unrelated account`,
  {
    referenceContent: true,
    forms: [{ fields: ['email', 'password'], action: 'https://news.example.org/session', method: 'post', buttonText: 'Sign in', labelText: 'Account password' }],
    links: ['https://unrelated.example.net/about', 'https://docs.example.org/security'],
  },
);
assertCase('long PayPal reference page with unrelated login and external links stays low risk',
  longPaypalReferencePage.score < 12
    && longPaypalReferencePage.findings.every((finding) => finding.title !== 'Brand-domain mismatch' && finding.title !== 'Brand impersonation with sensitive form'));
const paypalLinkTextAnalysis = runFullAnalysis('https://news.example.com/', 'Read about PayPal', {
  linkMetadata: [{ href: 'https://example.com/articles/paypal', label: 'Read about PayPal' }],
});
assertCase('informational PayPal anchor to ordinary external page is not mismatched',
  paypalLinkTextAnalysis.findings.every((finding) => finding.title !== 'Brand-destination mismatch'));
const paypalLoginLinkAnalysis = runFullAnalysis('https://news.example.com/', 'Login to PayPal', {
  linkMetadata: [{ href: 'https://paypal-security-example.xyz/login', label: 'Login to PayPal' }],
});
assertCase('PayPal login anchor to deceptive destination creates a mismatch signal',
  paypalLoginLinkAnalysis.findings.some((finding) => finding.title === 'Brand-destination mismatch')
    && paypalLoginLinkAnalysis.overallSeverity !== 'threat');

const passwordOnly = runFullAnalysis('https://login.example.com/', 'Sign in to continue.', {
  credentialForm: true,
  forms: [{ fields: ['password current-password'], action: 'https://login.example.com/session', method: 'post', buttonText: 'Sign in', labelText: 'Password' }],
});
assertCase('password field alone remains weak evidence',
  passwordOnly.score < 12 && passwordOnly.overallSeverity === 'safe');
const suspiciousPaypalForm = runFullAnalysis('https://paypal-security-example.com/login', 'PayPal account verification', {
  credentialForm: true,
  forms: [{ fields: ['email username', 'password current-password', 'card number', 'CVV'], action: 'https://random-example.xyz/collect', method: 'post', buttonText: 'Verify account', labelText: 'PayPal email password card security code' }],
});
assertCase('PayPal identity plus sensitive form and unrelated action is high-confidence',
  suspiciousPaypalForm.overallSeverity === 'threat'
    && suspiciousPaypalForm.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form')
    && suspiciousPaypalForm.findings.some((finding) => finding.title === 'Sensitive form external destination'));
const suspiciousExternalForm = runFullAnalysis('https://shop.example.com/checkout', 'Checkout', {
  forms: [{ fields: ['password'], action: 'https://collector.example.xyz/submit', method: 'post', buttonText: 'Continue', labelText: 'Password' }],
});
assertCase('sensitive form to unrelated external host is supporting evidence',
  suspiciousExternalForm.findings.some((finding) => finding.title === 'Sensitive form external destination')
    && suspiciousExternalForm.overallSeverity !== 'threat');
const trustedPaymentForm = runFullAnalysis('https://shop.example.com/checkout', 'Secure checkout', {
  forms: [{ fields: ['card number', 'CVV'], action: 'https://checkout.stripe.com/pay', method: 'post', buttonText: 'Pay', labelText: 'Card number security code' }],
});
assertCase('legitimate external payment provider is not treated as suspicious action',
  trustedPaymentForm.findings.every((finding) => finding.title !== 'Sensitive form external destination'));
assertCase('same-origin sensitive form action is not suspicious',
  runFullAnalysis('https://account.example.com/login', 'Sign in', {
    forms: [{ fields: ['password'], action: 'https://account.example.com/auth', method: 'post', buttonText: 'Sign in', labelText: 'Password' }],
  }).findings.every((finding) => finding.title !== 'Sensitive form external destination'));
const cardAutocomplete = runFullAnalysis('https://shop.example.com/payment', 'Secure checkout', {
  forms: [{
    fields: ['autocomplete cc-number', 'autocomplete cc-exp', 'autocomplete cc-exp-month', 'autocomplete cc-exp-year', 'autocomplete cc-csc'],
    action: 'https://shop.example.com/payment',
    method: 'post',
    buttonText: 'Pay',
    labelText: 'Card information',
  }],
});
assertCase('card autocomplete metadata is detected structurally without a threat by itself',
  cardAutocomplete.score < 12
    && cardAutocomplete.findings.some((finding) => finding.title === 'Sensitive form fields' && finding.evidence?.fieldCount === 5));
const legitimateAutocompletePayment = runFullAnalysis('https://shop.example.com/checkout', 'Secure checkout', {
  forms: [{
    fields: ['autocomplete cc-number', 'autocomplete cc-exp', 'autocomplete cc-csc'],
    action: 'https://checkout.stripe.com/pay',
    method: 'post',
    buttonText: 'Pay',
    labelText: 'Card number expiration security code',
  }],
});
assertCase('legitimate external payment provider with card autocomplete remains low risk',
  legitimateAutocompletePayment.score < 12
    && legitimateAutocompletePayment.findings.every((finding) => finding.title !== 'Sensitive form external destination'));
const suspiciousAutocompletePayment = runFullAnalysis('https://refund.example.com/claim', 'Pay a processing fee to receive your refund.', {
  forms: [{
    fields: ['autocomplete cc-number', 'autocomplete cc-exp', 'autocomplete cc-csc'],
    action: 'https://collector.example.xyz/submit',
    method: 'post',
    buttonText: 'Claim refund',
    labelText: 'Card number expiration security code',
  }],
});
assertCase('suspicious external payment action with card autocomplete is detected',
  suspiciousAutocompletePayment.findings.some((finding) => finding.title === 'Sensitive form external destination')
    && suspiciousAutocompletePayment.findings.some((finding) => finding.title === 'Payment lure with card form')
    && suspiciousAutocompletePayment.overallSeverity === 'threat');
const cardRefundForm = runFullAnalysis('https://refund.example.com/', 'Pay a processing fee to receive your refund.', {
  forms: [{ fields: ['card number', 'CVV'], action: 'https://refund.example.com/claim', method: 'post', buttonText: 'Claim refund', labelText: 'Card number CVV' }],
});
assertCase('card/CVV form reinforces a payment/refund scam',
  cardRefundForm.overallSeverity === 'threat' && cardRefundForm.findings.some((finding) => finding.title === 'Payment lure with card form'));
assertCase('OTP account threat plus suspicious host becomes high risk',
  runFullAnalysis('https://paypal-login.xyz/', 'PayPal account is blocked. Share your OTP now.', {
    credentialForm: true,
    forms: [{ fields: ['one-time-code', 'password'], action: 'https://collector.example.xyz/submit', method: 'post', buttonText: 'Verify', labelText: 'PayPal account OTP' }],
  }).overallSeverity === 'threat');
assertCase('domain infrastructure signals do not create a threat alone',
  runFullAnalysis('https://paypal-security-example.xyz/', 'Welcome.').overallSeverity !== 'threat');
const lookalikeOnly = runFullAnalysis('https://paypal-security-example.com/', 'Welcome to our information page.');
assertCase('lookalike domain alone remains a supporting signal',
  lookalikeOnly.score <= 18 && lookalikeOnly.findings.some((finding) => finding.title === 'Brand-lookalike domain'));
const mismatchOnly = runFullAnalysis(
  'https://example.com/security',
  'PayPal account suspended. Click here to verify.',
);
const lookalikeAndMismatch = runFullAnalysis(
  'https://paypal-security-example.com/security',
  'PayPal account suspended. Click here to verify.',
);
assertCase('brand/domain mismatch without a sensitive form is supporting evidence',
  mismatchOnly.findings.some((finding) => finding.title === 'Brand-domain mismatch')
    && mismatchOnly.findings.every((finding) => finding.title !== 'Brand impersonation with sensitive form'));
assertCase('lookalike plus brand mismatch does not add the same hostname evidence twice',
  lookalikeAndMismatch.findings.some((finding) => finding.title === 'Brand-domain mismatch')
    && lookalikeAndMismatch.score <= mismatchOnly.score + 2);
const mismatchSuspiciousTld = runFullAnalysis(
  'https://paypal-security-example.xyz/login',
  'PayPal account suspended. Click here to verify.',
);
assertCase('brand mismatch groups suspicious TLD infrastructure within a bounded score',
  mismatchSuspiciousTld.findings.some((finding) => finding.title === 'Brand-domain mismatch')
    && mismatchSuspiciousTld.score <= mismatchOnly.score + 8);
const mismatchHyphenHost = runFullAnalysis(
  'https://paypal-security-example-secure-account.com/login',
  'PayPal account suspended. Click here to verify.',
);
assertCase('brand mismatch groups hyphen-heavy hostname evidence within a bounded score',
  mismatchHyphenHost.findings.some((finding) => finding.title === 'Brand-domain mismatch')
    && mismatchHyphenHost.score <= mismatchOnly.score + 8);
const mismatchWithCredentialForm = runFullAnalysis(
  'https://paypal-security-example.com/login',
  'Verify your PayPal account',
  { forms: [{
    fields: ['password'],
    action: 'https://paypal-security-example.com/login',
    method: 'post',
    buttonText: 'Verify',
    labelText: 'PayPal account password',
    contextText: 'Verify your PayPal account',
  }] },
);
assertCase('brand mismatch plus a related credential form reaches high risk',
  mismatchWithCredentialForm.findings.some((finding) => finding.title === 'Brand impersonation with sensitive form')
    && mismatchWithCredentialForm.score >= 40);
const mismatchCredentialThreat = runFullAnalysis(
  'https://paypal-security-example.com/login',
  'PayPal account suspended. Verify your account.',
  { forms: [{
    fields: ['password'],
    action: 'https://collector.example.xyz/submit',
    method: 'post',
    buttonText: 'Verify',
    labelText: 'PayPal account password',
    contextText: 'PayPal account suspended. Verify your account.',
  }] },
);
assertCase('brand mismatch, related credential form, and account threat add independent evidence',
  mismatchCredentialThreat.score > mismatchWithCredentialForm.score
    && mismatchCredentialThreat.overallSeverity === 'threat');
const infrastructureWithUnrelatedMention = runFullAnalysis(
  'https://unrelated-domain.xyz/',
  'This article contains PayPal account security information.',
);
assertCase('infrastructure and an unrelated brand mention do not create impersonation or excessive risk',
  infrastructureWithUnrelatedMention.score <= 18
    && infrastructureWithUnrelatedMention.findings.every((finding) => finding.title !== 'Brand-domain mismatch' && finding.title !== 'Brand impersonation with sensitive form'));
const rawIpCredentialForm = runFullAnalysis('http://192.0.2.1/login', 'Sign in to continue.', {
  forms: [{ fields: ['password'], action: 'http://192.0.2.1/login', method: 'post', buttonText: 'Sign in', labelText: 'Password' }],
});
assertCase('raw IP plus a credential form remains supporting evidence without other scam context',
  rawIpCredentialForm.findings.some((finding) => finding.title === 'Raw IP address')
    && rawIpCredentialForm.overallSeverity !== 'threat');
const duplicateUrgency = runFullAnalysis('https://message.example/', 'Urgent urgent urgent! Act now immediately within 2 hours!');
assertCase('repeated urgency language remains score-capped',
  duplicateUrgency.score <= 6);
assertCase('lookalike plus suspicious TLD remains capped as one weak infrastructure group',
  runFullAnalysis('https://paypal-security-example.xyz/', 'Welcome to the information page.').score <= 18);
const paypalDemoPattern = runFullAnalysis('https://paypal-security-example.com/login', 'PayPal account verification', {
  credentialForm: true,
  forms: [{ fields: ['email', 'password', 'card number', 'CVV'], action: 'https://random-example.xyz/collect', method: 'post', buttonText: 'Continue', labelText: 'PayPal account verification' }],
});
const legitimatePaypalPattern = runFullAnalysis('https://www.paypal.com/signin', 'PayPal account sign in', {
  credentialForm: true,
  forms: [{ fields: ['email', 'password'], action: 'https://www.paypal.com/signin', method: 'post', buttonText: 'Log in', labelText: 'Email password' }],
});
assertCase('PayPal PhishLens-style impersonation fixture scores materially above legitimate PayPal',
  paypalDemoPattern.score >= 40 && paypalDemoPattern.score > legitimatePaypalPattern.score + 30);

console.log('Modern scam-family and relationship regressions:');
const modernScams = [
  ['OAuth authorization deception', 'Allow this Google app access to restore your blocked account and continue immediately.'],
  ['unknown app requests account access and password', 'Allow this unknown app to access your account and enter your password to continue.'],
  ['app authorization threatens suspension', 'Authorize this application or your account will be suspended.'],
  ['recovery-code theft', 'Please send me your recovery code to restore account access.'],
  ['MFA approval pressure', 'Approve this sign-in you did not initiate or your account will be blocked.'],
  ['fake CAPTCHA command', 'Verify you are human with this CAPTCHA, then press Win+R and paste the command to continue.'],
  ['shared-document credential bait', 'A shared invoice document requires sign-in; enter your password to view it.'],
  ['callback phishing', 'Suspicious charge detected. Call 18005551234 immediately to cancel the payment.'],
  ['QR refund phishing', 'Scan this QR code to receive your refund payment now.'],
  ['advance fee to release refund', 'Pay a processing fee to receive your pending refund.'],
  ['job registration fee scam', 'Remote job available. Pay a registration fee to start the job and get paid.'],
  ['task scam security deposit', 'Complete online tasks and pay a security deposit to withdraw your earnings.'],
  ['investment withdrawal fee scam', 'Guaranteed investment returns; transfer a withdrawal tax fee to release your profit.'],
  ['authority impersonation', 'CBI officer says your parcel contains drugs; pay customs urgently or face arrest.'],
] as const;
for (const [label, text] of modernScams) {
  const result = verdict(text);
  assertCase(label, result.overallSeverity === 'threat' || result.overallSeverity === 'caution', `${result.score} ${result.overallSeverity}`);
}
const benignCases = [
  ['generic authorization wording', 'https://login.example.com/', 'Allow access to continue.'],
  ['multilingual news article', 'https://news.example.org/article', 'இந்த செய்தி பொதுமக்களுக்கான தகவல்; இங்கு எந்த பணமும் அல்லது ரகசிய குறியீடும் கேட்கப்படவில்லை.'],
  ['security article warning', 'https://security.example.org/guide', 'Security awareness guide: never share your O T P; learn how to report phishing.'],
  ['normal login', 'https://login.example.com/', 'Sign in to view your account dashboard.'],
  ['normal payment receipt', 'https://payments.example.com/receipt', 'Payment received successfully. Your receipt is available in your account.'],
  ['normal job listing', 'https://careers.example.com/jobs', 'Part-time job opening: apply with your resume; salary and benefits are listed.'],
  ['normal investment article', 'https://finance.example.com/education', 'This educational article explains investment risk, returns, and market volatility.'],
  ['normal CAPTCHA', 'https://example.com/verify', 'Complete the CAPTCHA to continue browsing.'],
  ['refund availability without a demand', 'https://shop.example.com/orders', 'A refund is available for the returned item.'],
  ['ordinary job availability', 'https://careers.example.com/', 'Job opening available in the engineering department.'],
  ['routine authentication approval wording', 'https://login.example.com/', 'Approve a login request you initiated on this device.'],
  ['ordinary courier delivery', 'https://delivery.example.com/', 'Your courier delivery is scheduled for tomorrow.'],
  ['routine payment fee information', 'https://billing.example.com/', 'The processing fee is listed on the invoice for transparency.'],
  ['routine family new-number message', 'https://messages.example.com/', 'Hi mom, this is my new number.'],
  ['URL path with login word without link instructions', 'https://messages.example.com/', 'Reference link: https://example.com/paypal/login'],
  ['routine utility maintenance notice', 'https://utility.example.com/', 'Electricity service will be disconnected tonight for scheduled maintenance.'],
] as const;
for (const [label, url, text] of benignCases) {
  assertCase(label, runFullAnalysis(url, text).overallSeverity === 'safe', runFullAnalysis(url, text).overallSeverity);
}

const emailIntel = extractIntel('Contact support@company.com for help.');
assertCase('email addresses are not misreported as UPI IDs', emailIntel.upiIds.length === 0);
const accountIntel = extractIntel('Order id 7894561230123 confirmed. Call 9876543210.');
assertCase('long order IDs and phone numbers are not bank accounts', accountIntel.bankAccounts.length === 0);
const transferIntel = extractIntel('Transfer to account 123456789012, IFSC HDFC0001234. Link: https://evil.xyz/login?x=1).');
assertCase('account numbers are extracted when labeled', transferIntel.bankAccounts.includes('123456789012'));
assertCase('URL punctuation and query parameters are removed', transferIntel.urls[0] === 'https://evil.xyz/login');
assertCase('protocol-relative links are extracted', extractIntel('Open //evil.xyz/login').urls[0] === 'https://evil.xyz/login');

const originalFetch = globalThis.fetch;
let rdapCalls = 0;
let rdapUrl = '';
globalThis.fetch = (async (input) => {
  rdapCalls++;
  rdapUrl = String(input);
  return new Response(JSON.stringify({
    events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 10 * 86400000).toISOString() }],
  }), { status: 200, headers: { 'content-type': 'application/json' } });
}) as typeof fetch;
try {
  const firstAge = await checkDomainAge('login.example.co.in');
  const secondAge = await checkDomainAge('www.example.co.in');
  assertCase('RDAP lookup uses the registrable domain and warns cautiously',
    firstAge?.severity === 'caution' && firstAge.evidence?.hostname === 'example.co.in' && rdapUrl.endsWith('/example.co.in'));
  assertCase('RDAP results are cached across subdomains', !!secondAge && rdapCalls === 1);
  await checkDomainAge('localhost');
  await checkDomainAge('service.example.local');
  assertCase('local and single-label hosts do not trigger RDAP requests', rdapCalls === 1);
} finally {
  globalThis.fetch = originalFetch;
}

console.log(`\nBenchmark assertions: ${passed} passed, ${failed} failed.`);
if (failed > 0) process.exitCode = 1;
