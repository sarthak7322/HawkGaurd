import { checkDomainAge, getDomainParts, normalizeUnicode, runFullAnalysis, extractIntel } from '../src/shared/detection';

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
} finally {
  globalThis.fetch = originalFetch;
}

console.log(`\nBenchmark assertions: ${passed} passed, ${failed} failed.`);
if (failed > 0) process.exitCode = 1;
