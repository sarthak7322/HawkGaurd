import { runFullAnalysis, extractIntel } from '../src/shared/detection';
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
];
const verdict = (t: string) => runFullAnalysis('https://sms.local/', t);
let tp = 0, fp = 0;
console.log('SCAM MESSAGES (should be caution/threat):');
for (const t of SCAMS) { const a = verdict(t); const hit = a.overallSeverity === 'threat' || a.overallSeverity === 'caution'; if (hit) tp++; console.log(`  ${hit ? '✓' : '✗ MISSED'} ${a.overallSeverity.padEnd(7)} ${String(a.score).padStart(3)}  ${t.slice(0, 70)}`); }
console.log('LEGIT MESSAGES (should be safe/unknown):');
for (const t of LEGIT) { const a = verdict(t); const flagged = a.overallSeverity === 'threat' || a.overallSeverity === 'caution'; if (flagged) fp++; console.log(`  ${flagged ? '✗ FALSE ALARM' : '✓'} ${a.overallSeverity.padEnd(7)} ${String(a.score).padStart(3)}  ${t.slice(0, 70)}`); }
console.log(`\nDetection rate: ${tp}/${SCAMS.length} (${Math.round(100 * tp / SCAMS.length)}%) · False alarms: ${fp}/${LEGIT.length} (${Math.round(100 * fp / LEGIT.length)}%)`);
console.log('\nINTEL EXTRACTION:');
for (const t of [
  'Contact support@company.com for help',
  'Pay to rahul.verma@okhdfcbank now',
  'Transfer to account 123456789012, IFSC HDFC0001234',
  'Call +91 98765 43210 or 098765-43210',
  'Order id 7894561230123 confirmed',
  'Link: https://evil.xyz/login?x=1).',
]) { const i = extractIntel(t); console.log(`  "${t}"\n     upi=${JSON.stringify(i.upiIds)} phones=${JSON.stringify(i.phoneNumbers)} accounts=${JSON.stringify(i.bankAccounts)} urls=${JSON.stringify(i.urls)}`); }
