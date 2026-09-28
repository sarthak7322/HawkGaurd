// Scenario classifier — this is the injection-resistant heart of HawkGuard.
// The scammer's message is never fed as free text to an LLM. Instead:
//   1. We classify the message into one of a small, fixed set of scenarios
//   2. We select a pre-written response template
//   3. The LLM (Claude) only fills in narrow, safe slots

import type { ScamScenario } from './types';

const CLASSIFIER_PATTERNS: Record<Exclude<ScamScenario, 'unknown'>, RegExp[]> = {
  payment_request: [
    /\bsend.{0,20}(rupee|rs\.?|inr|₹|\d+)/i,
    /\bpay.{0,20}\d+/i,
    /\bprocessing fee/i,
    /\bupi\b/i,
    /\btransfer.{0,20}(amount|money)/i,
  ],
  otp_solicitation: [
    /\botp\b/i,
    /\bone.time.password/i,
    /\bverification code/i,
    /\bsms.{0,10}code/i,
    /\b6.digit\b/i,
  ],
  identity_verification: [
    /\baadhaar/i,
    /\bpan\b/i,
    /\bkyc\b/i,
    /\bdate of birth/i,
    /\bfull name/i,
    /\bidentity.{0,20}(verify|proof)/i,
  ],
  urgency_escalation: [
    /\bnow\b|\bimmediately/i,
    /\bwithin.{0,20}(minute|hour)/i,
    /\bwill be (blocked|suspended|closed)/i,
    /\blast chance/i,
    /\bfinal warning/i,
  ],
  link_click_bait: [
    /\bclick.{0,10}(here|link|below)/i,
    /https?:\/\//i,
    /\bvisit.{0,20}website/i,
  ],
  account_info_request: [
    /\baccount number/i,
    /\bifsc/i,
    /\bbank name/i,
    /\bbranch/i,
    /\bcard.{0,10}(number|details)/i,
    /\bcvv/i,
    /\bexpiry/i,
  ],
  personal_details_request: [
    /\bmother.{0,10}maiden/i,
    /\baddress/i,
    /\bdate of birth/i,
    /\bage\b/i,
    /\byour name/i,
  ],
  reassurance_seeking: [
    /\btrust me/i,
    /\bofficial/i,
    /\bgovernment/i,
    /\brbi/i,
    /\bcbi/i,
  ],
};

export function classifyScenario(message: string): ScamScenario {
  const lower = message.toLowerCase();
  // Priority order — more specific / more dangerous scenarios first
  const order: Array<Exclude<ScamScenario, 'unknown'>> = [
    'otp_solicitation',
    'account_info_request',
    'payment_request',
    'identity_verification',
    'personal_details_request',
    'urgency_escalation',
    'link_click_bait',
    'reassurance_seeking',
  ];
  for (const scenario of order) {
    if (CLASSIFIER_PATTERNS[scenario].some((p) => p.test(lower))) {
      return scenario;
    }
  }
  return 'unknown';
}

// Template library — the LLM never sees the scammer's raw text.
// It only sees: "rewrite this template in the voice of {persona}", plus safe metadata.
//
// The goal is to keep the scammer talking, so the decoy plays an easy mark who is TRYING:
// willing, a bit slow, always one small step from doing what they ask. Every reply hands the
// scammer something to do (explain a step, resend, wait), and doubts are soft enough that the
// scammer thinks one more message will fix them. Flat refusals or "this is a fraud" end the chat.
//
// {family} is filled per persona (grandson, son…) before the AI ever sees the template.
export const RESPONSE_TEMPLATES: Record<ScamScenario, string[]> = {
  payment_request: [
    "ok i opened phonepe. where do i put the id",
    "how much you said? and it will come back after, no?",
    "it is asking for pin. the atm pin or some other pin",
    "my {family} set up gpay for me but i never sent money to anyone. what do i press",
    "it says payment failed. should i try again",
    "i will do it, just tell me slowly one by one",
    "ok sending. it is showing some red message now",
    "but why i have to pay, the mistake is from bank side no?",
  ],
  otp_solicitation: [
    "wait a message came just now. is this the one from bank",
    "there are 3 messages from the bank. which one you want",
    "the numbers are very small, let me get my glasses",
    "it says do not share with anyone. but you are from the bank only no?",
    "the message went away from the screen. can you send again",
    "it says expired. can you send a new one",
    "i was trying to copy it and it got deleted. sorry",
    "it is asking me to press something. should i press yes",
  ],
  identity_verification: [
    "aadhaar is in the cupboard. give me few minutes",
    "which one you want, aadhaar or pan? both are somewhere here",
    "my {family} took my aadhaar card for some work. i have one photocopy, will that do?",
    "i found the card but it is very faded. i cant read properly",
    "bank already has all this no? i gave everything when i opened the account",
    "you want the aadhaar number or the pan number?",
    "hold on, let me find my glasses first",
  ],
  urgency_escalation: [
    "ok ok i am doing it. please dont cut the call",
    "please dont block it, all my savings are in that account",
    "i am trying, my phone is very slow today",
    "one minute, someone is at the door. dont go",
    "i dont want any problem. just tell me what to do",
    "i am getting scared now. what will happen if it gets blocked",
    "tell me again slowly, i will write it down",
  ],
  link_click_bait: [
    "which link? i dont see any link",
    "i pressed it. it is just loading",
    "it is asking to download something. should i press ok",
    "the screen went white. now what to do",
    "it opened but the letters are very small. what do i fill",
    "can you send on whatsapp? links from sms dont open in my phone",
    "it is asking my name and number again. should i fill",
  ],
  account_info_request: [
    "account number is in the passbook. let me find it",
    "the card is in the other room, one minute",
    "which number, the long one on the front?",
    "i have 2 cards, one old one new. which one you want",
    "passbook last page is torn. is the first page ok",
    "cvv means what? the small number on the back?",
    "wait i think my card has expired. will the old one work",
  ],
  personal_details_request: [
    "which address, old one or the current one?",
    "date of birth is different on my aadhaar and pan. which one you want",
    "my name spelling is different on every card. which one",
    "one sec, let me write down what you are asking",
    "you want the full address with pincode?",
    "why you need all this? you are from the bank no",
  ],
  reassurance_seeking: [
    "ok if you are from the bank then fine. what should i do",
    "sorry, so many fraud calls come these days. what is your good name?",
    "can you give your office number? just so i can tell my {family}",
    "ok i trust you. but tell me slowly, i dont understand these things",
    "i will do what you say. my money will be safe no?",
    "what is your employee id? my {family} told me to always ask",
  ],
  unknown: [
    "sorry didnt understand. say again?",
    "hello? are you there",
    "one sec",
    "ok. what do i have to do now",
    "sorry i was in the kitchen. what did you say",
    "ok. then?",
  ],
};

// Pick a template for this persona, avoiding any this chat has already used so the decoy
// never repeats itself (a repeated line is the fastest way to sound like a bot).
export function pickTemplate(scenario: ScamScenario, family = 'son', used: string[] = []): string {
  const all = RESPONSE_TEMPLATES[scenario].map((t) => t.replace(/\{family\}/g, family));
  const fresh = all.filter((t) => !used.includes(t));
  const pool = fresh.length ? fresh : all;
  return pool[Math.floor(Math.random() * pool.length)];
}
