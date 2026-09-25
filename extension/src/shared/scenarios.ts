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
// It only sees: "generate a natural-sounding variation of this template
// in the voice of {persona}", plus safe metadata.
//
// Written the way people actually text on these calls: short, plain, a bit distracted,
// asking questions back. Stalling works best when it sounds real, not theatrical.
export const RESPONSE_TEMPLATES: Record<ScamScenario, string[]> = {
  payment_request: [
    "ok but how to do upi. my grandson does all this for me",
    "wait, which account? i have 2, one is very old",
    "i'll have to ask my son first. he comes home by 7",
    "can i just go to the branch tomorrow and pay there?",
    "why do i have to pay if the mistake is from your side?",
  ],
  otp_solicitation: [
    "some message came. which one? there are 3 messages",
    "wait let me get my glasses. the numbers are very small",
    "my daughter says never tell otp to anyone. why do you need it?",
    "it says do not share this with anyone. is that ok?",
    "the message went away. can you send it again",
  ],
  identity_verification: [
    "aadhaar is in the almirah. give me 5 min",
    "my son took my aadhaar for some work. can you call back in the evening?",
    "why do you need all this? bank already has it no",
    "which one, aadhaar or pan? i have both somewhere",
    "hold on, let me find it",
  ],
  urgency_escalation: [
    "ok ok please don't shout, i'm trying",
    "one minute. can you speak slowly",
    "why so urgent? i went to the bank only last week",
    "i'm doing it only. phone is very slow today",
    "please wait, somebody is at the door",
  ],
  link_click_bait: [
    "which link? i don't see any link",
    "i clicked. it's just loading and loading",
    "it's asking to download something. should i?",
    "screen went white. now what",
    "can you send it on whatsapp? i can't open from sms",
  ],
  account_info_request: [
    "account number is in my passbook. let me find it",
    "the card is upstairs. my knees are bad, it will take time",
    "which number is cvv? front side or back side?",
    "i have 2 cards. which bank you want?",
    "wait, why do you need my card number for kyc?",
  ],
  personal_details_request: [
    "which address, old one or new one?",
    "dob on my aadhaar is wrong actually. which one you want?",
    "my name spelling is different on every card",
    "why you need all this? you are from the bank no",
    "one sec, let me write it down first",
  ],
  reassurance_seeking: [
    "how do i know you are really from the bank?",
    "can you give me your office number? i'll call back",
    "my son says so many fraud calls are coming these days",
    "ok. what is your name and employee id?",
    "i'll just go to the branch and ask them once, ok?",
  ],
  unknown: [
    "sorry, what?",
    "didn't understand. say again",
    "hello? network is very bad here",
    "one sec",
    "what is this on my screen?",
  ],
};

export function pickTemplate(scenario: ScamScenario): string {
  const templates = RESPONSE_TEMPLATES[scenario];
  return templates[Math.floor(Math.random() * templates.length)];
}
