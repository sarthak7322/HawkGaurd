import type { Persona } from '../shared/types';
import type { DecoyInfo, HoneypotEvent } from '../shared/honeypot';

export type Provider = 'claude' | 'gemini' | null;

export interface Health {
  ok: boolean;
  provider: Provider;
  honeypot?: DecoyInfo;
}

// Served by the backend (http://localhost:3789) → same origin; inside the extension → absolute
export const DEFAULT_BACKEND = location.protocol.startsWith('http') ? '' : 'http://localhost:3789';

export async function fetchHealth(base = DEFAULT_BACKEND): Promise<Health | null> {
  try {
    const res = await fetch(`${base}/api/health`);
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

// Same constrained payload the background worker sends: persona profile + safe template + turn.
// The scammer's text is deliberately not a parameter here.
export function aiPayload(persona: Persona, template: string, turnNumber: number) {
  return {
    persona: {
      displayName: persona.displayName,
      age: persona.age,
      location: persona.location,
      occupation: persona.occupation,
      personality: persona.personality,
      writingStyle: persona.writingStyle,
      samples: persona.samples,
      quirks: persona.quirks,
    },
    template,
    turnNumber,
  };
}

export async function generateReply(
  persona: Persona,
  template: string,
  turnNumber: number,
  base = DEFAULT_BACKEND
): Promise<{ text: string; rewritten: boolean }> {
  try {
    const res = await fetch(`${base}/api/generate-response`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(aiPayload(persona, template, turnNumber)),
    });
    const data = await res.json();
    const text: string = data.response || template;
    return { text, rewritten: text !== template };
  } catch {
    return { text: template, rewritten: false };
  }
}

export async function fetchHoneypot(base = DEFAULT_BACKEND): Promise<{ decoy: DecoyInfo; events: HoneypotEvent[] } | null> {
  try {
    const res = await fetch(`${base}/api/honeypot`);
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

export async function clearHoneypot(base = DEFAULT_BACKEND): Promise<void> {
  await fetch(`${base}/api/honeypot`, { method: 'DELETE' }).catch(() => {});
}
