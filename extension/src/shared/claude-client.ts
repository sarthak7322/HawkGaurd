// Claude API client for HawkGuard
// SECURITY NOTE: All calls go through a local backend proxy (localhost:3789)
// so the API key never lives in the extension.
//
// The prompt architecture is CONSTRAINED:
//   - The LLM only sees a template + persona metadata
//   - It never sees raw scammer text
//   - Its job is to naturalize the template in the persona's voice
//   - It returns just the response string, no instructions can leak through

import type { Persona } from './types';

const DEFAULT_BACKEND = 'http://localhost:3789';

export async function generatePersonaResponse(
  persona: Persona,
  templateResponse: string,
  turnNumber: number,
  backendUrl: string = DEFAULT_BACKEND
): Promise<string> {
  const url = `${backendUrl}/api/generate-response`;

  const payload = {
    persona: {
      displayName: persona.displayName,
      age: persona.age,
      location: persona.location,
      occupation: persona.occupation,
      personality: persona.personality,
      writingStyle: persona.writingStyle,
      quirks: persona.quirks,
    },
    template: templateResponse,
    turnNumber,
  };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      console.warn('[HawkGuard] Backend unavailable, using template as-is');
      return templateResponse;
    }

    const data = await res.json();
    return data.response || templateResponse;
  } catch (err) {
    console.warn('[HawkGuard] Backend error, falling back to template:', err);
    return templateResponse;
  }
}

export async function checkBackendHealth(backendUrl: string = DEFAULT_BACKEND): Promise<boolean> {
  try {
    const res = await fetch(`${backendUrl}/api/health`);
    return res.ok;
  } catch {
    return false;
  }
}
