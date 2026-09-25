// The hawk screech that plays when HawkGuard catches a scam.
// Swap src/assets/hawk-screech.wav for any short clip to change it.
import screechUrl from '../assets/hawk-screech.wav';

export function playScreech(volume = 0.6): Promise<void> {
  const audio = new Audio(screechUrl);
  audio.volume = volume;
  // Browsers refuse audio before the user has interacted with the page — that's fine, stay quiet
  return audio.play().catch(() => {});
}
