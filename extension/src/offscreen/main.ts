import { playScreech } from '../ui/sound';

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.kind === 'PLAY_SCREECH' && msg.target === 'offscreen') playScreech(msg.volume);
});
