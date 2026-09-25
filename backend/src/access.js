// Who may reach what.
//
//   /shop/…         the honeypot trap — open to everyone (tunnel, Wi-Fi, this laptop).
//   everything else the API (captured attacker data, AI proxy) and the demo/extension build —
//                   this laptop only.
//
// Three checks, because each closes a different door:
//   1. Tunnel: cloudflared/ngrok connect from localhost, so a request from the internet looks
//      local by socket address. The tunnel stamps its own headers on every request and a
//      visitor cannot strip them, so their presence means "came from outside".
//   2. Wi-Fi: anyone else on the network connects from a non-loopback address.
//   3. Browser: a website the user visits can aim requests at localhost, or DNS-rebind its own
//      hostname to 127.0.0.1. The Host header must name localhost, and any Origin must be the
//      extension or this backend's own pages. (CORS alone only hides responses — it doesn't
//      stop a request from running, e.g. a DELETE wiping the log.)

const TUNNEL_HEADERS = ['cf-connecting-ip', 'cf-ray', 'cdn-loop', 'x-forwarded-for', 'x-forwarded-host', 'ngrok-trace-id'];
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const LOCAL_HOST = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

// No dot-segments: "/shop/../api/honeypot" must not ride the /shop exemption past the lock
export const isPublicPath = (path) =>
  (path === '/shop' || path.startsWith('/shop/')) && !/(^|\/)(\.|%2e){2}(\/|$)/i.test(path);

export function localOnly() {
  const refused = new Set(); // log each blocked source once, not on every request

  return (req, res, next) => {
    if (isPublicPath(req.path)) return next();

    const origin = req.get('origin');
    const reason = TUNNEL_HEADERS.some((h) => req.get(h))
      ? 'via tunnel'
      : !LOOPBACK.has(req.socket.remoteAddress)
        ? 'from network'
        : !LOCAL_HOST.test(req.get('host') || '')
          ? 'foreign Host header'
          : origin && !origin.startsWith('chrome-extension://') && !LOCAL_HOST.test(origin.replace(/^https?:\/\//, ''))
            ? 'foreign Origin'
            : null;

    if (!reason) return next();

    const who = `${reason} ${req.get('cf-connecting-ip') || req.socket.remoteAddress}`;
    if (!refused.has(who)) {
      if (refused.size > 1000) refused.clear();
      refused.add(who);
      console.warn(`[HawkGuard backend] 🔒 blocked ${req.method} ${req.path} (${who})`);
    }
    // Look like there's nothing here rather than advertising a locked door
    res.status(404).type('text/plain').send('Not found');
  };
}
