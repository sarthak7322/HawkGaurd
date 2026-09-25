#!/bin/bash
# Double-click to run HawkGuard for a demo (Wi-Fi mode — no tunnel, no account, nothing to die).
# The honeypot trap is served on this Mac's Wi-Fi address, so a phone on the SAME Wi-Fi can open it.
# Close this window (or press Ctrl+C) to stop.

cd "$(dirname "$0")" || exit 1

# Wi-Fi mode: no public tunnel URL, so the backend uses this Mac's LAN address automatically.
sed -i '' 's/^HONEYPOT_PUBLIC_URL=/# HONEYPOT_PUBLIC_URL=/' backend/.env 2>/dev/null

# stop anything left over
pkill -f "cloudflared tunnel" 2>/dev/null
pkill -f "ngrok http" 2>/dev/null
pkill -f "node src/server.js" 2>/dev/null
sleep 1

LAN=$(ipconfig getifaddr en0 2>/dev/null)
[ -z "$LAN" ] && LAN=$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127\.' | head -1)

echo "▲ Starting HawkGuard (Wi-Fi mode)…"
echo "   Live demo (this Mac):  http://localhost:3789"
[ -n "$LAN" ] && echo "   Trap for phones on the same Wi-Fi:  http://$LAN:3789/shop/wp-login.php"
echo "   Keep this window open during the demo. Start a NEW engagement so the QR uses the current address."
echo

trap 'echo; echo "▲ Stopping HawkGuard…"; pkill -f "node src/server.js" 2>/dev/null; exit 0' INT TERM HUP
cd backend || exit 1
# caffeinate keeps the Mac awake so the backend stays reachable during the demo
caffeinate -dims npm start &
wait $!
