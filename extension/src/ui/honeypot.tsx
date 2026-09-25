// Live honeypot card: the trap link (with a QR code so a teammate can play the scammer from a
// phone) and a feed of everything the scammer did on the decoy site. Styles in ./modern.css.

import { useEffect, useMemo, useState } from 'react';
import qrcode from 'qrcode-generator';
import { Crosshair, Globe, KeyRound, Laptop, Map as MapIcon, MapPin, Trash2 } from 'lucide-react';
import { groupIntruders, mapUrl, type DecoyInfo, type HoneypotEvent, type Intruder } from '../shared/honeypot';
import { clearHoneypot, fetchHoneypot, DEFAULT_BACKEND } from './ai';

const POLL_MS = 2500;

// Poll the backend's honeypot log. Only events after `since` count, so old demo runs don't leak in.
export function useHoneypot(since: number, base = DEFAULT_BACKEND) {
  const [decoy, setDecoy] = useState<DecoyInfo | null>(null);
  const [events, setEvents] = useState<HoneypotEvent[]>([]);
  const [online, setOnline] = useState<boolean | undefined>(undefined);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const data = await fetchHoneypot(base);
      if (!alive) return;
      setOnline(!!data);
      if (data) {
        setDecoy(data.decoy);
        setEvents(data.events.filter((e) => e.at >= since));
      }
    };
    tick();
    const t = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [since, base]);

  const intruders = useMemo(() => groupIntruders(events), [events]);
  const clear = async () => {
    await clearHoneypot(base);
    setEvents([]);
  };
  return { decoy, events, intruders, online, clear };
}

function QrCode({ text, size = 112 }: { text: string; size?: number }) {
  const cells = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    let d = '';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c} ${r}h1v1h-1z`;
    return { n, d };
  }, [text]);
  return (
    <svg className="qr" viewBox={`-2 -2 ${cells.n + 4} ${cells.n + 4}`} width={size} height={size} role="img" aria-label="QR code for the decoy login">
      <rect x="-2" y="-2" width={cells.n + 4} height={cells.n + 4} fill="#fff" />
      <path d={cells.d} fill="#0b0c10" />
    </svg>
  );
}

const time = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

export function IntruderCard({ v, selected, onSelect }: { v: Intruder; selected?: boolean; onSelect?: () => void }) {
  return (
    <article className={`intruder intruder--${v.worst} ${selected ? 'is-selected' : ''} ${onSelect ? 'is-clickable' : ''}`} onClick={onSelect}>
      <div className="intruder-head">
        <span className="intruder-device">
          <Laptop size={13} /> {v.device} · {v.browser}
        </span>
        {v.automated && <span className="flag flag--threat">bot / script</span>}
        {v.loggedIn && <span className="flag flag--threat">logged in</span>}
      </div>
      <div className="intruder-facts">
        <span className="mono">{v.ip}</span>
        <span>
          <Globe size={11} /> {v.geo.label}
          {v.geo.isp ? ` · ${v.geo.isp}` : ''}
        </span>
        {v.geo.lat !== undefined && v.geo.lon !== undefined && (
          <a className="map-link" href={mapUrl(v.geo.lat, v.geo.lon)} target="_blank" rel="noreferrer" title="Approximate — IP geolocation is city-level">
            <MapPin size={11} /> ≈ {v.geo.lat.toFixed(3)}, {v.geo.lon.toFixed(3)}
          </a>
        )}
        {v.geo.mobile && <span>mobile network</span>}
        {v.geo.asn && <span className="mono">{v.geo.asn.split(' ')[0]}</span>}
        {v.geo.vpn && <span className="flag flag--caution">VPN / hosting IP</span>}
        {v.language && <span>lang {v.language}</span>}
      </div>
      {v.credentialsTried.length > 0 && (
        <div className="chips">
          {v.credentialsTried.map((c, i) => (
            <span key={i} className="chip">
              <KeyRound size={10} /> {c.username || '—'} / {c.password || '—'}
            </span>
          ))}
        </div>
      )}
      <ol className="intruder-log">
        {v.actions.slice(-6).map((e) => (
          <li key={e.id} className={`sev-${e.severity}`}>
            <span className="mono">{time(e.at)}</span> {e.detail}
          </li>
        ))}
      </ol>
    </article>
  );
}

export function HoneypotCard(props: {
  decoy: DecoyInfo | null;
  online: boolean | undefined;
  lured: boolean;
  intruders: Intruder[];
  onClear: () => void;
  compact?: boolean;
}) {
  const { decoy, lured, intruders } = props;
  const status =
    props.online === false
      ? ['Backend offline', 'flag--caution']
      : intruders.some((v) => v.loggedIn)
        ? ['Scammer is inside the trap', 'flag--threat']
        : intruders.length
          ? ['Scammer took the bait', 'flag--threat']
          : lured
            ? ['Bait sent · waiting', 'flag--caution']
            : ['Armed', 'flag--safe'];

  return (
    <div className={`honeypot ${props.compact ? 'honeypot--compact' : ''}`}>
      <div className="card-head">
        <h2>
          <Crosshair size={15} /> Honeypot trap
        </h2>
        <span className={`flag ${status[1]}`}>{status[0]}</span>
      </div>

      {!lured || !decoy ? (
        <p className="muted honeypot-hint">
          On the persona's 3rd reply they "trust" the scammer and hand over a login to a fake shop website. Whoever
          uses it gets fingerprinted.
        </p>
      ) : (
        <div className="trap">
          <QrCode text={decoy.loginUrl} size={props.compact ? 92 : 112} />
          <div className="trap-body">
            <div className="muted">Decoy login handed to the scammer · scan to play them</div>
            <a className="trap-url mono" href={decoy.loginUrl} target="_blank" rel="noreferrer">
              {decoy.loginUrl}
            </a>
            <div className="chips">
              <span className="chip">user {decoy.username}</span>
              <span className="chip">pass {decoy.password}</span>
            </div>
          </div>
        </div>
      )}

      {intruders.length > 0 && (
        <div className="intruders">
          {intruders.map((v) => (
            <IntruderCard key={v.visitor} v={v} />
          ))}
          <div className="honeypot-actions">
            <a className="btn btn-accent" href={new URL('../map/index.html', location.href).href} target="_blank" rel="noreferrer">
              <MapIcon size={14} /> Open threat map
            </a>
            <button className="btn btn-ghost honeypot-clear" onClick={props.onClear}>
              <Trash2 size={13} /> Clear trap log
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
