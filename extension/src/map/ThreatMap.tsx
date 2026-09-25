// Threat map: plots every honeypot intruder at their approximate (IP-based) location, with a
// live-updating side list. Opened from the Honeypot card. Dark tiles to match the theme.

import { useEffect, useMemo, useRef, useState } from 'react';
import L from 'leaflet';
import Globe from 'globe.gl';
import { Crosshair, Globe2, Map as MapIcon, ShieldAlert } from 'lucide-react';
import { fetchHoneypot, DEFAULT_BACKEND } from '../ui/ai';
import { IntruderCard } from '../ui/honeypot';
import { groupIntruders, type HoneypotEvent, type Intruder } from '../shared/honeypot';

const POLL_MS = 2500;
const SEV_COLOR: Record<Intruder['worst'], string> = {
  info: '#7d8497',
  medium: '#ffb547',
  high: '#ff5d6c',
  critical: '#ff5d6c',
};

// The "home" HawkGuard node the attack-arcs point back to (India centroid)
const HUB = { lat: 20.6, lng: 78.96 };

// ─── 3D globe view ────────────────────────────────────────────
// A dark rotating Earth with a glowing point + pulsing ring per intruder and an animated arc
// from each back to the hub. World-scale, so it never implies street-level precision.
function GlobeView({
  located,
  selected,
  onSelect,
}: {
  located: Intruder[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const globe = useRef<any>(null);

  useEffect(() => {
    if (!host.current || globe.current) return;
    const g = new Globe(host.current, { rendererConfig: { antialias: true, alpha: true } })
      .backgroundColor('rgba(0,0,0,0)')
      .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
      .showAtmosphere(true)
      .atmosphereColor('#7c82ff')
      .atmosphereAltitude(0.16)
      .pointLat('lat').pointLng('lng').pointColor('color').pointAltitude(0.01).pointRadius(0.35).pointLabel('label')
      .onPointClick((d: any) => onSelect(d.visitor))
      .ringLat('lat').ringLng('lng').ringColor((d: any) => () => d.color).ringMaxRadius(2.4).ringPropagationSpeed(1.3).ringRepeatPeriod(1300)
      .arcStartLat('slat').arcStartLng('slng').arcEndLat('elat').arcEndLng('elng')
      .arcColor('color').arcStroke(0.5).arcDashLength(0.45).arcDashGap(1.1).arcDashAnimateTime(1600).arcAltitudeAutoScale(0.45);
    g.pointOfView({ lat: 18, lng: 80, altitude: 2.3 });

    // Render at the screen's real pixel density (fixes the soft/blurry look on Retina/HiDPI)
    g.renderer().setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const controls = g.controls() as any;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.5;
    controls.enableZoom = true;
    controls.zoomSpeed = 1.1;
    // Stop zoom at a clean regional view (globe radius is 100). Getting closer only reveals the
    // texture's resolution limit and blows the markers up, and the data is only city-accurate anyway.
    controls.minDistance = 165;
    controls.maxDistance = 500;
    controls.enableDamping = true;

    // Sharpen the map texture at grazing angles once it has loaded
    setTimeout(() => {
      try {
        const mat: any = g.globeMaterial();
        const maxAniso = g.renderer().capabilities.getMaxAnisotropy?.() ?? 8;
        if (mat?.map) {
          mat.map.anisotropy = maxAniso;
          mat.map.needsUpdate = true;
        }
      } catch {
        /* texture not ready — harmless */
      }
    }, 1800);

    const resize = () => host.current && g.width(host.current.clientWidth).height(host.current.clientHeight);
    resize();
    addEventListener('resize', resize);
    globe.current = g;
    return () => {
      removeEventListener('resize', resize);
      (g as any)._destructor?.();
      globe.current = null;
      if (host.current) host.current.innerHTML = '';
    };
  }, []);

  // feed data
  useEffect(() => {
    const g = globe.current;
    if (!g) return;
    const pts = located.map((v) => ({
      lat: v.geo.lat!,
      lng: v.geo.lon!,
      color: SEV_COLOR[v.worst],
      visitor: v.visitor,
      label: `${v.device} · ${v.browser} — ${v.geo.label}`,
    }));
    const arcs = located.map((v) => ({
      slat: v.geo.lat!,
      slng: v.geo.lon!,
      elat: HUB.lat,
      elng: HUB.lng,
      color: [SEV_COLOR[v.worst], '#7c82ff'],
    }));
    g.pointsData(pts).ringsData(pts).arcsData(arcs);
  }, [located]);

  // spin to a selected intruder
  useEffect(() => {
    const g = globe.current;
    const v = located.find((x) => x.visitor === selected);
    if (g && v) {
      (g.controls() as any).autoRotate = false;
      g.pointOfView({ lat: v.geo.lat!, lng: v.geo.lon!, altitude: 1.6 }, 900);
    }
  }, [selected, located]);

  return <div ref={host} className="globe-host" />;
}

// Coloured pin, with a soft glow for the dangerous ones
function pin(sev: Intruder['worst']) {
  const c = SEV_COLOR[sev];
  const glow = sev === 'high' || sev === 'critical';
  return L.divIcon({
    className: 'threat-pin',
    html: `<span style="--c:${c}" class="${glow ? 'glow' : ''}"></span>`,
    iconSize: [18, 18],
    iconAnchor: [9, 9],
  });
}

// Honest uncertainty for an IP-based fix. An IP locates the ISP's network, not the device,
// so we never pretend to a pin — we draw the real radius. Mobile/cellular is coarser; a
// VPN/hosting IP is a datacenter, so the circle marks the server, not the person.
function accuracy(geo: Intruder['geo']): { radiusM: number; note: string } {
  if (geo.vpn) return { radiusM: 25000, note: 'VPN / hosting IP — this is the server, not the person' };
  if (geo.mobile) return { radiusM: 20000, note: 'Mobile network — city-level at best (±~20 km)' };
  return { radiusM: 5000, note: 'IP / ISP location — city-level (±~5 km), not the exact device' };
}

export function ThreatMap() {
  const mapEl = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const layer = useRef<L.LayerGroup | null>(null);
  const circles = useRef<Map<string, L.Circle>>(new Map());
  const [intruders, setIntruders] = useState<Intruder[]>([]);
  const [online, setOnline] = useState<boolean | undefined>(undefined);
  const [selected, setSelected] = useState<string | null>(null);
  const [fitted, setFitted] = useState(false);
  const [view, setView] = useState<'globe' | 'map'>('globe');

  // init map once — only while the 2D map view is mounted
  useEffect(() => {
    if (view !== 'map' || !mapEl.current || map.current) return;
    const m = L.map(mapEl.current, { worldCopyJump: true, zoomControl: true, attributionControl: false }).setView([22, 79], 4);
    // Keyless OpenStreetMap tiles, darkened via CSS filter (.leaflet-host) to match the theme — no API key, no watermark
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 19, subdomains: 'abc' }).addTo(m);
    layer.current = L.layerGroup().addTo(m);
    map.current = m;
    return () => {
      m.remove();
      map.current = null;
      setFitted(false); // re-fit next time the map view is opened
    };
  }, [view]);

  // poll the honeypot log
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const data = await fetchHoneypot();
      if (!alive) return;
      setOnline(!!data);
      if (data) setIntruders(groupIntruders(data.events as HoneypotEvent[]));
    };
    tick();
    const t = setInterval(tick, POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const located = useMemo(
    () => intruders.filter((v) => v.geo.lat !== undefined && v.geo.lon !== undefined),
    [intruders]
  );

  // redraw markers + honest accuracy circles
  useEffect(() => {
    if (!map.current || !layer.current) return;
    layer.current.clearLayers();
    circles.current.clear();
    let bounds: L.LatLngBounds | null = null;
    // slight spread so intruders sharing one city (or the same Wi-Fi) don't stack into one dot
    const seen = new Map<string, number>();
    for (const v of located) {
      const key = `${v.geo.lat},${v.geo.lon}`;
      const n = seen.get(key) || 0;
      seen.set(key, n + 1);
      const jitter = n === 0 ? 0 : 0.03 * n;
      const lat = v.geo.lat! + jitter;
      const lon = v.geo.lon! + jitter;
      const c = SEV_COLOR[v.worst];
      const { radiusM, note } = accuracy(v.geo);

      // The circle IS the location claim — everything inside is "somewhere in here", not the pin
      const circle = L.circle([lat, lon], {
        radius: radiusM,
        color: c,
        weight: 1,
        opacity: 0.55,
        fillColor: c,
        fillOpacity: 0.1,
        dashArray: v.geo.vpn ? '4 4' : undefined,
        interactive: false,
      }).addTo(layer.current!);
      circles.current.set(v.visitor, circle);
      // getBounds() returns a fresh object each call, so seeding/extending with it is safe
      bounds = bounds ? bounds.extend(circle.getBounds()) : circle.getBounds();

      L.marker([lat, lon], { icon: pin(v.worst) })
        .addTo(layer.current!)
        .on('click', () => setSelected(v.visitor))
        .bindTooltip(
          `<b>${v.device} · ${v.browser}</b><br>${v.ip}<br>${v.geo.label}` +
            `<br><span style="opacity:.7">${note}</span>` +
            (v.loggedIn ? '<br><b style="color:#ff5d6c">logged in to decoy</b>' : ''),
          { className: 'threat-tip', direction: 'top', offset: [0, -8] }
        );
    }
    if (bounds && !fitted) {
      map.current.fitBounds(bounds.pad(0.25), { maxZoom: 11 });
      setFitted(true);
    }
  }, [located, fitted, view]);

  // fly to a selected intruder — frame their accuracy circle, never zoom past it into false precision
  useEffect(() => {
    const circle = selected ? circles.current.get(selected) : undefined;
    if (circle && map.current) map.current.flyToBounds(circle.getBounds().pad(0.6), { duration: 0.6, maxZoom: 12 });
  }, [selected, located]);

  const loggedIn = intruders.filter((v) => v.loggedIn).length;

  return (
    <div className="map-page">
      <aside className="map-side">
        <header className="map-head">
          <div className="brand">
            <div className="brand-mark brand-mark--sm">
              <Crosshair size={15} />
            </div>
            <div>
              <div className="map-title">Threat map</div>
              <div className="brand-sub">Honeypot intruders</div>
            </div>
          </div>
          <span className={`status ${online === false ? 'status--off' : online ? 'status--on' : ''}`}>
            {online === false ? 'Backend offline' : online ? <><span className="dot" /> live</> : 'connecting…'}
          </span>
        </header>

        <div className="view-toggle" role="tablist">
          <button className={view === 'globe' ? 'is-active' : ''} onClick={() => setView('globe')} role="tab" aria-selected={view === 'globe'}>
            <Globe2 size={14} /> Globe
          </button>
          <button className={view === 'map' ? 'is-active' : ''} onClick={() => setView('map')} role="tab" aria-selected={view === 'map'}>
            <MapIcon size={14} /> Map
          </button>
        </div>

        <div className="map-stats">
          <div className="stat">
            <div className="stat-value">{intruders.length}</div>
            <div className="stat-label">intruders</div>
          </div>
          <div className="stat stat--warn">
            <div className="stat-value">{loggedIn}</div>
            <div className="stat-label">inside the trap</div>
          </div>
          <div className="stat stat--accent">
            <div className="stat-value">{located.length}</div>
            <div className="stat-label">on the map</div>
          </div>
        </div>

        <div className="map-list">
          {intruders.length === 0 ? (
            <div className="empty">
              No intruders yet. When a scammer opens the decoy login, they appear here.
            </div>
          ) : (
            intruders.map((v) => (
              <div key={v.visitor}>
                <IntruderCard v={v} selected={v.visitor === selected} onSelect={() => setSelected(v.visitor)} />
                {v.geo.lat === undefined && (
                  <div className="no-loc">
                    <ShieldAlert size={11} /> No map location (local address)
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        <p className="map-note">
          {view === 'globe' ? (
            <>
              Each point is an intruder; the arc runs to the HawkGuard node. Positions are <b>approximate</b> — from the
              visitor's IP, city/ISP-level (±~5 km) and coarser on mobile, not the exact device. Drag to spin, scroll to
              zoom, click a point to focus. Switch to <b>Map</b> for the exact uncertainty radius.
            </>
          ) : (
            <>
              The <b>circle is the location claim</b>, not the dot: the intruder is somewhere inside it. Fixes come from
              the visitor's IP — city/ISP-level (±~5 km), coarser on mobile, and a dashed circle means a VPN or hosting
              IP, so it marks the server, not the person. Precise (50–100 m) location would need the device's GPS with
              consent.
            </>
          )}
        </p>
      </aside>

      <div className="map-canvas">
        {view === 'globe' ? (
          <GlobeView located={located} selected={selected} onSelect={setSelected} />
        ) : (
          <div ref={mapEl} className="leaflet-host" />
        )}
        {online && located.length === 0 && intruders.length > 0 && (
          <div className="map-overlay">Intruders are on a local network — no public location to plot yet.</div>
        )}
      </div>
    </div>
  );
}
