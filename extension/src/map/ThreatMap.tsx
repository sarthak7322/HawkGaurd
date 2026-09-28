// Threat map: plots every honeypot intruder on a Mapbox map with real place labels. One map
// morphs between a 3D globe and a flat 2D map (projection swap), both fully labelled. Each
// intruder gets a coloured dot, its city name, and an honest accuracy circle (IP geolocation is
// city-level, so we draw the radius rather than pretend to a pin).

import { useEffect, useMemo, useRef, useState } from 'react';
import mapboxgl from 'mapbox-gl';
import 'mapbox-gl/dist/mapbox-gl.css';
import { Crosshair, Globe2, Map as MapIcon, ShieldAlert } from 'lucide-react';
import { fetchHoneypot } from '../ui/ai';
import { IntruderCard } from '../ui/honeypot';
import { groupIntruders, type HoneypotEvent, type Intruder } from '../shared/honeypot';

const POLL_MS = 2500;
const TOKEN = import.meta.env.VITE_MAPBOX_TOKEN as string | undefined;

const SEV_COLOR: Record<Intruder['worst'], string> = {
  info: '#7d8497',
  medium: '#ffb547',
  high: '#ff5d6c',
  critical: '#ff5d6c',
};

// Honest uncertainty for an IP-based fix. An IP locates the ISP's network, not the device.
function accuracy(geo: Intruder['geo']): { radiusM: number; note: string } {
  if (geo.precise) return { radiusM: Math.max(geo.accuracyM || 40, 25), note: 'Precise — consented GPS on this device' };
  if (geo.vpn) return { radiusM: 25000, note: 'VPN / hosting IP — server, not the person' };
  if (geo.mobile) return { radiusM: 20000, note: 'Mobile network — city-level at best (±~20 km)' };
  return { radiusM: 5000, note: 'IP / ISP location — city-level (±~5 km)' };
}

// A geo-accurate circle polygon (metres → lon/lat ring) so the accuracy radius is truthful on the map
function circleRing(lng: number, lat: number, radiusM: number, steps = 64): number[][] {
  const dLat = radiusM / 110574;
  const dLng = radiusM / (111320 * Math.cos((lat * Math.PI) / 180));
  const ring: number[][] = [];
  for (let i = 0; i <= steps; i++) {
    const t = (i / steps) * 2 * Math.PI;
    ring.push([lng + dLng * Math.cos(t), lat + dLat * Math.sin(t)]);
  }
  return ring;
}

const shortPlace = (label: string) => (label.split('·').pop() || label).split(',')[0].trim();

export function ThreatMap() {
  const mapEl = useRef<HTMLDivElement>(null);
  const map = useRef<mapboxgl.Map | null>(null);
  const ready = useRef(false);
  const centered = useRef(false);
  const [intruders, setIntruders] = useState<Intruder[]>([]);
  const [online, setOnline] = useState<boolean | undefined>(undefined);
  const [selected, setSelected] = useState<string | null>(null);
  const [view, setView] = useState<'globe' | 'map'>('globe');

  const located = useMemo(
    () => intruders.filter((v) => v.geo.lat !== undefined && v.geo.lon !== undefined),
    [intruders]
  );

  // Build GeoJSON for the intruder dots/labels and the accuracy circles
  const featureData = useMemo(() => {
    const points: any[] = [];
    const rings: any[] = [];
    for (const v of located) {
      const lng = v.geo.lon!;
      const lat = v.geo.lat!;
      const color = SEV_COLOR[v.worst];
      const { radiusM } = accuracy(v.geo);
      const props = { visitor: v.visitor, color, place: shortPlace(v.geo.label) };
      points.push({ type: 'Feature', properties: props, geometry: { type: 'Point', coordinates: [lng, lat] } });
      rings.push({
        type: 'Feature',
        properties: { color },
        geometry: { type: 'Polygon', coordinates: [circleRing(lng, lat, radiusM)] },
      });
    }
    return {
      points: { type: 'FeatureCollection', features: points } as any,
      rings: { type: 'FeatureCollection', features: rings } as any,
    };
  }, [located]);

  // ── init the map once ──
  useEffect(() => {
    if (!mapEl.current || map.current || !TOKEN) return;
    mapboxgl.accessToken = TOKEN;
    const m = new mapboxgl.Map({
      container: mapEl.current,
      style: 'mapbox://styles/mapbox/dark-v11', // dark basemap, place labels built in
      projection: 'globe',
      center: [78, 20],
      zoom: 1.4,
      maxZoom: 18, // Mapbox has real street tiles; the accuracy circle shows the city-level uncertainty
      attributionControl: false,
    });
    m.addControl(new mapboxgl.NavigationControl({ showCompass: false }), 'top-right');
    m.on('style.load', () => {
      m.setFog({
        color: 'rgb(12,14,22)',
        'high-color': 'rgb(60,50,120)',
        'horizon-blend': 0.15,
        'space-color': 'rgb(6,7,12)',
        'star-intensity': 0.5,
      });
    });
    m.on('load', () => {
      m.addSource('rings', { type: 'geojson', data: { type: 'FeatureCollection', features: [] } });
      m.addSource('intruders', { type: 'geojson', data: { type: 'FeatureCollection', features: [] } });
      // accuracy circle — outline only (a fill would cover the map when zoomed inside the radius)
      m.addLayer({ id: 'ring-line', type: 'line', source: 'rings', paint: { 'line-color': ['get', 'color'], 'line-width': 1.5, 'line-opacity': 0.75, 'line-dasharray': [3, 2] } });
      // glow + dot
      m.addLayer({ id: 'dot-glow', type: 'circle', source: 'intruders', paint: { 'circle-radius': 16, 'circle-color': ['get', 'color'], 'circle-opacity': 0.18, 'circle-blur': 1 } });
      m.addLayer({ id: 'dot', type: 'circle', source: 'intruders', paint: { 'circle-radius': 6, 'circle-color': ['get', 'color'], 'circle-stroke-color': '#fff', 'circle-stroke-width': 1.5 } });
      // city label
      m.addLayer({
        id: 'label',
        type: 'symbol',
        source: 'intruders',
        layout: { 'text-field': ['get', 'place'], 'text-size': 13, 'text-offset': [0, -1.4], 'text-anchor': 'bottom', 'text-font': ['DIN Pro Medium', 'Arial Unicode MS Regular'] },
        paint: { 'text-color': '#e9edff', 'text-halo-color': 'rgba(8,9,12,0.9)', 'text-halo-width': 1.4 },
      });
      const pick = (e: mapboxgl.MapMouseEvent) => {
        const f: any = m.queryRenderedFeatures(e.point, { layers: ['dot'] })[0];
        if (f) setSelected(f.properties!.visitor);
      };
      m.on('click', 'dot', pick);
      m.on('mouseenter', 'dot', () => (m.getCanvas().style.cursor = 'pointer'));
      m.on('mouseleave', 'dot', () => (m.getCanvas().style.cursor = ''));
      ready.current = true;
      map.current = m;
      // push any data that arrived before load
      (m.getSource('intruders') as mapboxgl.GeoJSONSource)?.setData(featureData.points);
      (m.getSource('rings') as mapboxgl.GeoJSONSource)?.setData(featureData.rings);
    });
    map.current = m;
    return () => {
      m.remove();
      map.current = null;
      ready.current = false;
    };
  }, []);

  // ── feed data ──
  useEffect(() => {
    const m = map.current;
    if (!m || !ready.current) return;
    (m.getSource('intruders') as mapboxgl.GeoJSONSource)?.setData(featureData.points);
    (m.getSource('rings') as mapboxgl.GeoJSONSource)?.setData(featureData.rings);
    if (!centered.current && located.length) {
      centered.current = true;
      const lng = located.reduce((s, v) => s + v.geo.lon!, 0) / located.length;
      const lat = located.reduce((s, v) => s + v.geo.lat!, 0) / located.length;
      m.flyTo({ center: [lng, lat], zoom: 2.2, duration: 1400 });
    }
  }, [featureData, located]);

  // ── morph globe ⇄ flat map (native projection swap, instant) ──
  useEffect(() => {
    const m = map.current;
    if (!m || !ready.current) return;
    m.setProjection(view === 'globe' ? 'globe' : 'mercator');
  }, [view]);

  // ── fly to a selected intruder ──
  useEffect(() => {
    const m = map.current;
    const v = located.find((x) => x.visitor === selected);
    if (m && ready.current && v) m.flyTo({ center: [v.geo.lon!, v.geo.lat!], zoom: 5, duration: 900 });
  }, [selected, located]);

  const loggedIn = intruders.filter((v) => v.loggedIn).length;

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
            <div className="empty">No intruders yet. When a scammer opens the decoy login, they appear here.</div>
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
          The <b>circle is the location claim</b>, not the dot: the intruder is somewhere inside it. Fixes come from the
          visitor's IP — city/ISP-level (±~5 km), coarser on mobile. A tight circle means the visitor allowed the browser's
          GPS prompt, giving a precise (tens of metres) fix. Toggle <b>Globe</b> / <b>Map</b> to morph the same view.
        </p>
      </aside>

      <div className="map-canvas">
        {TOKEN ? (
          <div ref={mapEl} className="mapbox-host" />
        ) : (
          <div className="map-overlay">Set VITE_MAPBOX_TOKEN in extension/.env to load the map.</div>
        )}
        {online && located.length === 0 && intruders.length > 0 && (
          <div className="map-overlay">Intruders are on a local network — no public location to plot yet.</div>
        )}
      </div>
    </div>
  );
}
