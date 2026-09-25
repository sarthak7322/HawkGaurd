// Shared UI for the side panel, popup and live demo (styles in ./modern.css)

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { AlertTriangle, Crosshair, Volume2, VolumeX, Cpu, FileText, Lock, Send, ShieldAlert, Sparkles } from 'lucide-react';
import type { Persona, ScamScenario, Severity } from '../shared/types';
import { aiPayload, type Health, type Provider } from './ai';
import { playScreech } from './sound';
import hawkIcon from '../assets/hawk-icon.png';
import waveImg from '../assets/mascot/wave.png';
import squintImg from '../assets/mascot/squint.png';
import celebrateImg from '../assets/mascot/celebrate.png';
import facepalmImg from '../assets/mascot/facepalm.png';

export type MascotMood = 'wave' | 'squint' | 'celebrate' | 'facepalm';

const MASCOT: Record<MascotMood, string> = {
  wave: waveImg,
  squint: squintImg,
  celebrate: celebrateImg,
  facepalm: facepalmImg,
};

// Safe → wave, scam caught → celebrate, anything in between → suspicious squint
export const moodFor = (severity: Severity): MascotMood =>
  severity === 'safe' ? 'wave' : severity === 'threat' ? 'celebrate' : 'squint';

export function Mascot({ mood, size = 72, className = '' }: { mood: MascotMood; size?: number; className?: string }) {
  return <img src={MASCOT[mood]} width={size} height={size} alt="" className={`mascot mascot--${mood} ${className}`} />;
}

// Mute switch for the hawk screech. Turning it on plays the sound once so you know what you get.
export function SoundToggle({ on, onChange }: { on: boolean; onChange: (on: boolean) => void }) {
  return (
    <button
      className={`sound-toggle ${on ? 'is-on' : ''}`}
      onClick={() => {
        if (!on) playScreech();
        onChange(!on);
      }}
      aria-pressed={on}
      title={on ? 'Hawk screech on scam: on' : 'Hawk screech on scam: off'}
    >
      {on ? <Volume2 size={15} /> : <VolumeX size={15} />}
    </button>
  );
}

export function BrandMark({ small }: { small?: boolean }) {
  return <img src={hawkIcon} alt="HawkGuard" className={`brand-mark brand-mark--img ${small ? 'brand-mark--sm' : ''}`} />;
}

// Numbers glide to their new value instead of jumping (respects reduced-motion)
export function useCountUp(target: number, ms = 800): number {
  const [shown, setShown] = useState(target);
  const from = useRef(target);
  useEffect(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) return setShown(target);
    const start = performance.now();
    const origin = from.current;
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / ms);
      const v = Math.round(origin + (target - origin) * (1 - Math.pow(1 - t, 3)));
      from.current = v;
      setShown(v);
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return shown;
}

// Animates the first number inside a label like "~12m"
export function CountUp({ value }: { value: string | number }) {
  const text = String(value);
  const m = /-?\d+/.exec(text);
  const n = useCountUp(m ? Number(m[0]) : 0);
  return <>{m ? text.slice(0, m.index) + n + text.slice(m.index + m[0].length) : text}</>;
}

export const scenarioLabel = (s: ScamScenario) => s.replace(/_/g, ' ');
export const initials = (name: string) => name.split(' ').map((w) => w[0]).join('').slice(0, 2);

export const SEVERITY_TEXT: Record<Severity, string> = {
  threat: 'Threat',
  caution: 'Caution',
  unknown: 'Suspicious',
  safe: 'Looks safe',
};

// UI-only flag. Spotting injection is NOT what makes HawkGuard safe — the LLM never sees
// scammer text at all. This just makes the attempt visible.
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+|any\s+)?(previous|prior|above|your)\s+(instructions|prompts?|rules)/i,
  /system\s+prompt/i,
  /you\s+are\s+now\s+/i,
  /^\s*system\s*:/i,
  /(developer|dan|jailbreak)\s+mode/i,
  /disregard\s+(the|your|all)/i,
];

// The bank-account pattern (9–18 digits) also matches bare phone numbers — drop those
export function accountsOnly(accounts: string[], phones: string[]): string[] {
  const phoneDigits = phones.map((p) => p.replace(/\D/g, '').slice(-10));
  return accounts.filter((a) => !phoneDigits.some((p) => a.endsWith(p) || p.endsWith(a)));
}

export function looksLikeInjection(text: string): boolean {
  return INJECTION_PATTERNS.some((p) => p.test(text));
}

export function StatusPill({ health }: { health: Health | null | undefined }) {
  if (health === undefined) return <span className="status">Connecting…</span>;
  if (!health) return <span className="status status--off">Backend offline · templates only</span>;
  if (!health.provider) return <span className="status status--warn">No AI key · templates only</span>;
  return (
    <span className="status status--on">
      <span className="dot" /> AI voice · {health.provider === 'gemini' ? 'Gemini' : 'Claude'}
    </span>
  );
}

export function Gauge({ score, severity, size = 128 }: { score: number; severity: Severity; size?: number }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const shown = useCountUp(score, 900);
  return (
    <div className={`gauge gauge--${severity}`} style={{ width: size, height: size }}>
      <svg viewBox="0 0 128 128" width={size} height={size} aria-hidden>
        <circle cx="64" cy="64" r={r} className="gauge-track" />
        <circle
          cx="64"
          cy="64"
          r={r}
          className="gauge-fill"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - score / 100)}
          transform="rotate(-90 64 64)"
        />
      </svg>
      <div className="gauge-center">
        <div className="gauge-score" style={{ fontSize: size * 0.27 }}>
          {shown}
        </div>
        {size >= 100 && <div className="gauge-label">risk score</div>}
      </div>
    </div>
  );
}

export function Stat({ value, label, accent, warn }: { value: string | number; label: string; accent?: boolean; warn?: boolean }) {
  return (
    <div className={`stat ${accent ? 'stat--accent' : ''} ${warn ? 'stat--warn' : ''}`}>
      <div className="stat-value">
        <CountUp value={value} />
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

export function IntelGroup({ icon, title, items }: { icon: ReactNode; title: string; items: string[] }) {
  return (
    <div className="intel-group">
      <div className="intel-title">
        {icon} {title}
        <span className="intel-count">{items.length}</span>
      </div>
      <div className="chips">
        {items.length ? (
          items.map((v) => (
            <span key={v} className="chip">
              {v}
            </span>
          ))
        ) : (
          <span className="chip chip--empty">none yet</span>
        )}
      </div>
    </div>
  );
}

export interface PipelineTrace {
  incoming: string;
  scenario: ScamScenario;
  template: string;
  reply: string;
  turn: number;
  persona: Persona;
  rewritten: boolean;
  lure?: boolean; // honeypot lure: fixed text, no AI
}

export function Pipeline({ trace, provider }: { trace: PipelineTrace; provider: Provider }) {
  const aiName = provider === 'gemini' ? 'Gemini' : provider === 'claude' ? 'Claude' : null;
  const injection = looksLikeInjection(trace.incoming);
  return (
    <ol className="pipeline">
      <li className="step">
        <div className="step-icon step-icon--threat">
          <AlertTriangle size={14} />
        </div>
        <div className="step-body">
          <div className="step-title">
            Scammer's message
            <span className="lock">
              <Lock size={11} /> never sent to the AI
            </span>
          </div>
          <blockquote className="quote">{trace.incoming}</blockquote>
          {injection && (
            <div className="callout">
              <ShieldAlert size={14} />
              Prompt-injection attempt. It goes nowhere: the AI never sees this text, so there is nothing to hijack.
            </div>
          )}
        </div>
      </li>
      {trace.lure ? (
        <li className="step">
          <div className="step-icon step-icon--threat">
            <Crosshair size={14} />
          </div>
          <div className="step-body">
            <div className="step-title">Honeypot lure — no AI involved</div>
            <div className="step-text">
              A fixed message hands the scammer a login to a fake shop website. The link and password must arrive intact,
              so this reply is never rewritten by the AI. Anyone who uses it is fingerprinted.
            </div>
          </div>
        </li>
      ) : (
        <>
      <li className="step">
        <div className="step-icon">
          <Cpu size={14} />
        </div>
        <div className="step-body">
          <div className="step-title">Rule-based classifier</div>
          <div className="step-text">
            Mapped to one of 8 fixed categories → <span className="pill">{scenarioLabel(trace.scenario)}</span>
          </div>
        </div>
      </li>
      <li className="step">
        <div className="step-icon">
          <FileText size={14} />
        </div>
        <div className="step-body">
          <div className="step-title">Pre-written safe template</div>
          <div className="step-text step-text--mono">{trace.template}</div>
        </div>
      </li>
      <li className="step">
        <div className="step-icon step-icon--ai">
          <Sparkles size={14} />
        </div>
        <div className="step-body">
          <div className="step-title">{aiName ? `${aiName} rewrites the voice only` : 'AI voice rewrite'}</div>
          <div className="step-text">
            {trace.rewritten
              ? `Sees only ${trace.persona.displayName}'s profile, the template and turn ${trace.turn}.`
              : 'AI busy or unavailable, so the safe template is sent as written.'}
          </div>
          <details className="payload">
            <summary>Exactly what the AI received</summary>
            <pre>{JSON.stringify(aiPayload(trace.persona, trace.template, trace.turn), null, 2)}</pre>
          </details>
        </div>
      </li>
        </>
      )}
      <li className="step">
        <div className="step-icon step-icon--safe">
          <Send size={13} />
        </div>
        <div className="step-body">
          <div className="step-title">Reply sent as {trace.persona.displayName}</div>
          <div className="step-text step-text--reply">{trace.reply}</div>
        </div>
      </li>
    </ol>
  );
}
