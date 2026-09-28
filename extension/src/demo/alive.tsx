// The "alive" layer: motion and small reactions shared by every section of the landing page.
//
// Words      headings that enter word by word and hop letter by letter under the cursor
// WaveField  slow seamless waves (one SVG twice as wide as its box, sliding by half)
// Band       a section's own backdrop: texture, waves and a few reactive symbols
// LiveMascot the hawk changes pose and says something when you hover it
// useMagnet  buttons marked data-magnet lean toward a nearby cursor
//
// Everything is transform/opacity only, and stops under prefers-reduced-motion.

import { Fragment, useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import {
  Ban,
  Bot,
  BadgeCheck,
  Bug,
  CheckCheck,
  Coffee,
  Eye,
  EyeOff,
  FileCheck,
  FileText,
  Fish,
  Hourglass,
  KeyRound,
  Laugh,
  Link2,
  Link2Off,
  Lock,
  MessageSquareWarning,
  PartyPopper,
  Search,
  ShieldCheck,
  Siren,
  Smartphone,
  Sparkles,
  Target,
  Terminal,
  Trophy,
  type LucideIcon,
} from 'lucide-react';
import { Mascot, type MascotMood } from '../ui/components';

const reduced = () => typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;

// ─── Words ────────────────────────────────────────────────────
// `start` offsets the stagger so two Words in one heading enter as one sentence.
export function Words({ text, start = 0, className = '' }: { text: string; start?: number; className?: string }) {
  let i = start;
  const lines = text.split('\n');
  return (
    <span className={`words ${className}`}>
      <span className="sr-only">{text.replace(/\n/g, ' ')}</span>
      <span aria-hidden>
        {lines.map((line, li) => (
          <Fragment key={li}>
            {line
              .split(' ')
              .filter(Boolean)
              .map((word, wi) => (
                <Fragment key={wi}>
                  {wi > 0 && ' '}
                  <span className="w" style={{ '--i': i++ } as CSSProperties}>
                    {[...word].map((ch, ci) => (
                      <span key={ci} className="ch" style={{ '--c': ci } as CSSProperties}>
                        {ch}
                      </span>
                    ))}
                  </span>
                </Fragment>
              ))}
            {li < lines.length - 1 && <br />}
          </Fragment>
        ))}
      </span>
    </span>
  );
}

// ─── Waves ────────────────────────────────────────────────────
type Wave = { y: number; amp: number; period: number; color: string; dur: number; fill?: boolean; width?: number; reverse?: boolean; opacity?: number };
const W = 2400; // two copies of a 1200-wide tile
const H = 240;

// Sine-like path from quadratic segments; T mirrors the last control point.
function wavePath({ y, amp, period, fill }: Wave) {
  let d = `M 0 ${y} Q ${period / 4} ${y - amp} ${period / 2} ${y}`;
  for (let x = period; x <= W; x += period / 2) d += ` T ${x} ${y}`;
  return fill ? `${d} V ${H} H 0 Z` : d;
}

export function WaveField({ waves, className = '' }: { waves: Wave[]; className?: string }) {
  return (
    <div className={`wavefield ${className}`} aria-hidden>
      {waves.map((w, i) => (
        <svg
          key={i}
          className={`wave ${w.reverse ? 'wave--rev' : ''}`}
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          style={{ '--dur': `${w.dur}s`, '--bob': `${6 + i * 3}s`, opacity: w.opacity ?? 1 } as CSSProperties}
        >
          <path d={wavePath(w)} fill={w.fill ? w.color : 'none'} stroke={w.fill ? 'none' : w.color} strokeWidth={w.width ?? 1.5} vectorEffect="non-scaling-stroke" />
        </svg>
      ))}
    </div>
  );
}

export const HERO_WAVES: Wave[] = [
  { y: 120, amp: 26, period: 600, color: 'rgba(185, 166, 255, .22)', dur: 46 },
  { y: 140, amp: 34, period: 400, color: 'rgba(240, 139, 208, .18)', dur: 38, reverse: true },
  { y: 160, amp: 20, period: 300, color: 'rgba(90, 170, 255, .16)', dur: 30 },
  { y: 150, amp: 40, period: 1200, color: 'rgba(123, 92, 255, .14)', dur: 60, fill: true, reverse: true },
];

// The live demo stage: aurora ribbons rising from the bottom edge
export const DEMO_WAVES: Wave[] = [
  { y: 170, amp: 30, period: 1200, color: 'rgba(123, 92, 255, .16)', dur: 70, fill: true },
  { y: 185, amp: 24, period: 600, color: 'rgba(217, 68, 156, .12)', dur: 52, fill: true, reverse: true },
  { y: 160, amp: 22, period: 400, color: 'rgba(185, 166, 255, .22)', dur: 40 },
];

// ─── Band themes ──────────────────────────────────────────────
// Each chapter of the page: its own texture, waves and symbols, on the shared palette.
export type BandTheme = 'scan' | 'how' | 'safe' | 'trap' | 'numbers';

type Floaty = { icon: LucideIcon; alt: LucideIcon; say: string; x: string; y: string; side?: boolean; size?: number };

const BANDS: Record<BandTheme, { waves: Wave[]; floaties: Floaty[] }> = {
  scan: {
    waves: [
      { y: 150, amp: 30, period: 600, color: 'rgba(123, 92, 255, .10)', dur: 50, fill: true },
      { y: 170, amp: 22, period: 400, color: 'rgba(217, 68, 156, .08)', dur: 40, fill: true, reverse: true },
      { y: 130, amp: 26, period: 300, color: 'rgba(123, 92, 255, .35)', dur: 34 },
    ],
    floaties: [
      { icon: MessageSquareWarning, alt: ShieldCheck, say: 'Suspicious text? Paste it here.', x: '9%', y: '64px' },
      { icon: Link2, alt: Link2Off, say: "Don't click me. Seriously.", x: '84%', y: '40px' },
      { icon: Smartphone, alt: Laugh, say: '"Hi mom, new number." Nope.', x: '2.5%', y: '52%', side: true },
    ],
  },
  how: {
    waves: [
      { y: 60, amp: 18, period: 400, color: 'rgba(53, 191, 220, .35)', dur: 42 },
      { y: 80, amp: 28, period: 600, color: 'rgba(123, 92, 255, .28)', dur: 56, reverse: true },
      { y: 100, amp: 14, period: 300, color: 'rgba(217, 68, 156, .2)', dur: 36 },
    ],
    floaties: [
      { icon: Search, alt: Eye, say: 'Every signal gets a second look.', x: '88%', y: '70px' },
      { icon: FileText, alt: FileCheck, say: 'Evidence, filed.', x: '95%', y: '46%', side: true },
      { icon: Hourglass, alt: Coffee, say: 'Scammer on hold. Minute 14…', x: '2.5%', y: '66%', side: true },
    ],
  },
  safe: {
    waves: [
      { y: 150, amp: 30, period: 600, color: 'rgba(53, 191, 220, .30)', dur: 44 },
      { y: 170, amp: 22, period: 400, color: 'rgba(123, 92, 255, .30)', dur: 36, reverse: true },
      { y: 175, amp: 36, period: 1200, color: 'rgba(123, 92, 255, .12)', dur: 64, fill: true },
    ],
    floaties: [
      { icon: Lock, alt: Laugh, say: 'Nice try.', x: '86%', y: '56px' },
      { icon: Terminal, alt: Ban, say: 'IGNORE ALL PREVIOUS… no.', x: '2.5%', y: '40%', side: true },
      { icon: Bot, alt: ShieldCheck, say: 'I only ever read our templates.', x: '95%', y: '62%', side: true },
    ],
  },
  trap: {
    waves: [
      { y: 150, amp: 28, period: 600, color: 'rgba(255, 122, 69, .12)', dur: 48, fill: true, reverse: true },
      { y: 170, amp: 20, period: 400, color: 'rgba(217, 68, 156, .09)', dur: 38, fill: true },
      { y: 130, amp: 24, period: 300, color: 'rgba(255, 122, 69, .4)', dur: 32 },
    ],
    floaties: [
      { icon: Fish, alt: Siren, say: 'Hooked one.', x: '10%', y: '60px' },
      { icon: KeyRound, alt: Laugh, say: 'Totally real password. Promise.', x: '84%', y: '44px' },
      { icon: Eye, alt: EyeOff, say: "We see you. They don't see us.", x: '95%', y: '58%', side: true },
      { icon: Bug, alt: CheckCheck, say: 'Caught a bug. It was a scammer.', x: '2.5%', y: '48%', side: true },
    ],
  },
  numbers: {
    waves: [
      { y: 80, amp: 22, period: 600, color: 'rgba(123, 92, 255, .28)', dur: 50 },
      { y: 100, amp: 16, period: 400, color: 'rgba(255, 122, 69, .3)', dur: 40, reverse: true },
    ],
    floaties: [
      { icon: Trophy, alt: PartyPopper, say: '15 for 15.', x: '86%', y: '62px' },
      { icon: Target, alt: BadgeCheck, say: 'Zero false alarms. We checked.', x: '8%', y: '48px' },
      { icon: Sparkles, alt: Sparkles, say: 'Rerun it yourself: it is in the repo.', x: '2.5%', y: '40%', side: true },
    ],
  },
};

// Symbols drift away from an approaching cursor, then wiggle, swap and speak when touched.
export function Band({ theme, children }: { theme: BandTheme; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const { waves, floaties } = BANDS[theme];

  const onMove = (e: React.PointerEvent) => {
    if (reduced() || e.pointerType === 'touch') return;
    ref.current?.querySelectorAll<HTMLElement>('.floaty').forEach((el) => {
      const r = el.getBoundingClientRect();
      const dx = r.left + r.width / 2 - e.clientX;
      const dy = r.top + r.height / 2 - e.clientY;
      const dist = Math.hypot(dx, dy);
      // Shy at a distance, but let the cursor reach it (inside 44px it holds still to be hovered)
      const push = dist > 44 && dist < 190 ? (1 - dist / 190) * 22 : 0;
      el.style.setProperty('--fx', `${(dx / (dist || 1)) * push}px`);
      el.style.setProperty('--fy', `${(dy / (dist || 1)) * push}px`);
    });
  };
  const onLeave = () =>
    ref.current?.querySelectorAll<HTMLElement>('.floaty').forEach((el) => {
      el.style.setProperty('--fx', '0px');
      el.style.setProperty('--fy', '0px');
    });

  return (
    <div className={`band band--${theme}`} ref={ref} onPointerMove={onMove} onPointerLeave={onLeave}>
      <div className="band-bg" aria-hidden>
        <div className="band-texture" />
        <WaveField waves={waves} className="band-waves" />
      </div>
      {floaties.map((f, i) => (
        <FloatyIcon key={i} f={f} i={i} />
      ))}
      {children}
    </div>
  );
}

function FloatyIcon({ f, i }: { f: Floaty; i: number }) {
  const [on, setOn] = useState(false);
  const size = f.size ?? 20;
  return (
    <span
      className={`floaty ${f.side ? 'floaty--side' : ''} ${parseFloat(f.x) > 50 ? 'floaty--right' : ''} ${on ? 'is-on' : ''}`}
      style={{ left: f.x, top: f.y, '--bob': `${5 + i * 1.3}s`, '--delay': `${-i * 1.7}s` } as CSSProperties}
      onPointerEnter={() => setOn(true)}
      onPointerLeave={() => setOn(false)}
      onClick={() => setOn((v) => !v)}
      aria-hidden
    >
      <span className="floaty-bob">
        <span className="floaty-face">
          <f.icon size={size} className="floaty-a" />
          <f.alt size={size} className="floaty-b" />
        </span>
      </span>
      <span className="floaty-say">{f.say}</span>
    </span>
  );
}

// ─── Mascot with a personality ────────────────────────────────
export function LiveMascot({ mood, hoverMood, lines, size, className = '' }: { mood: MascotMood; hoverMood: MascotMood; lines: string[]; size: number; className?: string }) {
  const [hover, setHover] = useState(false);
  const [n, setN] = useState(0);
  const enter = () => {
    setN((x) => x + 1);
    setHover(true);
  };
  return (
    <span className={`live-mascot ${hover ? 'is-hover' : ''} ${className}`} onPointerEnter={enter} onPointerLeave={() => setHover(false)} onClick={() => (hover ? setHover(false) : enter())}>
      <Mascot mood={hover ? hoverMood : mood} size={size} />
      <span className="mascot-bubble" aria-hidden>
        {lines[n % lines.length]}
      </span>
    </span>
  );
}

// ─── Magnetic buttons ─────────────────────────────────────────
export function useMagnet() {
  useEffect(() => {
    if (reduced()) return;
    let raf = 0;
    const onMove = (e: PointerEvent) => {
      if (e.pointerType === 'touch') return;
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        document.querySelectorAll<HTMLElement>('[data-magnet]').forEach((el) => {
          const r = el.getBoundingClientRect();
          const dx = e.clientX - (r.left + r.width / 2);
          const dy = e.clientY - (r.top + r.height / 2);
          const reach = Math.max(r.width, r.height) / 2 + 60;
          const near = Math.hypot(dx, dy) < reach;
          el.style.setProperty('--mgx', near ? `${dx * 0.22}px` : '0px');
          el.style.setProperty('--mgy', near ? `${dy * 0.3}px` : '0px');
        });
      });
    };
    addEventListener('pointermove', onMove, { passive: true });
    return () => {
      cancelAnimationFrame(raf);
      removeEventListener('pointermove', onMove);
    };
  }, []);
}
