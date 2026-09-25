// Landing sections above the live demo, in a Linear-inspired style: near-black, hairline
// borders, white→grey headlines, one indigo accent, a tilted product shot and calm fade-ups.
// Motion is CSS-driven; this file only adds what CSS can't do alone (scroll reveal, scroll
// progress, hero tilt, cursor spotlight).

import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  ArrowRight,
  Bot,
  ChevronRight,
  FileText,
  Fingerprint,
  KeyRound,
  Lock,
  MessagesSquare,
  ScanSearch,
  ShieldCheck,
  UserRound,
} from 'lucide-react';
import { BrandMark, Mascot, useCountUp } from '../ui/components';
import heroShot from '../assets/hero-shot.jpg';

// ─── Page-wide behaviours ─────────────────────────────────────
function useScrollEffects() {
  useEffect(() => {
    const root = document.documentElement;

    // Reveal anything marked data-reveal once it scrolls into view
    const io = new IntersectionObserver(
      (entries) =>
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add('is-in');
            io.unobserve(e.target);
          }
        }),
      { threshold: 0.15, rootMargin: '0px 0px -6% 0px' }
    );
    const watch = () => document.querySelectorAll('[data-reveal]:not(.is-in)').forEach((el) => io.observe(el));
    watch();
    const mo = new MutationObserver(watch);
    mo.observe(document.body, { childList: true, subtree: true });

    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const max = root.scrollHeight - innerHeight;
        root.style.setProperty('--scroll', String(max > 0 ? scrollY / max : 0));
        // Hero product shot straightens over the first ~half screen of scrolling
        root.style.setProperty('--hero', Math.min(1, scrollY / (innerHeight * 0.55)).toFixed(3));
        root.classList.toggle('is-scrolled', scrollY > 12);
      });
    };
    onScroll();
    addEventListener('scroll', onScroll, { passive: true });
    addEventListener('resize', onScroll);

    // Cursor spotlight: cards light up faintly under the pointer
    const onMove = (e: PointerEvent) => {
      const el = (e.target as HTMLElement).closest?.<HTMLElement>('.card, .stat, .spot');
      if (!el) return;
      const r = el.getBoundingClientRect();
      el.style.setProperty('--mx', `${e.clientX - r.left}px`);
      el.style.setProperty('--my', `${e.clientY - r.top}px`);
    };
    addEventListener('pointermove', onMove, { passive: true });

    return () => {
      io.disconnect();
      mo.disconnect();
      removeEventListener('scroll', onScroll);
      removeEventListener('resize', onScroll);
      removeEventListener('pointermove', onMove);
    };
  }, []);
}

// ─── Nav ──────────────────────────────────────────────────────
function Nav() {
  return (
    <nav className="nav">
      <div className="nav-inner">
        <a href="#top" className="brand">
          <BrandMark small />
          <span className="nav-name">HawkGuard</span>
        </a>
        <div className="nav-links">
          <a href="#how">Method</a>
          <a href="#safe">Safety</a>
          <a href="#trap">Honeypot</a>
          <a href="#numbers">Results</a>
        </div>
        <a href="#demo" className="btn btn-primary nav-cta">
          Live demo
        </a>
      </div>
    </nav>
  );
}

// ─── Hero ─────────────────────────────────────────────────────
function Hero() {
  return (
    <header className="hero" id="top">
      <div className="hero-copy">
        <a href="#safe" className="announce">
          <span className="announce-tag">New</span>
          Injection-proof engagement
          <ChevronRight size={14} />
        </a>
        <h1 className="hero-title">
          <span className="line">Scammers waste your time.</span>
          <span className="line">Now you waste theirs.</span>
        </h1>
        <p className="hero-sub">
          HawkGuard flags the scam in your browser, engages it as a harmless decoy — the attacker's words never
          reach the AI — and turns the exchange into evidence you can file.
        </p>
        <div className="hero-ctas">
          <a href="#demo" className="btn btn-primary btn-lg">
            Watch it catch a scammer
          </a>
          <a href="#how" className="text-link">
            How it works <ArrowRight size={14} />
          </a>
        </div>
      </div>

      <div className="shot-wrap" aria-hidden>
        <div className="shot-glow" />
        <div className="shot">
          <img src={heroShot} alt="" />
        </div>
      </div>
    </header>
  );
}

// ─── Scam types (muted, like a logo row) ──────────────────────
const SCAMS = ['Bank KYC fraud', 'Digital arrest', 'Courier scam', 'Lottery prize', 'Fake job offer', 'AnyDesk access', 'Crypto "investment"', 'Power cut threat', '"Hi mom, new number"', 'Refund link'];

function Marquee() {
  return (
    <section className="logos" data-reveal>
      <p>Recognises the playbooks behind India's most common scams</p>
      <div className="marquee">
        <div className="marquee-track">
          {[...SCAMS, ...SCAMS].map((s, i) => (
            <span key={i} className="marquee-item" aria-hidden={i >= SCAMS.length}>
              {s}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── Section header (label, big heading, supporting copy) ─────
function Intro({ label, title, children, wide }: { label: string; title: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <div className={`intro ${wide ? 'intro--wide' : ''}`} data-reveal>
      <div className="intro-label">
        <span className="intro-dot" /> {label}
      </div>
      <h2 className="intro-title">{title}</h2>
      <p className="intro-copy">{children}</p>
    </div>
  );
}

// ─── Method ───────────────────────────────────────────────────
const STAGES = [
  { icon: ScanSearch, title: 'Detect', text: 'Scam playbooks, lookalike and brand-new domains, redirect chains.' },
  { icon: FileText, title: 'Investigate', text: 'Every signal becomes evidence with a severity, not a black box.' },
  { icon: UserRound, title: 'Decide', text: 'Block it, or engage. Every reply waits for your approval.' },
  { icon: MessagesSquare, title: 'Engage', text: 'A decoy persona stalls them and collects UPI IDs, numbers, links.' },
  { icon: ShieldCheck, title: 'Report', text: 'A case file ready for cybercrime.gov.in and helpline 1930.' },
];

function How() {
  return (
    <section className="block" id="how">
      <Intro label="Method" title={<>A case file, built<br />while they talk</>}>
        Five stages in one side panel. From the first suspicious message to a report the police can act on.
      </Intro>
      <div className="grid5">
        {STAGES.map((s, i) => (
          <article key={s.title} className="cell spot" data-reveal style={{ '--d': `${i * 70}ms` } as React.CSSProperties}>
            <div className="cell-top">
              <s.icon size={17} />
              <span className="cell-num">{String(i + 1).padStart(2, '0')}</span>
            </div>
            <h3>{s.title}</h3>
            <p>{s.text}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

// ─── Safety: the pipeline ─────────────────────────────────────
function Safe() {
  const nodes = [
    { icon: MessagesSquare, label: "Scammer's message", note: 'Never sent to the AI', tone: 'threat' },
    { icon: ScanSearch, label: 'Classifier', note: 'Rules, 8 fixed categories' },
    { icon: FileText, label: 'Template', note: 'Pre-written, safe' },
    { icon: Bot, label: 'AI voice', note: 'Sees the template only', tone: 'ai' },
    { icon: ShieldCheck, label: 'Your approval', note: 'Nothing real shared', tone: 'safe' },
  ];
  return (
    <section className="block" id="safe">
      <Intro
        wide
        label="Safety"
        title={
          <>
            <span className="strike">"Ignore your instructions"</span>
            <br />
            goes nowhere
          </>
        }
      >
        Prompt injection needs the attacker's words to reach the model. In HawkGuard they never do: the AI only
        rewrites a template we wrote.
      </Intro>
      <div className="flow card" data-reveal>
        <div className="flow-rail" aria-hidden>
          <i />
          <i />
          <i />
        </div>
        <div className="flow-wall" aria-hidden>
          <Lock size={11} /> Boundary
        </div>
        {nodes.map((n, i) => (
          <div key={n.label} className={`flow-node flow-node--${n.tone || 'plain'}`} style={{ '--d': `${i * 110}ms` } as React.CSSProperties}>
            <div className="flow-icon">
              <n.icon size={16} />
            </div>
            <strong>{n.label}</strong>
            <span>{n.note}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

// ─── Honeypot ─────────────────────────────────────────────────
function Trap() {
  const beats = [
    { mood: 'squint' as const, icon: KeyRound, title: 'Nothing real to lose', text: 'The decoy shares a login to a sandbox — no real customers, money or data sit behind it, so no one can be harmed.' },
    { mood: 'celebrate' as const, icon: Lock, title: 'On the record', text: 'Every page view, password tried and export attempt is captured with a timestamp.' },
    { mood: 'facepalm' as const, icon: Fingerprint, title: 'Attributable', text: 'IP, device, browser, rough location and VPN use — an intruder profile ready for a report.' },
  ];
  return (
    <section className="block" id="trap">
      <Intro label="Honeypot" title="Engagement becomes evidence">
        If you choose to engage, the exchange is recorded, and nothing behind the decoy is real — evidence, not vigilantism.
      </Intro>
      <div className="grid3">
        {beats.map((b, i) => (
          <article key={b.title} className="trap-card card" data-reveal style={{ '--d': `${i * 90}ms` } as React.CSSProperties}>
            <div className="trap-art">
              <Mascot mood={b.mood} size={132} />
            </div>
            <div className="trap-body">
              <h3>
                <b.icon size={15} /> {b.title}
              </h3>
              <p>{b.text}</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

// ─── Numbers (count when they scroll into view) ───────────────
function Numbers() {
  const ref = useRef<HTMLDivElement>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const io = new IntersectionObserver(([e]) => e.isIntersecting && setSeen(true), { threshold: 0.4 });
    if (ref.current) io.observe(ref.current);
    return () => io.disconnect();
  }, []);
  return (
    <section className="block block--tight" id="numbers">
      <div className="numbers" ref={ref} data-reveal>
        <Num value={seen ? 15 : 0} suffix="/15" label="Real-style scam texts caught" />
        <Num value={seen ? 0 : 10} label="False alarms on genuine messages" />
        <Num value={seen ? 8 : 0} label="Fixed reply categories" />
        <Num value={seen ? 0 : 100} label="Words of scammer text seen by the AI" />
      </div>
    </section>
  );
}
function Num({ value, suffix = '', label }: { value: number; suffix?: string; label: string }) {
  const n = useCountUp(value, 1400);
  return (
    <div className="num">
      <div className="num-value">
        {n}
        <small>{suffix}</small>
      </div>
      <div className="num-label">{label}</div>
    </div>
  );
}

export function Landing() {
  useScrollEffects();
  return (
    <>
      <div className="scroll-bar" aria-hidden />
      <Nav />
      <Hero />
      <Marquee />
      <How />
      <Safe />
      <Trap />
      <Numbers />
    </>
  );
}

export function Footer() {
  return (
    <footer className="footer">
      <div className="footer-inner">
        <div className="footer-brand">
          <BrandMark small />
          <span>HawkGuard</span>
        </div>
        <div className="footer-cols">
          <div>
            <h4>Product</h4>
            <a href="#how">Method</a>
            <a href="#safe">Safety</a>
            <a href="#trap">Honeypot</a>
            <a href="#demo">Live demo</a>
          </div>
          <div>
            <h4>Report fraud</h4>
            <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">
              cybercrime.gov.in
            </a>
            <span>Helpline 1930</span>
          </div>
          <div>
            <h4>Built for</h4>
            <span>ASYNC'26</span>
            <span>Track 3 · Cybersecurity</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
