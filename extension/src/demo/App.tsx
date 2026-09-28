import { useEffect, useMemo, useRef, useState } from 'react';
import { Download, FileText, Landmark, Link2, Pause, Phone, Play, RotateCcw, Send, ShieldAlert, SkipForward, Wallet } from 'lucide-react';
import { classifyScenario, pickTemplate } from '../shared/scenarios';
import { PERSONAS } from '../shared/personas';
import { extractIntel, runFullAnalysis } from '../shared/detection';
import { SCRIPTS } from './scripts';
import { LURE_TURN, lureMessage } from '../shared/honeypot';
import { HoneypotCard, useHoneypot } from '../ui/honeypot';
import { downloadText, printAsPdf, type CaseReport } from './report';
import { fetchHealth, generateReply, type Health } from '../ui/ai';
import { playScreech } from '../ui/sound';
import {
  Gauge,
  IntelGroup,
  accountsOnly,
  BrandMark,
  Mascot,
  moodFor,
  Pipeline,
  SEVERITY_TEXT,
  SoundToggle,
  Stat,
  StatusPill,
  initials,
  looksLikeInjection,
  scenarioLabel as label,
  type PipelineTrace,
} from '../ui/components';

type Trace = PipelineTrace & { injection: boolean };

interface Msg {
  id: string;
  role: 'scammer' | 'persona';
  text: string;
  at: number;
  trace?: Trace;
}

const uid = () => crypto.randomUUID();
const newCaseId = () => Math.random().toString(16).slice(2, 8).toUpperCase();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const time = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

// Rough, clearly-labelled estimate: each stalling reply costs the scammer a few minutes
const MINUTES_PER_TURN = 3;

export function App() {
  const [scriptId, setScriptId] = useState(SCRIPTS[0].id);
  const [personaId, setPersonaId] = useState(PERSONAS[0].id);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [cursor, setCursor] = useState(0);
  const [auto, setAuto] = useState(false);
  const [typing, setTyping] = useState(false);
  const [draft, setDraft] = useState('');
  const [health, setHealth] = useState<Health | null | undefined>(undefined);
  const [inspectId, setInspectId] = useState<string | null>(null);
  const [caseId, setCaseId] = useState(newCaseId);
  const runRef = useRef(0); // bumps on reset so in-flight replies are dropped
  const threadRef = useRef<HTMLDivElement>(null);

  const script = SCRIPTS.find((s) => s.id === scriptId)!;
  const persona = PERSONAS.find((p) => p.id === personaId)!;
  const scriptDone = cursor >= script.messages.length;

  useEffect(() => {
    fetchHealth().then(setHealth);
  }, []);

  useEffect(() => {
    threadRef.current?.scrollTo({ top: threadRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages.length, typing]);

  const reset = (nextScript = scriptId, nextPersona = personaId) => {
    runRef.current++;
    setScriptId(nextScript);
    setPersonaId(nextPersona);
    setMessages([]);
    setCursor(0);
    setAuto(false);
    setTyping(false);
    setDraft('');
    setInspectId(null);
    setCaseId(newCaseId());
  };

  async function sendScammer(text: string) {
    if (!text.trim() || typing) return;
    const run = runRef.current;
    setMessages((m) => [...m, { id: uid(), role: 'scammer', text, at: Date.now() }]);
    setTyping(true);

    // The injection-resistant pipeline: classify → template → voice-only rewrite
    const scenario = classifyScenario(text);
    const used = messages.map((m) => m.trace?.template || '');
    const template = pickTemplate(scenario, persona.family, used);
    const turn = messages.filter((m) => m.role === 'persona').length + 1;
    const started = Date.now();
    // Honeypot: on the lure turn the persona hands over the decoy login — fixed text, no AI
    const decoy = health?.honeypot;
    const lure = turn === LURE_TURN && !!decoy;
    const reply = lure
      ? { text: lureMessage(persona.id, decoy), rewritten: false }
      : await generateReply(persona, template, turn);
    await sleep(Math.max(0, 1500 - (Date.now() - started))); // feel like typing

    if (run !== runRef.current) return;
    const replyText = reply.text;
    const personaMsg: Msg = {
      id: uid(),
      role: 'persona',
      text: replyText,
      at: Date.now(),
      trace: {
        incoming: text,
        reply: replyText,
        scenario,
        template: lure ? reply.text : template,
        turn,
        rewritten: reply.rewritten,
        lure,
        injection: looksLikeInjection(text),
        persona,
      },
    };
    setMessages((m) => [...m, personaMsg]);
    setInspectId(personaMsg.id);
    setTyping(false);
  }

  const sendNext = () => {
    if (scriptDone || typing) return;
    sendScammer(script.messages[cursor]);
    setCursor((c) => c + 1);
  };

  const sendDraft = () => {
    if (!draft.trim() || typing) return;
    sendScammer(draft.trim());
    setDraft('');
  };

  // Auto-play: feed the next scripted line once the persona has answered
  useEffect(() => {
    if (!auto || typing) return;
    if (scriptDone) {
      setAuto(false);
      return;
    }
    const t = setTimeout(sendNext, messages.length === 0 ? 300 : 2400);
    return () => clearTimeout(t);
  }, [auto, typing, cursor, messages.length]);

  // ─── Derived case-file data ─────────────────────────────────
  const scammerText = messages
    .filter((m) => m.role === 'scammer')
    .map((m) => m.text)
    .join('\n');

  const analysis = useMemo(
    () => (scammerText ? runFullAnalysis('https://chat.local/', scammerText) : null),
    [scammerText]
  );

  // Hawk screech the first time this conversation is judged a threat (remembered per viewer)
  const [sound, setSound] = useState(() => {
    try {
      return localStorage.getItem('hg-sound') !== 'off';
    } catch {
      return true;
    }
  });
  const toggleSound = (on: boolean) => {
    setSound(on);
    try {
      localStorage.setItem('hg-sound', on ? 'on' : 'off');
    } catch {}
  };
  const screechedCase = useRef<string | null>(null);
  useEffect(() => {
    if (sound && analysis?.overallSeverity === 'threat' && screechedCase.current !== caseId) {
      screechedCase.current = caseId;
      playScreech();
    }
  }, [analysis?.overallSeverity, caseId, sound]);

  const intel = useMemo(() => {
    const i = extractIntel(scammerText);
    return {
      upi: i.upiIds,
      phones: i.phoneNumbers,
      urls: i.urls,
      accounts: accountsOnly(i.bankAccounts, i.phoneNumbers),
    };
  }, [scammerText]);

  const intelCount = intel.upi.length + intel.phones.length + intel.urls.length + intel.accounts.length;
  const personaTurns = messages.filter((m) => m.role === 'persona').length;
  const injections = messages.filter((m) => m.trace?.injection).length;
  // Only trap activity after the bait was handed over belongs to this case
  const lureAt = messages.find((m) => m.trace?.lure)?.at;
  const lured = lureAt !== undefined;
  const honeypot = useHoneypot(lureAt ?? Number.MAX_SAFE_INTEGER);
  const inspected =
    messages.find((m) => m.id === inspectId && m.trace) ||
    [...messages].reverse().find((m) => m.trace);

  const buildReport = (): CaseReport => ({
    caseId: `HG-${caseId}`,
    generatedAt: new Date(),
    scamType: script.title,
    scammerContact: script.contact,
    decoyPersona: persona.displayName,
    threat: analysis && {
      score: analysis.score,
      severity: analysis.overallSeverity,
      signals: analysis.suspicionReasons,
    },
    intel,
    injectionAttempts: injections,
    intruders: honeypot.intruders,
    transcript: messages.map((m) => ({ role: m.role, text: m.text, at: m.at, classifiedAs: m.trace?.scenario })),
  });

  return (
    <div className="app" id="demo">
      <header className="topbar" data-reveal>
        <div>
          <div className="section-eyebrow">● Live demo</div>
          <h2 className="topbar-title">Watch HawkGuard waste a scammer's time</h2>
          <div className="brand-sub">Pick a scam and a decoy, then press play. Every reply below is generated live.</div>
        </div>
        <div className="topbar-actions">
          <SoundToggle on={sound} onChange={toggleSound} />
          <StatusPill health={health} />
        </div>
      </header>

      <section className="controls">
        <div className="control">
          <div className="control-label">Scam scenario</div>
          <div className="segmented">
            {SCRIPTS.map((s) => (
              <button
                key={s.id}
                className={s.id === scriptId ? 'is-active' : ''}
                onClick={() => reset(s.id, personaId)}
                title={s.subtitle}
              >
                {s.id === 'injection' && <ShieldAlert size={14} />}
                {s.title}
              </button>
            ))}
          </div>
        </div>
        <div className="control">
          <div className="control-label">Decoy persona</div>
          <div className="personas">
            {PERSONAS.map((p) => (
              <button
                key={p.id}
                className={`persona ${p.id === personaId ? 'is-active' : ''}`}
                onClick={() => reset(scriptId, p.id)}
                title={p.personality}
              >
                <span className="avatar avatar--sm">{initials(p.displayName)}</span>
                <span className="persona-text">
                  {p.displayName}
                  <small>
                    {p.age} · {p.location.split(',')[0]}
                  </small>
                </span>
              </button>
            ))}
          </div>
        </div>
      </section>

      <main className="stage" data-reveal="stage">
        {/* ─── Phone ─────────────────────────────────────────── */}
        <div className="phone-col">
          <div className="phone">
            <div className="phone-head">
              <span className="avatar avatar--scam">
                <Phone size={16} />
              </span>
              <div className="phone-contact">
                <div className="phone-name">{script.contact.name}</div>
                <div className="phone-number">{script.contact.number}</div>
              </div>
              {analysis && analysis.overallSeverity !== 'safe' && (
                <span className={`flag flag--${analysis.overallSeverity}`}>
                  <ShieldAlert size={12} /> Scam
                </span>
              )}
            </div>

            <div className="thread" ref={threadRef}>
              {messages.length === 0 ? (
                <div className="thread-empty">
                  <Mascot mood="wave" size={120} className="empty-mascot" />
                  <div className="thread-empty-title">{script.title}</div>
                  <p>{script.subtitle}.</p>
                  <p>
                    <strong>{persona.displayName}</strong> will answer, and waste their time without ever sharing
                    anything real.
                  </p>
                  <button className="btn btn-primary" onClick={() => setAuto(true)}>
                    <Play size={15} /> Start conversation
                  </button>
                </div>
              ) : (
                <>
                  <div className="thread-day">Today · HawkGuard is replying as {persona.displayName.split(' ')[0]}</div>
                  {messages.map((m) => (
                    <div key={m.id} className={`bubble-row bubble-row--${m.role}`}>
                      <div
                        className={`bubble bubble--${m.role} ${m.trace && inspected?.id === m.id ? 'is-inspected' : ''}`}
                        onClick={() => m.trace && setInspectId(m.id)}
                      >
                        {m.text}
                        <span className="bubble-time">{time(m.at)}</span>
                      </div>
                      {m.trace && (
                        <button className="bubble-tag" onClick={() => setInspectId(m.id)}>
                          {m.trace.injection && <ShieldAlert size={11} />}
                          {m.trace.lure ? 'honeypot lure' : label(m.trace.scenario)}
                        </button>
                      )}
                    </div>
                  ))}
                  {typing && (
                    <div className="bubble-row bubble-row--persona">
                      <div className="bubble bubble--persona bubble--typing">
                        <i />
                        <i />
                        <i />
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>

            <form
              className="composer"
              onSubmit={(e) => {
                e.preventDefault();
                sendDraft();
              }}
            >
              <input
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="Type as the scammer…"
                aria-label="Scammer message"
              />
              <button type="submit" disabled={!draft.trim() || typing} aria-label="Send">
                <Send size={16} />
              </button>
            </form>
          </div>

          <div className="playbar">
            <button className="btn btn-primary" onClick={() => setAuto((a) => !a)} disabled={scriptDone && !auto}>
              {auto ? <Pause size={15} /> : <Play size={15} />}
              {auto ? 'Pause' : messages.length ? 'Resume' : 'Auto-play'}
            </button>
            <button className="btn" onClick={sendNext} disabled={scriptDone || typing || auto}>
              <SkipForward size={15} /> Next line
              <span className="btn-count">
                {cursor}/{script.messages.length}
              </span>
            </button>
            <button className="btn btn-ghost" onClick={() => reset()} aria-label="Reset">
              <RotateCcw size={15} />
            </button>
          </div>
        </div>

        {/* ─── Case file ─────────────────────────────────────── */}
        <div className="casefile">
          <div className={`card threat threat--${analysis?.overallSeverity ?? 'idle'}`} key={analysis?.overallSeverity ?? 'idle'}>
            <Gauge score={analysis?.score ?? 0} severity={analysis?.overallSeverity ?? 'safe'} />
            <div className="threat-body">
              <div className="eyebrow">
                Case HG-{caseId} · {script.title}
              </div>
              <div className="threat-title">
                {analysis ? (
                  <>
                    {SEVERITY_TEXT[analysis.overallSeverity]} detected
                  </>
                ) : (
                  'Waiting for first message'
                )}
              </div>
              <ul className="signals">
                {(analysis?.suspicionReasons.length ? analysis.suspicionReasons : ['No signals yet']).map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            </div>
            {analysis && (
              <Mascot key={analysis.overallSeverity} mood={moodFor(analysis.overallSeverity)} size={110} className="threat-mascot" />
            )}
          </div>

          <div className="stats">
            <Stat value={`~${personaTurns * MINUTES_PER_TURN}m`} label="Scammer time wasted (est.)" />
            <Stat value={intelCount} label="Intel items captured" accent={intelCount > 0} />
            <Stat value={injections} label="Injection attempts blocked" warn={injections > 0} />
          </div>

          <div className="card">
            <div className="card-head">
              <h2>Captured intel</h2>
              <span className="muted">Extracted locally from the scammer's messages</span>
            </div>
            <div className="intel">
              <IntelGroup icon={<Wallet size={14} />} title="UPI IDs" items={intel.upi} />
              <IntelGroup icon={<Phone size={14} />} title="Phone numbers" items={intel.phones} />
              <IntelGroup icon={<Link2 size={14} />} title="Links" items={intel.urls} />
              <IntelGroup icon={<Landmark size={14} />} title="Bank accounts" items={intel.accounts} />
            </div>
          </div>

          <HoneypotCard
            decoy={honeypot.decoy}
            online={honeypot.online}
            lured={lured}
            intruders={honeypot.intruders}
            onClear={honeypot.clear}
          />

          <div className="card">
            <div className="card-head">
              <h2>Why the scammer can't hack the AI</h2>
              <span className="muted">{inspected?.trace ? `Turn ${inspected.trace.turn}` : 'Live pipeline'}</span>
            </div>
            {inspected?.trace ? (
              <Pipeline trace={inspected.trace} provider={health?.provider ?? null} />
            ) : (
              <div className="empty">Start a conversation to watch each reply move through the pipeline.</div>
            )}
          </div>

          <div className="report-row">
            <button className="btn btn-primary" onClick={() => printAsPdf(buildReport())} disabled={!messages.length}>
              <Download size={15} /> Download PDF report
            </button>
            <button className="btn" onClick={() => downloadText(buildReport())} disabled={!messages.length}>
              <FileText size={15} /> Text file
            </button>
            <span className="muted">Ready to file at cybercrime.gov.in · helpline 1930</span>
          </div>
        </div>
      </main>
    </div>
  );
}
