import { useEffect, useState } from 'react';
import {
  ArrowRight,
  CheckCircle,
  FileText,
  Landmark,
  Link2,
  MessageSquare,
  Phone,
  ShieldAlert,
  Wallet,
  Wand2,
  X,
  Zap,
} from 'lucide-react';
import type {
  HawkGuardState,
  ScamAnalysis,
  EngagementSession,
  EngagementMessage,
  Persona,
  ThreatReport,
  PanelStage,
} from '../shared/types';
import { PERSONAS, getPersona } from '../shared/personas';
import { analysisIdentity } from '../shared/tab-analysis-store';
import { fetchHealth, type Health } from '../ui/ai';
import { HoneypotCard, useHoneypot } from '../ui/honeypot';
import {
  BrandMark,
  Gauge,
  Mascot,
  moodFor,
  IntelGroup,
  accountsOnly,
  Pipeline,
  SEVERITY_TEXT,
  StatusPill,
  initials,
  looksLikeInjection,
  scenarioLabel,
} from '../ui/components';

type Stage = PanelStage;

const STAGES: { id: Stage; label: string }[] = [
  { id: 'evidence', label: 'Evidence' },
  { id: 'persona', label: 'Persona' },
  { id: 'engage', label: 'Engage' },
  { id: 'report', label: 'Report' },
];

const time = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export function Panel() {
  const [state, setState] = useState<HawkGuardState | null>(null);
  const [stage, setStage] = useState<Stage>('evidence');
  const [selectedPersona, setSelectedPersona] = useState<string>('suresh_pillai');
  const [scammerInput, setScammerInput] = useState('');
  const [draftMessage, setDraftMessage] = useState<EngagementMessage | null>(null);
  const [editedDraft, setEditedDraft] = useState('');
  const [initialContext, setInitialContext] = useState('');
  const [drafting, setDrafting] = useState(false);
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [health, setHealth] = useState<Health | null | undefined>(undefined);
  const [inspectId, setInspectId] = useState<string | null>(null);

  // Surface background failures instead of silently doing nothing
  const check = (res: any) => {
    if (res?.ok) {
      setError(null);
      return true;
    }
    setError(String(res?.error || 'No response from HawkGuard background').replace(/^Error: /, ''));
    return false;
  };

  useEffect(() => {
    chrome.runtime.sendMessage({ kind: 'GET_STATE', payload: {} }).then((res) => {
      if (res?.ok) setState(res.data);
    });
    // Banner buttons can ask for a starting stage (Engage → persona)
    chrome.runtime.sendMessage({ kind: 'CONSUME_PANEL_STAGE' }).then((res) => {
      if (res?.ok && res.data) setStage(res.data);
    });
    const listener = (msg: any) => {
      if (msg.kind === 'STATE_UPDATE') setState(msg.payload);
      if (msg.kind === 'SET_PANEL_STAGE') setStage(msg.payload.stage);
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  const backendUrl = state?.settings.backendUrl;
  useEffect(() => {
    if (backendUrl) fetchHealth(backendUrl).then(setHealth);
  }, [backendUrl]);

  const analysis = state?.currentAnalysis;
  const session = state?.activeSession;
  // Only trap activity after this engagement handed over the bait belongs to the case
  const lureAt = session?.messages.find((m) => m.lure)?.timestamp;
  const honeypot = useHoneypot(lureAt ?? Number.MAX_SAFE_INTEGER, backendUrl);

  const startEngagement = async () => {
    if (!analysis) return;
    const context = initialContext || analysis.suspicionReasons.join('. ') || 'Initial contact';
    const res = await chrome.runtime.sendMessage({
      kind: 'START_ENGAGEMENT',
      payload: {
        analysisId: analysisIdentity(analysis),
        personaId: selectedPersona,
        initialContext: context,
      },
    });
    if (check(res)) {
      setStage('engage');
    }
  };

  // Auto-reply on = the decoy answers by itself; off = you review a draft before it's sent
  const auto = state?.settings.requireApproval === false;
  const toggleAuto = (on: boolean) =>
    chrome.runtime.sendMessage({ kind: 'SET_SETTINGS', payload: { requireApproval: !on } });

  // Generate the persona's reply. In auto mode it goes straight into the thread; otherwise it
  // becomes an editable draft awaiting approval.
  const runReply = async (autoSend: boolean) => {
    if (!session || drafting || draftMessage) return;
    setDrafting(true);
    try {
      const res = await chrome.runtime.sendMessage({
        kind: 'DRAFT_RESPONSE',
        payload: { sessionId: session.id },
      });
      if (!check(res)) return;
      const draft = res.data as EngagementMessage;
      if (autoSend) {
        await chrome.runtime.sendMessage({
          kind: 'APPROVE_RESPONSE',
          payload: { sessionId: session.id, messageId: draft.id, edited: draft.content, draft },
        });
        setInspectId(draft.id);
      } else {
        setDraftMessage(draft);
        setEditedDraft(draft.content);
      }
    } finally {
      setDrafting(false);
    }
  };
  const draftReply = () => runReply(auto);

  const approveDraft = async () => {
    if (!session || !draftMessage) return;
    await chrome.runtime.sendMessage({
      kind: 'APPROVE_RESPONSE',
      payload: { sessionId: session.id, messageId: draftMessage.id, edited: editedDraft, draft: draftMessage },
    });
    setInspectId(draftMessage.id);
    setDraftMessage(null);
    setEditedDraft('');
  };

  const submitScammer = async () => {
    if (!session || !scammerInput.trim()) return;
    const res = await chrome.runtime.sendMessage({
      kind: 'SUBMIT_SCAMMER_REPLY',
      payload: { sessionId: session.id, message: scammerInput },
    });
    setScammerInput('');
    // In auto mode, logging their message immediately triggers the decoy's reply
    if (check(res) && auto) await runReply(true);
  };

  const generateReport = async () => {
    if (!session) return;
    const res = await chrome.runtime.sendMessage({
      kind: 'GENERATE_REPORT',
      payload: { sessionId: session.id },
    });
    if (check(res)) {
      setReport(res.data);
      setStage('report');
    }
  };

  return (
    <div className="panel">
      <header className="panel-head">
        <div className="panel-top">
          <div className="brand">
            <BrandMark small />
            <div>
              <div className="panel-title">Case File</div>
              <div className="eyebrow">{analysis ? `HG-${analysis.timestamp.toString().slice(-6)}` : 'No active case'}</div>
            </div>
          </div>
          <StatusPill health={health} />
        </div>

        {analysis && (
          <div className="verdict">
            <Gauge score={analysis.score} severity={analysis.overallSeverity} size={60} />
            <div className="verdict-body">
              <div className={`verdict-title verdict-title--${analysis.overallSeverity}`}>
                {SEVERITY_TEXT[analysis.overallSeverity]}
                {analysis.overallSeverity !== 'safe' && ' detected'}
              </div>
              <div className="verdict-host">{analysis.hostname || 'local file'}</div>
            </div>
            <Mascot key={analysis.overallSeverity} mood={moodFor(analysis.overallSeverity)} size={64} className="verdict-mascot" />
          </div>
        )}

        <nav className="steps" aria-label="Case stages">
          {STAGES.map((s, i) => (
            <button key={s.id} className={stage === s.id ? 'is-active' : ''} onClick={() => setStage(s.id)}>
              <span className="steps-num">{i + 1}</span>
              {s.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="panel-body">
        {error && (
          <div className="error-banner">
            <Mascot mood="facepalm" size={40} />
            <span>
              {error}
              {/session/i.test(error) && ' — go back to Persona and start the engagement again.'}
            </span>
          </div>
        )}
        {stage === 'evidence' && <EvidenceStage analysis={analysis} onEngage={() => setStage('persona')} />}
        {stage === 'persona' && (
          <PersonaStage
            selectedPersona={selectedPersona}
            onSelect={setSelectedPersona}
            initialContext={initialContext}
            onContext={setInitialContext}
            onStart={startEngagement}
            hasAnalysis={!!analysis}
          />
        )}
        {stage === 'engage' && (
          <EngageStage
            session={session}
            analysis={analysis}
            health={health}
            honeypot={honeypot}
            inspectId={inspectId}
            onInspect={setInspectId}
            draftMessage={draftMessage}
            editedDraft={editedDraft}
            onEditDraft={setEditedDraft}
            onDiscardDraft={() => setDraftMessage(null)}
            onDraft={draftReply}
            onApprove={approveDraft}
            drafting={drafting}
            auto={auto}
            onToggleAuto={toggleAuto}
            scammerInput={scammerInput}
            onScammerInput={setScammerInput}
            onSubmitScammer={submitScammer}
            onGenerateReport={generateReport}
          />
        )}
        {stage === 'report' && <ReportStage report={report} />}
      </main>
    </div>
  );
}

// ─── Stage 1: Evidence ────────────────────────────────────────
function EvidenceStage({ analysis, onEngage }: { analysis?: ScamAnalysis; onEngage: () => void }) {
  if (!analysis) {
    return (
      <div className="empty">
        <Mascot mood="wave" size={96} className="empty-mascot" />
        No page analysed yet. Open a page or paste a message in the HawkGuard popup.
      </div>
    );
  }

  return (
    <>
      <section className="section">
        <h3 className="section-title">
          Forensic findings <span className="section-count">{analysis.findings.length}</span>
        </h3>
        {analysis.findings.length === 0 ? (
          <div className="empty">No specific findings — the page appears benign.</div>
        ) : (
          <div className="findings">
            {analysis.findings.map((f) => (
              <article key={f.id} className={`finding finding--${f.severity}`}>
                <div className="finding-head">
                  <span className="finding-dot" />
                  <span className="finding-title">{f.title}</span>
                  <span className="finding-cat">{f.category}</span>
                </div>
                <p className="finding-detail">{f.detail}</p>
                {f.evidence && Object.keys(f.evidence).length > 0 && (
                  <div className="finding-evidence">
                    {Object.entries(f.evidence).map(([k, v]) => (
                      <div key={k}>
                        <span className="muted">{k}</span> {String(v)}
                      </div>
                    ))}
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </section>

      {analysis.overallSeverity !== 'safe' && (
        <button className="btn btn-accent btn-block" onClick={onEngage}>
          Engage the scammer <ArrowRight size={15} />
        </button>
      )}
    </>
  );
}

// ─── Stage 2: Persona selection ───────────────────────────────
function PersonaStage(props: {
  selectedPersona: string;
  onSelect: (id: string) => void;
  initialContext: string;
  onContext: (t: string) => void;
  onStart: () => void;
  hasAnalysis: boolean;
}) {
  return (
    <>
      <section className="section">
        <h3 className="section-title">Choose a decoy identity</h3>
        <div className="persona-list">
          {PERSONAS.map((p) => (
            <PersonaCardView
              key={p.id}
              persona={p}
              selected={p.id === props.selectedPersona}
              onSelect={() => props.onSelect(p.id)}
            />
          ))}
        </div>
      </section>

      <section className="section">
        <h3 className="section-title">Scammer's first message</h3>
        <textarea
          className="field-input"
          rows={3}
          placeholder="Paste it here, or leave blank to start from the page findings…"
          value={props.initialContext}
          onChange={(e) => props.onContext(e.target.value)}
        />
      </section>

      <button className="btn btn-accent btn-block" onClick={props.onStart} disabled={!props.hasAnalysis}>
        <MessageSquare size={15} /> Begin engagement
      </button>
      {!props.hasAnalysis && <div className="hint">Analyse a page or paste a message first.</div>}
    </>
  );
}

function PersonaCardView({ persona, selected, onSelect }: { persona: Persona; selected: boolean; onSelect: () => void }) {
  return (
    <button className={`persona-card ${selected ? 'is-selected' : ''}`} onClick={onSelect} aria-pressed={selected}>
      <span className="avatar avatar--sm">{initials(persona.displayName)}</span>
      <span className="persona-card-body">
        <span className="persona-card-name">
          {persona.displayName}
          <span className="muted">
            {persona.age} · {persona.location.split(',')[0]}
          </span>
        </span>
        <span className="persona-card-desc">
          {persona.occupation}. {persona.personality}
        </span>
      </span>
      {selected && <CheckCircle size={16} className="persona-card-check" />}
    </button>
  );
}

// ─── Stage 3: Engage ──────────────────────────────────────────
function EngageStage(props: {
  session?: EngagementSession;
  analysis?: ScamAnalysis;
  health: Health | null | undefined;
  honeypot: ReturnType<typeof useHoneypot>;
  inspectId: string | null;
  onInspect: (id: string) => void;
  draftMessage: EngagementMessage | null;
  editedDraft: string;
  onEditDraft: (t: string) => void;
  onDiscardDraft: () => void;
  onDraft: () => void;
  onApprove: () => void;
  drafting: boolean;
  auto: boolean;
  onToggleAuto: (on: boolean) => void;
  scammerInput: string;
  onScammerInput: (t: string) => void;
  onSubmitScammer: () => void;
  onGenerateReport: () => void;
}) {
  if (!props.session) {
    return <div className="empty">No engagement running. Pick a persona in step 2 to begin.</div>;
  }

  const s = props.session;
  const persona = getPersona(s.personaId);
  const intel = s.aggregateIntel;
  const accounts = accountsOnly(intel.bankAccounts, intel.phoneNumbers);
  // Sessions started without a pasted message open with the page findings — show that as a note, not a chat bubble
  const fromFindings = (m: EngagementMessage, i: number) =>
    i === 0 && !!props.analysis && m.content === props.analysis.suspicionReasons.join('. ');

  // Inspect the chosen persona reply, or the latest one that has a template
  const withTrace = s.messages.filter((m) => m.role === 'persona' && m.template);
  const inspected = withTrace.find((m) => m.id === props.inspectId) || withTrace[withTrace.length - 1];
  const inspectedIdx = inspected ? s.messages.indexOf(inspected) : -1;
  const incoming = inspected
    ? [...s.messages.slice(0, inspectedIdx)].reverse().find((m) => m.role === 'scammer')
    : undefined;

  return (
    <>
      <section className="section">
        <h3 className="section-title">
          Captured intel
          <span className="section-count">
            {intel.upiIds.length + intel.phoneNumbers.length + intel.urls.length + accounts.length}
          </span>
        </h3>
        <div className="intel-grid">
          <IntelGroup icon={<Wallet size={13} />} title="UPI IDs" items={intel.upiIds} />
          <IntelGroup icon={<Phone size={13} />} title="Phones" items={intel.phoneNumbers} />
          <IntelGroup icon={<Link2 size={13} />} title="Links" items={intel.urls} />
          <IntelGroup icon={<Landmark size={13} />} title="Accounts" items={accounts} />
        </div>
      </section>

      <section className="section">
        <h3 className="section-title">
          Conversation
          <span className="section-count">{persona ? `as ${persona.displayName}` : ''}</span>
        </h3>
        <div className="thread">
          {s.messages.map((m, i) =>
            fromFindings(m, i) ? (
              <div key={m.id} className="note">
                <div className="note-label">Opened from page findings</div>
                {m.content}
              </div>
            ) : (
              <div key={m.id} className={`bubble-row bubble-row--${m.role}`}>
                <div
                  className={`bubble bubble--${m.role} ${m.id === inspected?.id ? 'is-inspected' : ''}`}
                  onClick={() => m.role === 'persona' && m.template && props.onInspect(m.id)}
                >
                  {m.content}
                  <span className="bubble-time">{time(m.timestamp)}</span>
                </div>
                {m.scenario && (
                  <button
                    className="bubble-tag"
                    onClick={() => m.role === 'persona' && m.template && props.onInspect(m.id)}
                  >
                    {m.role === 'scammer' && looksLikeInjection(m.content) && <ShieldAlert size={11} />}
                    {m.lure ? 'honeypot lure' : scenarioLabel(m.scenario)}
                  </button>
                )}
              </div>
            )
          )}

          {props.drafting && (
            <div className="bubble-row bubble-row--persona">
              <div className="bubble bubble--persona bubble--typing">
                <i />
                <i />
                <i />
              </div>
            </div>
          )}

          {props.draftMessage && (
            <div className="draft">
              <div className="draft-label">Draft reply · needs your approval</div>
              <textarea
                className="field-input"
                rows={4}
                value={props.editedDraft}
                onChange={(e) => props.onEditDraft(e.target.value)}
              />
              <div className="row">
                <button className="btn btn-primary" onClick={props.onApprove} disabled={!props.editedDraft.trim()}>
                  <CheckCircle size={15} /> Approve & send
                </button>
                <button className="btn btn-ghost" onClick={props.onDiscardDraft} aria-label="Discard draft">
                  <X size={15} />
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      <HoneypotCard
        compact
        decoy={props.honeypot.decoy}
        online={props.honeypot.online}
        lured={s.messages.some((m) => m.lure)}
        intruders={props.honeypot.intruders}
        onClear={props.honeypot.clear}
      />

      <section className="section composer-card">
        <div className="composer-top">
          <span className="section-title" style={{ margin: 0 }}>
            {props.auto ? 'Auto-reply on' : 'Review each reply'}
          </span>
          <button
            className={`auto-switch ${props.auto ? 'is-on' : ''}`}
            role="switch"
            aria-checked={props.auto}
            onClick={() => props.onToggleAuto(!props.auto)}
            title={props.auto ? 'The decoy answers by itself' : 'You approve each reply before it is sent'}
          >
            <span className="auto-switch-track"><span className="auto-switch-knob" /></span>
            Auto
          </button>
        </div>
        <textarea
          className="field-input"
          rows={2}
          placeholder="Scammer replied? Paste their message here…"
          value={props.scammerInput}
          onChange={(e) => props.onScammerInput(e.target.value)}
        />
        <div className="row">
          <button
            className="btn btn-accent"
            onClick={props.onSubmitScammer}
            disabled={!props.scammerInput.trim() || props.drafting || !!props.draftMessage}
          >
            {props.auto ? <Zap size={15} /> : <MessageSquare size={15} />}
            {props.auto ? (props.drafting ? 'Replying…' : 'Log & reply') : 'Log reply'}
          </button>
          {!props.auto && (
            <button className="btn" onClick={props.onDraft} disabled={props.drafting || !!props.draftMessage}>
              <Wand2 size={15} /> {props.drafting ? 'Drafting…' : 'Draft response'}
            </button>
          )}
        </div>
      </section>

      {inspected && incoming && persona && (
        <section className="section card card--tight">
          <h3 className="section-title">Why this reply is safe</h3>
          <Pipeline
            provider={props.health?.provider ?? null}
            trace={{
              incoming: incoming.content,
              scenario: inspected.scenario || 'unknown',
              template: inspected.template!,
              reply: inspected.content,
              turn: s.messages.filter((m, i) => m.role === 'persona' && i <= inspectedIdx).length,
              persona,
              rewritten: inspected.content !== inspected.template,
              lure: inspected.lure,
            }}
          />
        </section>
      )}

      <button className="btn btn-danger btn-block" onClick={props.onGenerateReport}>
        <FileText size={15} /> End session · generate report
      </button>
    </>
  );
}

// ─── Stage 4: Report ──────────────────────────────────────────
function ReportStage({ report }: { report: ThreatReport | null }) {
  if (!report) {
    return <div className="empty">End the engagement to generate a threat report.</div>;
  }

  const openFullReport = () => {
    const url = chrome.runtime.getURL(`src/report/index.html?id=${report.id}`);
    chrome.tabs.create({ url });
  };
  const intel = report.engagement?.aggregateIntel;
  const minutes = report.engagement
    ? Math.max(1, Math.round((report.engagement.endedAt! - report.engagement.startedAt) / 60000))
    : 0;

  return (
    <>
      <section className="card card--tight report-card">
        <div className="report-head">
          <div>
            <div className="eyebrow">Case {report.id.slice(0, 8).toUpperCase()}</div>
            <div className="report-title">{report.scamType}</div>
          </div>
          <span className={`flag flag--${report.confidence === 'high' ? 'threat' : 'caution'}`}>
            {report.confidence} confidence
          </span>
        </div>
        <div className="report-stats">
          <div>
            <div className="report-stat">{report.analysis.findings.length}</div>
            <div className="muted">findings</div>
          </div>
          <div>
            <div className="report-stat">
              {(intel?.upiIds.length || 0) + (intel?.phoneNumbers.length || 0) + (intel?.urls.length || 0)}
            </div>
            <div className="muted">intel items</div>
          </div>
          <div>
            <div className="report-stat">{report.engagement?.messages.length || 0}</div>
            <div className="muted">messages · {minutes}m</div>
          </div>
        </div>
      </section>

      <section className="section">
        <h3 className="section-title">Recommended actions</h3>
        <ol className="actions">
          {report.recommendedActions.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
        </ol>
      </section>

      <button className="btn btn-accent btn-block" onClick={openFullReport}>
        <FileText size={15} /> Open full report
      </button>
    </>
  );
}
