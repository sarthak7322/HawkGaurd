import { useEffect, useState } from 'react';
import { ChevronRight, Eye, FileText, Play, ScanLine } from 'lucide-react';
import type { HawkGuardState, ScamAnalysis, ThreatReport } from '../shared/types';
import { BrandMark, Gauge, Mascot, SEVERITY_TEXT, SoundToggle, moodFor } from '../ui/components';

type Tab = 'current' | 'paste' | 'reports';

export function Popup() {
  const [state, setState] = useState<HawkGuardState | null>(null);
  const [tab, setTab] = useState<Tab>('current');
  const [pasteText, setPasteText] = useState('');
  const [pasteResult, setPasteResult] = useState<ScamAnalysis | null>(null);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    chrome.runtime.sendMessage({ kind: 'GET_STATE' }).then((res) => {
      if (res?.ok) setState(res.data);
    });
    const listener = (msg: any) => {
      if (msg.kind === 'STATE_UPDATE') setState(msg.payload);
    };
    chrome.runtime.onMessage.addListener(listener);
    return () => chrome.runtime.onMessage.removeListener(listener);
  }, []);

  const openPanel = async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab.windowId !== undefined) {
      await chrome.sidePanel.open({ windowId: tab.windowId });
    }
  };

  const analyzePaste = async () => {
    if (!pasteText.trim()) return;
    setScanning(true);
    try {
      const res = await chrome.runtime.sendMessage({
        kind: 'ANALYZE_TEXT',
        payload: { text: pasteText },
      });
      if (res?.ok) setPasteResult(res.data);
    } finally {
      setScanning(false);
    }
  };

  const openReport = (reportId: string) => {
    const url = chrome.runtime.getURL(`src/report/index.html?id=${reportId}`);
    chrome.tabs.create({ url });
  };

  const openDemo = () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/demo/index.html') });
  };

  return (
    <div className="popup">
      <header className="popup-head">
        <div className="brand">
          <BrandMark small />
          <div>
            <div className="popup-title">HawkGuard</div>
            <div className="brand-sub">Defensive intelligence</div>
          </div>
        </div>
        <SoundToggle
          on={state?.settings.sound ?? true}
          onChange={(sound) => chrome.runtime.sendMessage({ kind: 'SET_SETTINGS', payload: { sound } })}
        />
      </header>

      <nav className="segmented popup-tabs" role="tablist">
        <button className={tab === 'current' ? 'is-active' : ''} onClick={() => setTab('current')}>
          This page
        </button>
        <button className={tab === 'paste' ? 'is-active' : ''} onClick={() => setTab('paste')}>
          Paste
        </button>
        <button className={tab === 'reports' ? 'is-active' : ''} onClick={() => setTab('reports')}>
          Case files
        </button>
      </nav>

      <main className="popup-body">
        {tab === 'current' && <CurrentPageTab analysis={state?.currentAnalysis} onOpen={openPanel} />}
        {tab === 'paste' && (
          <PasteTab
            text={pasteText}
            onText={setPasteText}
            onAnalyze={analyzePaste}
            scanning={scanning}
            result={pasteResult}
            onOpenPanel={openPanel}
          />
        )}
        {tab === 'reports' && <ReportsTab reports={state?.recentReports || []} onOpen={openReport} />}
      </main>

      <button className="demo-card" onClick={openDemo}>
        <span className="demo-card-icon">
          <Play size={16} fill="currentColor" />
        </span>
        <span className="demo-card-text">
          <strong>Live engagement demo</strong>
          <span>Watch HawkGuard waste a scammer's time</span>
        </span>
        <ChevronRight size={16} className="demo-card-arrow" />
      </button>
    </div>
  );
}

function Verdict({ analysis }: { analysis: ScamAnalysis }) {
  const sev = analysis.overallSeverity;
  return (
    <div className="popup-verdict">
      <Gauge score={analysis.score} severity={sev} size={64} />
      <div className="popup-verdict-body">
        <div className={`popup-verdict-title popup-verdict-title--${sev}`}>{SEVERITY_TEXT[sev]}</div>
        <div className="popup-verdict-host">{analysis.hostname || 'local file'}</div>
      </div>
      <Mascot key={sev} mood={moodFor(sev)} size={60} className="verdict-mascot" />
    </div>
  );
}

function CurrentPageTab({ analysis, onOpen }: { analysis?: ScamAnalysis; onOpen: () => void }) {
  if (!analysis) {
    return (
      <div className="empty">
        <Mascot mood="wave" size={80} className="empty-mascot" />
        Nothing flagged yet. Load a page or paste a message to begin.
      </div>
    );
  }

  return (
    <>
      <Verdict analysis={analysis} />
      {analysis.suspicionReasons.length > 0 && (
        <ul className="reasons">
          {analysis.suspicionReasons.slice(0, 3).map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
      <button className="btn btn-accent btn-block" onClick={onOpen}>
        <Eye size={15} /> Open case file
      </button>
    </>
  );
}

function PasteTab(props: {
  text: string;
  onText: (t: string) => void;
  onAnalyze: () => void;
  scanning: boolean;
  result: ScamAnalysis | null;
  onOpenPanel: () => void;
}) {
  return (
    <>
      <textarea
        className="field-input"
        rows={5}
        placeholder="Paste an SMS, email, or WhatsApp forward…"
        value={props.text}
        onChange={(e) => props.onText(e.target.value)}
      />
      <button className="btn btn-primary btn-block" onClick={props.onAnalyze} disabled={props.scanning || !props.text.trim()}>
        <ScanLine size={15} />
        {props.scanning ? 'Analysing…' : 'Analyse message'}
      </button>

      {props.result && (
        <>
          <Verdict analysis={props.result} />
          <button className="btn btn-accent btn-block" onClick={props.onOpenPanel}>
            <Eye size={15} /> Open case file
          </button>
        </>
      )}
    </>
  );
}

function ReportsTab({ reports, onOpen }: { reports: ThreatReport[]; onOpen: (id: string) => void }) {
  if (reports.length === 0) {
    return <div className="empty">Reports you generate will land here.</div>;
  }
  return (
    <div className="report-list">
      {reports.map((r) => (
        <button key={r.id} className="report-item" onClick={() => onOpen(r.id)}>
          <FileText size={16} className="report-item-icon" />
          <span className="report-item-body">
            <span className="report-item-title">{r.scamType}</span>
            <span className="muted">
              {new Date(r.createdAt).toLocaleString()} · {r.confidence}
            </span>
          </span>
          <ChevronRight size={15} className="muted" />
        </button>
      ))}
    </div>
  );
}
