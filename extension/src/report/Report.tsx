import { useEffect, useState } from 'react';
import { Copy, Download, ExternalLink, Printer } from 'lucide-react';
import type { ThreatReport } from '../shared/types';

export function Report() {
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const id = params.get('id');
    chrome.storage.local.get(['recentReports'], (data) => {
      const reports = (data.recentReports || []) as ThreatReport[];
      const found = id ? reports.find((r) => r.id === id) : reports[0];
      setReport(found || null);
    });
  }, []);

  const copyText = async () => {
    if (!report) return;
    const text = formatAsText(report);
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const openCertIn = () => {
    window.open('https://www.cert-in.org.in/', '_blank');
  };

  const openCyberCrime = () => {
    window.open('https://cybercrime.gov.in/', '_blank');
  };

  if (!report) {
    return (
      <div className="report-page">
        <div className="empty-state">
          <div className="empty-state__icon">— CASE FILE NOT FOUND —</div>
          <div>This report does not exist or has been archived.</div>
        </div>
      </div>
    );
  }

  const createdAt = new Date(report.createdAt);

  return (
    <div className="report-page">
      <div className="report-toolbar">
        <button className="btn btn-primary" onClick={copyText}>
          <Copy size={14} /> {copied ? 'Copied' : 'Copy report'}
        </button>
        <button className="btn" onClick={() => window.print()}>
          <Printer size={14} /> Print / Save PDF
        </button>
        <button className="btn btn-ghost" onClick={openCertIn}>
          <ExternalLink size={14} /> CERT-In
        </button>
        <button className="btn btn-ghost" onClick={openCyberCrime}>
          <ExternalLink size={14} /> cybercrime.gov.in
        </button>
      </div>

      <header className="report-header">
        <div className="report-header__row">
          <div className="report-header__brand">
            <div className="report-header__mark">HG</div>
            <div>
              <div className="report-header__title">Threat Report</div>
              <div className="report-header__sub">HAWKGUARD · CASE FILE · CONFIDENTIAL</div>
            </div>
          </div>
          <div className="report-header__stamp">
            CASE#: {report.id.slice(0, 8).toUpperCase()}<br />
            FILED: {createdAt.toLocaleDateString()} {createdAt.toLocaleTimeString()}<br />
            CONFIDENCE: {report.confidence.toUpperCase()}
          </div>
        </div>

        <div className="report-meta-grid">
          <div className="report-meta-cell">
            <div className="report-meta-cell__label">CLASSIFICATION</div>
            <div className="report-meta-cell__value">{report.scamType}</div>
          </div>
          <div className="report-meta-cell">
            <div className="report-meta-cell__label">HOSTNAME</div>
            <div className="report-meta-cell__value" style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--type-sm)' }}>
              {report.analysis.hostname}
            </div>
          </div>
          <div className="report-meta-cell">
            <div className="report-meta-cell__label">FINDINGS</div>
            <div className="report-meta-cell__value">{report.analysis.findings.length}</div>
          </div>
          <div className="report-meta-cell">
            <div className="report-meta-cell__label">ENGAGEMENT</div>
            <div className="report-meta-cell__value">
              {report.engagement ? `${report.engagement.messages.length} msgs` : 'none'}
            </div>
          </div>
        </div>
      </header>

      <div className="report-verdict-strip">
        <div>
          <div className="report-verdict-strip__label">OVERALL VERDICT</div>
          <div className="report-verdict-strip__value">
            {report.analysis.overallSeverity.toUpperCase()}
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div className="report-verdict-strip__label">THREAT SCORE</div>
          <div className="report-verdict-strip__score">{report.analysis.score}</div>
        </div>
      </div>

      <section className="report-section">
        <h2 className="report-section__title">Forensic findings</h2>
        <div className="finding-list">
          {report.analysis.findings.map((f) => (
            <div key={f.id} className={`finding finding--${f.severity}`}>
              <div className="finding__header">
                <div className="finding__title">{f.title}</div>
                <div className="finding__cat">{f.category.toUpperCase()}</div>
              </div>
              <div className="finding__detail">{f.detail}</div>
              {f.evidence && Object.keys(f.evidence).length > 0 && (
                <div className="finding__evidence">
                  {Object.entries(f.evidence).map(([k, v]) => (
                    <div key={k}>
                      <span style={{ color: 'var(--ink-500)' }}>{k}:</span> {String(v)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {report.engagement && (
        <>
          <section className="report-section">
            <h2 className="report-section__title">Extracted intelligence</h2>
            <table className="report-intel-table">
              <thead>
                <tr>
                  <th style={{ width: 140 }}>TYPE</th>
                  <th>VALUES</th>
                </tr>
              </thead>
              <tbody>
                <IntelRow label="UPI IDs" items={report.engagement.aggregateIntel.upiIds} />
                <IntelRow label="Phones" items={report.engagement.aggregateIntel.phoneNumbers} />
                <IntelRow label="URLs" items={report.engagement.aggregateIntel.urls} />
                <IntelRow label="Bank #s" items={report.engagement.aggregateIntel.bankAccounts} />
                <IntelRow label="Emails" items={report.engagement.aggregateIntel.emailAddresses} />
              </tbody>
            </table>
          </section>

          <section className="report-section">
            <h2 className="report-section__title">Engagement transcript</h2>
            <div className="report-transcript">
              {report.engagement.messages.map((m) => (
                <div key={m.id} className={`report-transcript__msg report-transcript__msg--${m.role}`}>
                  <div className="report-transcript__role">
                    {m.role === 'scammer' ? 'SCAMMER' : 'PERSONA'}
                    {m.scenario && ` · ${m.scenario.replace(/_/g, ' ').toUpperCase()}`}
                  </div>
                  <div>{m.content}</div>
                </div>
              ))}
            </div>
          </section>
        </>
      )}

      {report.intruders && report.intruders.length > 0 && (
        <section className="report-section">
          <h2 className="report-section__title">Scammer fingerprint · honeypot</h2>
          {report.intruders.map((v) => (
            <div key={v.visitor} className={`finding finding--${v.worst === 'info' ? 'unknown' : v.worst}`} style={{ marginBottom: 'var(--sp-3)' }}>
              <div className="finding__header">
                <div className="finding__title">
                  {v.device} · {v.browser}
                  {v.loggedIn ? ' — logged in to decoy' : ''}
                  {v.automated ? ' — automated tool' : ''}
                </div>
                <div className="finding__cat">{v.worst.toUpperCase()}</div>
              </div>
              <div className="finding__evidence">
                <div><span style={{ color: 'var(--ink-500)' }}>IP address:</span> {v.ip}</div>
                <div><span style={{ color: 'var(--ink-500)' }}>Location:</span> {v.geo.label}{v.geo.isp ? ` · ${v.geo.isp}` : ''}{v.geo.vpn ? ' · VPN / hosting IP' : ''}</div>
                {v.geo.lat !== undefined && v.geo.lon !== undefined && (
                  <div><span style={{ color: 'var(--ink-500)' }}>Coordinates:</span> ≈ {v.geo.lat}, {v.geo.lon} (IP-based, city level){v.geo.timezone ? ` · ${v.geo.timezone}` : ''}</div>
                )}
                {v.geo.asn && <div><span style={{ color: 'var(--ink-500)' }}>Network:</span> {v.geo.asn}{v.geo.mobile ? ' (mobile)' : ''}</div>}
                {v.language && <div><span style={{ color: 'var(--ink-500)' }}>Language:</span> {v.language}</div>}
                {v.credentialsTried.length > 0 && (
                  <div><span style={{ color: 'var(--ink-500)' }}>Credentials tried:</span> {v.credentialsTried.map((c) => `${c.username} / ${c.password}`).join(', ')}</div>
                )}
              </div>
              <div className="finding__detail" style={{ marginTop: 'var(--sp-2)' }}>
                {v.actions.map((a) => (
                  <div key={a.id}>
                    [{new Date(a.at).toLocaleTimeString()}] <strong>{a.severity.toUpperCase()}</strong> — {a.detail}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </section>
      )}

      <section className="report-section">
        <h2 className="report-section__title">Recommended actions</h2>
        <ol className="report-actions-list">
          {report.recommendedActions.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
        </ol>
      </section>
    </div>
  );
}

function IntelRow({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <tr>
      <td>{label}</td>
      <td>
        {items.map((v, i) => (
          <div key={i}>{v}</div>
        ))}
      </td>
    </tr>
  );
}

function formatAsText(report: ThreatReport): string {
  const lines = [
    `HAWKGUARD THREAT REPORT`,
    `─────────────────────────────`,
    `Case ID: ${report.id.slice(0, 8).toUpperCase()}`,
    `Filed: ${new Date(report.createdAt).toISOString()}`,
    `Classification: ${report.scamType}`,
    `Confidence: ${report.confidence.toUpperCase()}`,
    `Verdict: ${report.analysis.overallSeverity.toUpperCase()} (${report.analysis.score}/100)`,
    ``,
    `HOST`,
    `  ${report.analysis.hostname}`,
    ``,
    `FORENSIC FINDINGS (${report.analysis.findings.length})`,
  ];
  for (const f of report.analysis.findings) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`      ${f.detail}`);
  }
  if (report.engagement) {
    lines.push('');
    lines.push('EXTRACTED INTEL');
    for (const [k, v] of Object.entries(report.engagement.aggregateIntel)) {
      const arr = v as string[];
      if (arr.length > 0) lines.push(`  ${k}: ${arr.join(', ')}`);
    }
    lines.push('');
    lines.push(`ENGAGEMENT: ${report.engagement.messages.length} messages exchanged`);
  }
  if (report.intruders && report.intruders.length > 0) {
    lines.push('');
    lines.push('SCAMMER FINGERPRINT (HONEYPOT)');
    report.intruders.forEach((v, i) => {
      lines.push(`  Visitor ${i + 1}: ${v.device}, ${v.browser}${v.automated ? ' (automated tool)' : ''}${v.loggedIn ? ' — logged in to decoy' : ''}`);
      lines.push(`    IP address: ${v.ip}`);
      lines.push(`    Location:   ${v.geo.label}${v.geo.isp ? ` · ${v.geo.isp}` : ''}${v.geo.vpn ? ' · VPN/hosting IP' : ''}`);
      if (v.geo.lat !== undefined && v.geo.lon !== undefined) lines.push(`    Coordinates: ~ ${v.geo.lat}, ${v.geo.lon} (IP-based, city level)`);
      if (v.geo.asn) lines.push(`    Network:    ${v.geo.asn}${v.geo.mobile ? ' (mobile)' : ''}`);
      if (v.credentialsTried.length) lines.push(`    Credentials: ${v.credentialsTried.map((c) => `${c.username} / ${c.password}`).join(', ')}`);
      v.actions.forEach((a) => lines.push(`    [${new Date(a.at).toLocaleTimeString()}] ${a.severity.toUpperCase()} ${a.detail}`));
    });
  }
  lines.push('');
  lines.push('RECOMMENDED ACTIONS');
  report.recommendedActions.forEach((a, i) => lines.push(`  ${i + 1}. ${a}`));
  return lines.join('\n');
}
