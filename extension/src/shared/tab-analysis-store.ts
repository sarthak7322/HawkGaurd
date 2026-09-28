import type { ScamAnalysis } from './types';

const DEFAULT_MAX_TABS = 50;

export class TabAnalysisStore {
  private readonly analyses = new Map<number, ScamAnalysis>();
  private selectedTabId: number | undefined;
  private activeAnalysis: ScamAnalysis | undefined;

  constructor(private readonly maxTabs = DEFAULT_MAX_TABS) {}

  get(tabId: number): ScamAnalysis | undefined {
    return this.analyses.get(tabId);
  }

  get selectedTab(): number | undefined {
    return this.selectedTabId;
  }

  get current(): ScamAnalysis | undefined {
    return this.activeAnalysis;
  }

  set(tabId: number, analysis: ScamAnalysis): boolean {
    this.analyses.delete(tabId);
    this.analyses.set(tabId, analysis);
    while (this.analyses.size > this.maxTabs) {
      const oldestTabId = this.analyses.keys().next().value;
      if (oldestTabId === undefined) break;
      this.analyses.delete(oldestTabId);
      if (this.selectedTabId === oldestTabId) {
        this.selectedTabId = undefined;
        this.activeAnalysis = undefined;
      }
    }
    if (this.selectedTabId !== tabId) return false;
    this.activeAnalysis = analysis;
    return true;
  }

  select(tabId: number): ScamAnalysis | undefined {
    this.selectedTabId = tabId;
    this.activeAnalysis = this.analyses.get(tabId);
    return this.activeAnalysis;
  }

  setPasted(analysis: ScamAnalysis): void {
    this.selectedTabId = undefined;
    this.activeAnalysis = analysis;
  }

  remove(tabId: number): boolean {
    this.analyses.delete(tabId);
    if (this.selectedTabId !== tabId) return false;
    this.selectedTabId = undefined;
    this.activeAnalysis = undefined;
    return true;
  }

  restore(value: unknown): void {
    this.analyses.clear();
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return;
    const entries = Object.entries(value);
    for (const [key, analysis] of entries.slice(-this.maxTabs)) {
      const tabId = Number(key);
      if (!Number.isSafeInteger(tabId) || tabId < 0 || !isScamAnalysis(analysis)) continue;
      this.analyses.set(tabId, analysis);
    }
  }

  serialize(): Record<string, ScamAnalysis> {
    return Object.fromEntries(this.analyses);
  }
}

export function analysisIdentity(analysis: ScamAnalysis): string {
  if (analysis.caseId) return analysis.caseId;
  return JSON.stringify([
    analysis.timestamp,
    analysis.url,
    analysis.score,
    analysis.overallSeverity,
    analysis.suspicionReasons,
    analysis.findings.map((finding) => finding.id),
  ]);
}

function isScamAnalysis(value: unknown): value is ScamAnalysis {
  if (typeof value !== 'object' || value === null) return false;
  const analysis = value as Partial<ScamAnalysis>;
  return typeof analysis.url === 'string'
    && typeof analysis.hostname === 'string'
    && (analysis.caseId === undefined || typeof analysis.caseId === 'string')
    && typeof analysis.timestamp === 'number'
    && typeof analysis.score === 'number'
    && ['safe', 'caution', 'threat', 'unknown'].includes(String(analysis.overallSeverity))
    && Array.isArray(analysis.findings)
    && Array.isArray(analysis.suspicionReasons);
}
