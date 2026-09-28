// HawkGuard shared types

export type Severity = 'safe' | 'caution' | 'threat' | 'unknown';

export interface ForensicFinding {
  id: string;
  category: 'domain' | 'certificate' | 'redirect' | 'content' | 'image' | 'download';
  title: string;
  severity: Severity;
  detail: string;
  evidence?: Record<string, string | number>;
  timestamp: number;
}

export interface ScamAnalysis {
  url: string;
  hostname: string;
  overallSeverity: Severity;
  score: number;              // 0-100 threat score
  findings: ForensicFinding[];
  suspicionReasons: string[];
  timestamp: number;
}

export interface Persona {
  id: string;
  displayName: string;
  age: number;
  location: string;
  occupation: string;
  personality: string;
  writingStyle: string;
  quirks: string[];
}

export type ScamScenario =
  | 'payment_request'
  | 'otp_solicitation'
  | 'identity_verification'
  | 'urgency_escalation'
  | 'link_click_bait'
  | 'account_info_request'
  | 'personal_details_request'
  | 'reassurance_seeking'
  | 'unknown';

export interface EngagementMessage {
  id: string;
  role: 'scammer' | 'persona';
  content: string;
  scenario?: ScamScenario;
  extractedIntel?: ExtractedIntel;
  timestamp: number;
  approvedByUser?: boolean;
  template?: string;            // persona replies: the safe template the AI rewrote
  lure?: boolean;               // persona reply that hands the scammer the honeypot login
}

export interface ExtractedIntel {
  upiIds: string[];
  phoneNumbers: string[];
  urls: string[];
  bankAccounts: string[];
  emailAddresses: string[];
  names: string[];
}

export interface EngagementSession {
  id: string;
  analysisId: string;
  personaId: string;
  startedAt: number;
  endedAt?: number;
  messages: EngagementMessage[];
  aggregateIntel: ExtractedIntel;
  status: 'active' | 'completed' | 'aborted';
}

export interface ThreatReport {
  id: string;
  createdAt: number;
  scamType: string;
  confidence: 'low' | 'medium' | 'high';
  analysis: ScamAnalysis;
  engagement?: EngagementSession;
  recommendedActions: string[];
  intruders?: import('./honeypot').Intruder[]; // honeypot visitors captured during this engagement
}

export interface LinkMetadata {
  href: string;
  label: string;
}

export interface FormMetadata {
  fields: string[];
  action: string;
  method: string;
  buttonText: string;
  labelText: string;
  contextText?: string;
  contextScope?: 'fieldset' | 'form' | 'local' | 'group' | 'section' | 'article' | 'none';
}

export interface PageAnalysisContext {
  referenceContent?: boolean;
  credentialForm?: boolean;
  links?: string[];
  linkMetadata?: LinkMetadata[];
  forms?: FormMetadata[];
}

export type PanelStage = 'evidence' | 'persona' | 'engage' | 'report';

// Message types across extension surfaces
export type ExtMessage =
  | { kind: 'ANALYZE_PAGE'; payload: { url: string; text: string; html: string; context?: PageAnalysisContext } }
  | { kind: 'ANALYSIS_RESULT'; payload: ScamAnalysis }
  | { kind: 'ANALYZE_TEXT'; payload: { text: string } }
  | { kind: 'START_ENGAGEMENT'; payload: { analysisId: string; personaId: string; initialContext: string } }
  | { kind: 'SUBMIT_SCAMMER_REPLY'; payload: { sessionId: string; message: string } }
  | { kind: 'DRAFT_RESPONSE'; payload: { sessionId: string } }
  | { kind: 'APPROVE_RESPONSE'; payload: { sessionId: string; messageId: string; edited?: string; draft?: EngagementMessage } }
  | { kind: 'GENERATE_REPORT'; payload: { sessionId: string } }
  | { kind: 'GET_STATE'; payload: {} }
  | { kind: 'OPEN_PANEL'; payload?: { stage?: PanelStage } }
  | { kind: 'SET_PANEL_STAGE'; payload: { stage: PanelStage } }
  | { kind: 'CONSUME_PANEL_STAGE' }
  | { kind: 'SET_SETTINGS'; payload: Partial<HawkGuardState['settings']> }
  | { kind: 'STATE_UPDATE'; payload: HawkGuardState };

export interface HawkGuardState {
  currentAnalysis?: ScamAnalysis;
  activeSession?: EngagementSession;
  recentReports: ThreatReport[];
  settings: {
    autoScan: boolean;
    requireApproval: boolean;
    backendUrl: string;
    sound: boolean; // hawk screech when a threat is detected
  };
}
