export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'SECURE';

export interface ReconData {
  nameservers: string[];
  mx_records: { preference: number; exchange: string }[];
  txt_records: string[];
  a_records: string[];
  registrar?: string;
  createdDate?: string;
  expiresDate?: string;
  status?: string[];
}

export interface DirectoryResult {
  path: string;
  statusCode: number;
  accessible: boolean;
  description: string;
  risk: RiskLevel;
  contentLength: number;
}

export interface VulnerabilityFinding {
  cve: string;
  title: string;
  severity: RiskLevel;
  cvss: number;
  affectedComponent: string;
  exploitationMechanic: string;
  remediation: string;
}

export interface AIAdvice {
  engine: string;
  executiveSummary: string;
  vulnerabilities: VulnerabilityFinding[];
  educationalAttackWalkthrough: string;
  defensiveHardeningChecklist: string[];
}

export interface CVEItem {
  id: string;
  title: string;
  cvss: number;
  severity: RiskLevel;
  description: string;
  vector?: string;
  affectedVersions: string;
  mitigation: string;
  references?: string[];
  remediationSnippet?: {
    language: string;
    code: string;
    explanation: string;
  };
}

export interface PortScanResult {
  port: number;
  service: string;
  status: 'OPEN' | 'CLOSED' | 'FILTERED';
  banner?: string;
  version?: string;
  latencyMs: number;
  vulnerabilities: CVEItem[];
  riskLevel: RiskLevel;
  mitigationTip: string;
}

export interface ShodanIntel {
  source: string;
  ip: string;
  org: string;
  isp: string;
  ports: number[];
  vulns: string[];
  hostnames: string[];
  lastUpdate: string;
  crawlerNotes?: string;
}

export interface AttackPathSimulation {
  stage1_Reconnaissance: string;
  stage2_InitialAccess: string;
  stage3_PrivilegeEscalation: string;
  overallImpactRating: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  narrativeWalkthrough: string;
}

export interface ExtendedAttackSurface {
  subdomains: string[];
  discoveredPaths: string[];
  shodanIntel: ShodanIntel;
  attackPathSimulation?: AttackPathSimulation;
}

export interface ScanResponse {
  scanId: string;
  target: string;
  resolvedIp: string;
  timestamp: string;
  durationMs: number;
  engine: 'python-fastapi' | 'native-security-engine';
  totalPortsScanned: number;
  openPortsCount: number;
  overallRisk: RiskLevel;
  maxCvss: number;
  recon: ReconData;
  ports: PortScanResult[];
  directories: DirectoryResult[];
  aiAdvice: AIAdvice;
  extendedAttackSurface?: ExtendedAttackSurface;
  logs: string[];
  summary: {
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    secureCount: number;
  };
  securityAudit: {
    commandInjectionTested: boolean;
    ssrfProtectionActive: boolean;
    rateLimitRemaining: number;
  };
}

export interface ScanRequest {
  target: string;
  ports?: number[];
  scanType?: 'quick' | 'full' | 'banner';
}
