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

export interface PortResult {
  port: number;
  service: string;
  status: 'OPEN' | 'CLOSED' | 'FILTERED';
  banner?: string | null;
  latencyMs: number;
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

export interface FullScanResult {
  scanId: string;
  target: string;
  resolvedIp: string;
  timestamp: string;
  durationMs: number;
  recon: ReconData;
  ports: PortResult[];
  directories: DirectoryResult[];
  aiAdvice: AIAdvice;
  extendedAttackSurface?: ExtendedAttackSurface;
  logs: string[];
}
