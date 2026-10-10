/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Header, AppTab } from './components/Header';
import { ScanForm } from './components/ScanForm';
import { ScanProgress } from './components/ScanProgress';
import { ResultsTable } from './components/ResultsTable';
import { ReconTab } from './components/ReconTab';
import { DirectoryFuzzTab } from './components/DirectoryFuzzTab';
import { AiAdviceTab } from './components/AiAdviceTab';
import { MitigationModal } from './components/MitigationModal';
import { ArchitectureView } from './components/ArchitectureView';
import { DocsView } from './components/DocsView';
import { ScanResponse, PortScanResult, CVEItem } from './types/scanner';
import { Shield, AlertTriangle, Terminal, ArrowRight, Sparkles, FolderSearch, Globe, Layers } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<AppTab>('scanner');
  const [isLoading, setIsLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [currentLogs, setCurrentLogs] = useState<string[]>([]);
  const [lastTarget, setLastTarget] = useState('demo-lab.vulnsight.local');
  const [lastPortsCount, setLastPortsCount] = useState(8);
  const [rateLimitRemaining, setRateLimitRemaining] = useState(12);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Inspector Modal State
  const [inspectingPort, setInspectingPort] = useState<PortScanResult | null>(null);
  const [inspectingCve, setInspectingCve] = useState<CVEItem | null>(null);

  // Poll rate limit status
  useEffect(() => {
    fetchRateLimit();
  }, []);

  const fetchRateLimit = async () => {
    try {
      const res = await fetch('/api/rate-limit-status');
      if (res.ok) {
        const data = await res.json();
        if (typeof data.remaining === 'number') {
          setRateLimitRemaining(data.remaining);
        }
      }
    } catch {}
  };

  const handleExecuteScan = async (target: string, ports: number[]) => {
    setIsLoading(true);
    setErrorMessage(null);
    setLastTarget(target);
    setLastPortsCount(ports.length);

    const startLogs = [
      `[1/3] Gathering Recon: Initializing DNS & WHOIS audit for '${target}'`,
      `[WAF] Input verification passed: Shell command injection metacharacters clean.`,
      `[2/3] Fuzzing: Dispatching socket probes across ${ports.length} ports and sensitive paths...`
    ];
    setCurrentLogs(startLogs);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, ports })
      });

      const data = await response.json();

      if (!response.ok) {
        setErrorMessage(data.message || data.error || 'Failed to complete security scan.');
        setCurrentLogs(prev => [...prev, `[ERROR] Scan terminated: ${data.message || data.error}`]);
        if (response.status === 429) setRateLimitRemaining(0);
        return;
      }

      setScanResult(data);
      setCurrentLogs(data.logs || []);
      if (data.securityAudit?.rateLimitRemaining !== undefined) {
        setRateLimitRemaining(data.securityAudit.rateLimitRemaining);
      }
    } catch (err: any) {
      setErrorMessage(`Network error connecting to VulnSight Gateway: ${err.message}`);
      setCurrentLogs(prev => [...prev, `[CRITICAL] Network dispatch failure: ${err.message}`]);
    } finally {
      setIsLoading(false);
      fetchRateLimit();
    }
  };

  const openPortInspector = (port: PortScanResult) => {
    setInspectingPort(port);
    setInspectingCve(port.vulnerabilities.length > 0 ? port.vulnerabilities[0] : null);
  };

  const openCveInspector = (cve: CVEItem, port: PortScanResult) => {
    setInspectingPort(port);
    setInspectingCve(cve);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        lastScan={scanResult}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 sm:py-8 space-y-6">
        
        {/* Tab Selection Bar (for quick in-page switching when scan results exist) */}
        {scanResult && !isLoading && (
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
            {[
              { id: 'scanner' as const, label: 'Master Dashboard', icon: Terminal },
              { id: 'recon' as const, label: 'DNS & WHOIS Recon', icon: Globe },
              { id: 'ports-dirs' as const, label: 'Ports & Sensitive Endpoints', icon: FolderSearch },
              { id: 'ai-advice' as const, label: 'Gemini AI Threat Report', icon: Sparkles },
              { id: 'architecture' as const, label: 'Two-Folder Architecture', icon: Layers },
            ].map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                    activeTab === t.id
                      ? 'bg-cyan-500/10 border border-cyan-500/40 text-cyan-300 font-bold'
                      : 'bg-slate-900/60 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {t.label}
                </button>
              );
            })}
          </div>
        )}

        {/* Tab 1: Scanner Main Overview */}
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            <ScanForm
              onScan={handleExecuteScan}
              isLoading={isLoading}
              rateLimitRemaining={rateLimitRemaining}
            />

            {errorMessage && (
              <div className="rounded-xl border border-red-500/40 bg-red-950/30 p-4 text-sm text-red-300 font-mono flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-red-400">Security Gate Block / Scan Error</div>
                  <div className="mt-1 text-xs text-red-200/90">{errorMessage}</div>
                </div>
              </div>
            )}

            {(isLoading || currentLogs.length > 0) && (
              <ScanProgress
                isLoading={isLoading}
                target={lastTarget}
                portsCount={lastPortsCount}
                logs={currentLogs}
              />
            )}

            {scanResult && !isLoading && (
              <div className="space-y-6">
                <ResultsTable
                  scan={scanResult}
                  onSelectPort={openPortInspector}
                  onSelectCve={openCveInspector}
                />
              </div>
            )}

            {!scanResult && !isLoading && (
              <div className="rounded-xl border border-slate-800/80 bg-slate-900/30 p-10 text-center space-y-4">
                <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Shield className="h-6 w-6" />
                </div>
                <div className="max-w-md mx-auto">
                  <h3 className="font-mono text-base font-bold text-white">
                    Awaiting Target Specification
                  </h3>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                    Select a target host or click below to launch the containerized DevSecOps testbed with pre-correlated CVEs, directory fuzzing, and Gemini AI remediation.
                  </p>
                </div>
                <div>
                  <button
                    onClick={() => handleExecuteScan('demo-lab.vulnsight.local', [21, 22, 23, 80, 443, 445, 3306, 8080])}
                    className="inline-flex items-center gap-2 rounded-lg bg-cyan-500/10 border border-cyan-500/40 px-4 py-2 text-xs font-mono font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-colors"
                  >
                    Run Multi-Stage Audit on Vulnerable Lab Host
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: DNS & WHOIS Recon */}
        {activeTab === 'recon' && (
          <div>
            {scanResult ? (
              <ReconTab
                recon={scanResult.recon}
                target={scanResult.target}
                subdomains={scanResult.extendedAttackSurface?.subdomains || []}
                directories={scanResult.directories}
                shodanIntel={scanResult.extendedAttackSurface?.shodanIntel}
              />
            ) : (
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-10 text-center text-xs font-mono text-slate-400">
                Execute a scan to view DNS Nameservers, MX records, TXT records, WHOIS metadata, Subdomain Map, and Exposed Files.
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Ports & Sensitive Directories */}
        {activeTab === 'ports-dirs' && (
          <div className="space-y-8">
            {scanResult ? (
              <>
                <DirectoryFuzzTab directories={scanResult.directories} />
                <div className="border-t border-slate-800 pt-6">
                  <h3 className="text-sm font-mono font-bold text-slate-300 uppercase mb-4">
                    Listening TCP Ports & Services
                  </h3>
                  <ResultsTable
                    scan={scanResult}
                    onSelectPort={openPortInspector}
                    onSelectCve={openCveInspector}
                  />
                </div>
              </>
            ) : (
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-10 text-center text-xs font-mono text-slate-400">
                Execute a scan to view probed ports and fuzzed web endpoints (/.env, /admin, /config.php, /robots.txt).
              </div>
            )}
          </div>
        )}

        {/* Tab 4: AI Exploitation & Remediation Advice */}
        {activeTab === 'ai-advice' && (
          <div>
            {scanResult ? (
              <AiAdviceTab
                advice={scanResult.aiAdvice}
                attackPathSimulation={scanResult.extendedAttackSurface?.attackPathSimulation}
              />
            ) : (
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-10 text-center text-xs font-mono text-slate-400">
                Execute a scan to generate Gemini AI exploitation analysis, Attack Path Simulation, and administrator remediation checklists.
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Two-Folder Architecture */}
        {activeTab === 'architecture' && <ArchitectureView />}

        {/* Tab 6: Docs & README */}
        {activeTab === 'docs' && <DocsView />}

      </main>

      {/* Mitigation Inspector Modal */}
      {inspectingPort && (
        <MitigationModal
          port={inspectingPort}
          initialCve={inspectingCve}
          onClose={() => {
            setInspectingPort(null);
            setInspectingCve(null);
          }}
        />
      )}

      {/* Refined Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/90 py-8 mt-16 text-slate-400 font-sans">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 space-y-6">
          {/* Notification: Strictly for Authorized Educational & Ethical Use */}
          <div className="rounded-xl border border-amber-500/25 bg-amber-950/20 p-4 sm:p-5 flex flex-col sm:flex-row items-start sm:items-center gap-3.5 shadow-sm">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
              <AlertTriangle className="h-4.5 w-4.5" />
            </div>
            <div className="space-y-1 text-xs">
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold uppercase tracking-wider text-amber-300">
                  Notification: For Authorized Educational & Ethical Research Only
                </span>
                <span className="inline-flex items-center rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-mono font-medium text-amber-400 border border-amber-500/20">
                  Legal Disclaimer
                </span>
              </div>
              <p className="text-slate-300/90 leading-relaxed font-sans text-xs">
                VulnSight is designed and provided exclusively for authorized educational purposes, defensive security research, and controlled laboratory penetration testing. Scanning networks or hosts without explicit, prior authorization from the system owner is illegal and strictly prohibited.
              </p>
            </div>
          </div>

          {/* Bottom Row: VulnSight Copyright & System Status */}
          <div className="pt-4 border-t border-slate-900/90 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center gap-2.5 text-slate-400">
              <div className="flex h-6 w-6 items-center justify-center rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Shield className="h-3.5 w-3.5" />
              </div>
              <span className="font-bold text-slate-200">VulnSight</span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-400">
                &copy; {new Date().getFullYear()} VulnSight. All rights reserved.
              </span>
            </div>

            <div className="flex items-center gap-3 text-slate-500 text-[11px]">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                Active Protection
              </span>
              <span>·</span>
              <span>Ethical Security Research Edition</span>
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}
