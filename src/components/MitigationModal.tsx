import React, { useState } from 'react';
import { X, ShieldAlert, Check, Copy, Terminal, ExternalLink, AlertOctagon, Wrench } from 'lucide-react';
import { CVEItem, PortScanResult } from '../types/scanner';

interface MitigationModalProps {
  port: PortScanResult | null;
  initialCve?: CVEItem | null;
  onClose: () => void;
}

export const MitigationModal: React.FC<MitigationModalProps> = ({ port, initialCve, onClose }) => {
  if (!port) return null;

  const [selectedCve, setSelectedCve] = useState<CVEItem | null>(
    initialCve || (port.vulnerabilities.length > 0 ? port.vulnerabilities[0] : null)
  );
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="relative w-full max-w-3xl rounded-xl border border-slate-800 bg-slate-900 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg border ${
              port.riskLevel === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
              port.riskLevel === 'HIGH' ? 'bg-orange-500/10 border-orange-500/30 text-orange-400' :
              port.riskLevel === 'MEDIUM' ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400' :
              'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
            }`}>
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-mono text-base font-bold text-white flex items-center gap-2">
                Port {port.port}/tcp - {port.service.toUpperCase()}
                <span className={`text-xs px-2 py-0.5 rounded font-mono ${
                  port.status === 'OPEN' ? 'bg-red-950/60 text-red-400 border border-red-800/60' : 'bg-slate-800 text-slate-400'
                }`}>
                  {port.status}
                </span>
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Latency: {port.latencyMs}ms · Banner: {port.banner || 'None detected'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {/* CVE Selection Tabs if multiple */}
          {port.vulnerabilities.length > 0 && (
            <div>
              <div className="text-xs font-mono uppercase text-slate-400 mb-2">
                Associated CVE Advisory Records ({port.vulnerabilities.length})
              </div>
              <div className="flex flex-wrap gap-2">
                {port.vulnerabilities.map((cve) => (
                  <button
                    key={cve.id}
                    onClick={() => setSelectedCve(cve)}
                    className={`rounded-lg border px-3 py-1.5 text-xs font-mono transition-colors flex items-center gap-2 ${
                      selectedCve?.id === cve.id
                        ? 'border-cyan-500 bg-cyan-950/40 text-cyan-300 font-bold'
                        : 'border-slate-800 bg-slate-950/50 text-slate-400 hover:border-slate-700 hover:text-white'
                    }`}
                  >
                    <span>{cve.id}</span>
                    <span className={`text-[10px] px-1 rounded ${
                      cve.severity === 'CRITICAL' ? 'bg-red-900/50 text-red-300' : 'bg-orange-900/50 text-orange-300'
                    }`}>
                      {cve.cvss}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Active CVE Details or Default Port Assessment */}
          {selectedCve ? (
            <div className="space-y-5 rounded-xl border border-slate-800 bg-slate-950/60 p-5">
              
              {/* CVE Title & CVSS Vector */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <h4 className="font-mono text-base font-bold text-white flex items-center gap-2">
                    {selectedCve.title}
                  </h4>
                  <div className="text-xs text-slate-400 font-mono mt-1">
                    Affected Scope: <span className="text-slate-200">{selectedCve.affectedVersions}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <div className={`px-3 py-1.5 rounded-lg border font-mono text-center ${
                    selectedCve.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/40 text-red-400' : 'bg-orange-500/10 border-orange-500/40 text-orange-400'
                  }`}>
                    <div className="text-[10px] uppercase font-bold tracking-wider">{selectedCve.severity}</div>
                    <div className="text-lg font-bold tabular-nums">{selectedCve.cvss} / 10.0</div>
                  </div>
                </div>
              </div>

              {/* CVSS Vector String */}
              {selectedCve.vector && (
                <div className="text-xs font-mono text-slate-400 flex items-center gap-2 bg-slate-900/80 px-3 py-1.5 rounded-md border border-slate-800/80">
                  <span className="text-slate-500">Vector:</span>
                  <code className="text-cyan-400">{selectedCve.vector}</code>
                </div>
              )}

              {/* Description */}
              <div>
                <div className="text-xs font-mono uppercase text-slate-400 mb-1 flex items-center gap-1.5">
                  <AlertOctagon className="h-3.5 w-3.5 text-amber-400" />
                  Vulnerability Description & Impact
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">
                  {selectedCve.description}
                </p>
              </div>

              {/* Mitigation Guidance */}
              <div>
                <div className="text-xs font-mono uppercase text-slate-400 mb-1 flex items-center gap-1.5">
                  <Wrench className="h-3.5 w-3.5 text-emerald-400" />
                  Remediation & Hardening Steps
                </div>
                <p className="text-sm text-emerald-400 font-medium">
                  {selectedCve.mitigation}
                </p>
              </div>

              {/* Code Snippet / Fix Command */}
              {selectedCve.remediationSnippet && (
                <div>
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
                    <span className="flex items-center gap-1.5">
                      <Terminal className="h-3.5 w-3.5 text-cyan-400" />
                      Remediation Script ({selectedCve.remediationSnippet.language})
                    </span>
                    <button
                      onClick={() => copyCode(selectedCve.remediationSnippet!.code)}
                      className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      {copiedSnippet ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      {copiedSnippet ? 'Copied' : 'Copy Script'}
                    </button>
                  </div>
                  <pre className="rounded-lg border border-slate-800 bg-slate-900 p-3.5 font-mono text-xs text-cyan-200 overflow-x-auto leading-relaxed">
                    {selectedCve.remediationSnippet.code}
                  </pre>
                  <p className="text-xs text-slate-400 mt-1.5 italic">
                    {selectedCve.remediationSnippet.explanation}
                  </p>
                </div>
              )}

            </div>
          ) : (
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5 space-y-3">
              <h4 className="font-mono text-sm font-bold text-white flex items-center gap-2">
                <Wrench className="h-4 w-4 text-cyan-400" />
                Service Hardening Guidance
              </h4>
              <p className="text-sm text-slate-300">
                {port.mitigationTip}
              </p>
              <div className="rounded-lg border border-slate-800 bg-slate-900 p-3 font-mono text-xs text-slate-300">
                # Recommended iptables firewall rule to restrict port {port.port} access:{"\n"}
                sudo iptables -A INPUT -p tcp --dport {port.port} -s 10.0.0.0/8 -j ACCEPT{"\n"}
                sudo iptables -A INPUT -p tcp --dport {port.port} -j DROP
              </div>
            </div>
          )}

        </div>

        {/* Modal Footer */}
        <div className="border-t border-slate-800 bg-slate-950 px-6 py-3.5 flex items-center justify-between">
          <span className="text-xs text-slate-500 font-mono">
            VulnSight DevSecOps Advisory
          </span>
          <button
            onClick={onClose}
            className="rounded-lg bg-slate-800 px-4 py-1.5 text-xs font-mono font-medium text-slate-200 hover:bg-slate-700 transition-colors"
          >
            Close Inspector
          </button>
        </div>

      </div>
    </div>
  );
};
