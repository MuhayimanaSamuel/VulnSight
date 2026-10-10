import React, { useState } from 'react';
import { AIAdvice, AttackPathSimulation } from '../types/scanner';
import { Sparkles, ShieldAlert, CheckCircle2, Copy, Check, Terminal, Shield, ArrowRight, Wrench, GitFork, ArrowDown, AlertTriangle } from 'lucide-react';

interface AiAdviceTabProps {
  advice: AIAdvice;
  attackPathSimulation?: AttackPathSimulation;
}

export const AiAdviceTab: React.FC<AiAdviceTabProps> = ({ advice, attackPathSimulation }) => {
  const [copiedItem, setCopiedItem] = useState<string | null>(null);

  const copyText = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(key);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  const simulation = attackPathSimulation || {
    stage1_Reconnaissance: "Adversaries passively query CRT.sh transparency logs and Shodan telemetry to map active developer subdomains (e.g. dev.*, admin.*) without raising perimeter IDS alerts.",
    stage2_InitialAccess: "Targeted wordlist fuzzing against the discovered subdomains uncovers exposed files such as /.env or /.git/HEAD, leaking database connection strings and secret API keys.",
    stage3_PrivilegeEscalation: "Using the harvested credentials, attackers authenticate to listening internal databases (port 3306) or cloud infrastructure, achieving persistent administrative access.",
    overallImpactRating: 'CRITICAL' as const,
    narrativeWalkthrough: "The extended attack surface demonstrates that perimeter security cannot rely on obscure hostnames alone. An adversary leverages passive certificate logs to bypass primary cloud firewalls, targets overlooked developer endpoints for credential leaks, and pivots directly into critical backend services."
  };

  return (
    <div className="space-y-6">
      
      {/* AI Header Card */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-bold uppercase tracking-wider">
              <Sparkles className="h-4 w-4 text-cyan-400" />
              AI Threat Modeling & Attack Path Simulation
            </div>
            <h2 className="text-xl font-bold font-mono text-white mt-1">
              Automated Exploitation Analysis & Defensive Blueprint
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3 py-1 rounded-full text-xs font-mono font-semibold bg-cyan-950 border border-cyan-800 text-cyan-300 flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
              Engine: {advice.engine || 'gemini-3.8-flash'}
            </span>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="rounded-lg bg-slate-950 p-4 border border-slate-800/80 space-y-1.5">
          <div className="text-xs font-mono uppercase text-slate-400 font-bold flex items-center gap-2">
            <Shield className="h-3.5 w-3.5 text-cyan-400" />
            Executive Leadership Synopsis
          </div>
          <p className="text-sm text-slate-200 leading-relaxed font-sans">
            {advice.executiveSummary || 'Audit complete. Review identified weaknesses and hardening runbooks below.'}
          </p>
        </div>
      </div>

      {/* NEW: ATTACK PATH SIMULATION (Gemini AI Feature) */}
      <div className="rounded-xl border border-red-500/40 bg-red-950/10 p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-red-500/20 pb-3">
          <div className="flex items-center gap-2 text-red-400 font-mono text-xs font-bold uppercase tracking-wider">
            <GitFork className="h-4 w-4" />
            Attack Path Simulation (Adversary Pivot Chain)
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-red-950 border border-red-800 text-red-300">
            SIMULATED IMPACT: {simulation.overallImpactRating}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
          
          {/* Stage 1 */}
          <div className="rounded-lg bg-slate-950/90 p-4 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-cyan-400 font-bold">
              <span>Phase 1: Recon & Scrape</span>
              <span className="text-[10px] text-slate-500">OSINT</span>
            </div>
            <p className="text-slate-300 font-sans text-xs leading-relaxed">
              {simulation.stage1_Reconnaissance}
            </p>
          </div>

          {/* Stage 2 */}
          <div className="rounded-lg bg-slate-950/90 p-4 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-amber-400 font-bold">
              <span>Phase 2: Initial Access</span>
              <span className="text-[10px] text-slate-500">200 OK Leaks</span>
            </div>
            <p className="text-slate-300 font-sans text-xs leading-relaxed">
              {simulation.stage2_InitialAccess}
            </p>
          </div>

          {/* Stage 3 */}
          <div className="rounded-lg bg-slate-950/90 p-4 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-red-400 font-bold">
              <span>Phase 3: Pivot & Escalate</span>
              <span className="text-[10px] text-slate-500">Internal Breach</span>
            </div>
            <p className="text-slate-300 font-sans text-xs leading-relaxed">
              {simulation.stage3_PrivilegeEscalation}
            </p>
          </div>

        </div>

        {/* Narrative Box */}
        <div className="rounded-lg bg-slate-950 p-4 border border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span className="font-bold text-slate-300">Detailed Exploit Chain Narrative:</span>
            <button
              onClick={() => copyText('sim_narrative', simulation.narrativeWalkthrough)}
              className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
            >
              {copiedItem === 'sim_narrative' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              {copiedItem === 'sim_narrative' ? 'Copied' : 'Copy Narrative'}
            </button>
          </div>
          <p className="text-xs text-slate-300 font-sans leading-relaxed">
            {simulation.narrativeWalkthrough}
          </p>
        </div>
      </div>

      {/* Educational Attack Walkthrough */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-950/10 p-6 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-amber-400 font-mono text-xs font-bold uppercase tracking-wider">
            <ShieldAlert className="h-4 w-4 text-amber-400" />
            Vulnerability Walkthrough (Adversary Perspective)
          </div>
          <button
            onClick={() => copyText('walkthrough', advice.educationalAttackWalkthrough)}
            className="flex items-center gap-1 text-xs font-mono text-amber-400 hover:text-amber-300"
          >
            {copiedItem === 'walkthrough' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {copiedItem === 'walkthrough' ? 'Copied' : 'Copy Analysis'}
          </button>
        </div>
        <p className="text-sm text-amber-200/90 leading-relaxed font-sans bg-slate-950/80 p-4 rounded-lg border border-amber-500/20">
          {advice.educationalAttackWalkthrough}
        </p>
        <div className="text-[11px] text-slate-400 italic font-mono">
          * Provided strictly for authorized defensive education to understand risk mechanics and motivate remediation.
        </div>
      </div>

      {/* Identified Vulnerabilities Matrix */}
      <div className="space-y-4">
        <h3 className="font-mono text-sm font-bold uppercase text-slate-300 flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400" />
          Correlated Vulnerability Findings ({advice.vulnerabilities?.length || 0})
        </h3>

        <div className="grid grid-cols-1 gap-4">
          {advice.vulnerabilities?.map((v, idx) => (
            <div
              key={idx}
              className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 hover:border-slate-700 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{v.cve}</span>
                    <span className="text-[10px] font-mono bg-slate-800 px-2 py-0.5 rounded text-slate-300">
                      Component: {v.affectedComponent}
                    </span>
                  </div>
                  <h4 className="font-mono text-sm font-bold text-white mt-1">{v.title}</h4>
                </div>

                <div className={`px-2.5 py-1 rounded-md border font-mono text-right shrink-0 ${
                  v.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/40 text-red-400' : 'bg-orange-500/10 border-orange-500/40 text-orange-400'
                }`}>
                  <div className="text-[9px] font-bold uppercase">{v.severity}</div>
                  <div className="text-sm font-bold tabular-nums">{v.cvss} / 10.0</div>
                </div>
              </div>

              {/* Threat Mechanic */}
              <div>
                <div className="text-xs font-mono text-slate-400 uppercase mb-1">Exploitation Risk Mechanic:</div>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">{v.exploitationMechanic}</p>
              </div>

              {/* Remediation */}
              <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                <div className="text-xs font-mono text-emerald-400 uppercase font-semibold flex items-center gap-1.5 mb-1">
                  <Wrench className="h-3.5 w-3.5" />
                  Defensive Remediation:
                </div>
                <p className="text-xs text-emerald-300 font-sans leading-relaxed">{v.remediation}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Defensive Hardening Checklist */}
      <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/10 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-emerald-400 font-mono text-xs font-bold uppercase tracking-wider">
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            Administrator Hardening Runbook
          </div>
          <button
            onClick={() => copyText('checklist', advice.defensiveHardeningChecklist?.join('\n') || '')}
            className="flex items-center gap-1 text-xs font-mono text-emerald-400 hover:text-emerald-300"
          >
            {copiedItem === 'checklist' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {copiedItem === 'checklist' ? 'Copied' : 'Copy Runbook'}
          </button>
        </div>

        <div className="space-y-2.5 font-mono text-xs">
          {advice.defensiveHardeningChecklist?.map((item, idx) => (
            <div key={idx} className="flex items-start gap-3 rounded-lg bg-slate-950 p-3 border border-slate-800/80">
              <span className="text-emerald-400 font-bold shrink-0 mt-0.5">[{idx + 1}]</span>
              <span className="text-slate-200 font-sans leading-relaxed">{item}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
};
