import React, { useState, useEffect } from 'react';
import { Terminal, Check, Loader2, ChevronDown, ChevronUp, Copy, CheckCheck } from 'lucide-react';

interface ScanProgressProps {
  isLoading: boolean;
  target: string;
  portsCount: number;
  logs: string[];
}

const STAGES = [
  { id: 1, name: '[1/3] Gathering Recon', desc: 'Querying Nameservers, MX, TXT & WHOIS' },
  { id: 2, name: '[2/3] Port & Directory Fuzzing', desc: 'Probing TCP ports & sensitive web paths' },
  { id: 3, name: '[3/3] AI Threat Synthesis', desc: 'Gemini AI threat analysis & remediation' }
];

export const ScanProgress: React.FC<ScanProgressProps> = ({ isLoading, target, portsCount, logs }) => {
  const [currentStage, setCurrentStage] = useState(1);
  const [logsExpanded, setLogsExpanded] = useState(true);
  const [copiedLogs, setCopiedLogs] = useState(false);

  useEffect(() => {
    if (!isLoading) {
      setCurrentStage(3);
      return;
    }

    setCurrentStage(1);
    const t1 = setTimeout(() => setCurrentStage(2), 500);
    const t2 = setTimeout(() => setCurrentStage(3), 1200);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, [isLoading]);

  const copyLogsToClipboard = () => {
    navigator.clipboard.writeText(logs.join('\n'));
    setCopiedLogs(true);
    setTimeout(() => setCopiedLogs(false), 2000);
  };

  const progressPercentage = isLoading
    ? Math.min(95, Math.round((currentStage / STAGES.length) * 100))
    : 100;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 backdrop-blur-sm space-y-4">
      
      {/* Top Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin text-cyan-400" />
          ) : (
            <Check className="h-4 w-4 text-emerald-400" />
          )}
          <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-200">
            {isLoading ? `Executing Assessment on ${target}` : `Assessment Complete for ${target}`}
          </span>
          <span className="text-xs text-slate-300 font-mono">({portsCount} ports)</span>
        </div>
        <div className="font-mono text-xs font-bold text-cyan-400 tabular-nums">
          {progressPercentage}%
        </div>
      </div>

      {/* Progress Bar */}
      <div className="relative h-2 w-full overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full bg-gradient-to-r from-cyan-500 via-sky-400 to-emerald-400 transition-all duration-300 ease-out"
          style={{ width: `${progressPercentage}%` }}
        />
      </div>

      {/* Stage Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
        {STAGES.map((s) => {
          const isDone = s.id < currentStage || !isLoading;
          const isCurrent = s.id === currentStage && isLoading;

          return (
            <div
              key={s.id}
              className={`rounded-lg border p-2.5 transition-colors ${
                isCurrent
                  ? 'border-cyan-500/60 bg-cyan-950/20'
                  : isDone
                  ? 'border-slate-800 bg-slate-950/40 text-slate-300'
                  : 'border-slate-800/40 bg-slate-950/20 text-slate-400'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] text-slate-300 font-bold">
                  0{s.id}
                </span>
                {isCurrent ? (
                  <Loader2 className="h-3 w-3 animate-spin text-cyan-400" />
                ) : isDone ? (
                  <Check className="h-3 w-3 text-emerald-400" />
                ) : (
                  <span className="h-1.5 w-1.5 rounded-full bg-slate-700" />
                )}
              </div>
              <div className={`mt-1 font-mono text-xs font-medium ${isCurrent ? 'text-cyan-300' : isDone ? 'text-slate-200' : 'text-slate-400'}`}>
                {s.name}
              </div>
              <div className="text-[10px] text-slate-300 truncate mt-0.5">
                {s.desc}
              </div>
            </div>
          );
        })}
      </div>

      {/* Real-time Terminal Log Console */}
      <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-950">
        <div className="flex items-center justify-between px-3.5 py-2 bg-slate-900/80 border-b border-slate-800 text-xs">
          <div className="flex items-center gap-2 text-slate-300 font-mono">
            <Terminal className="h-3.5 w-3.5 text-cyan-400" />
            <span>Inspection Engine Log Stream ({logs.length} events)</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={copyLogsToClipboard}
              className="flex items-center gap-1 text-[11px] text-slate-300 hover:text-cyan-400 font-mono transition-colors"
              title="Copy audit log"
            >
              {copiedLogs ? <CheckCheck className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              {copiedLogs ? 'Copied' : 'Copy'}
            </button>
            <button
              onClick={() => setLogsExpanded(!logsExpanded)}
              className="text-slate-300 hover:text-white"
            >
              {logsExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
          </div>
        </div>

        {logsExpanded && (
          <div className="p-3 font-mono text-[11px] leading-relaxed text-slate-300 max-h-44 overflow-y-auto space-y-1 scrollbar-thin">
            {logs.length === 0 ? (
              <div className="text-slate-400 italic">Waiting for scan initialization...</div>
            ) : (
              logs.map((log, idx) => {
                let colorClass = 'text-slate-300';
                if (log.includes('[ERROR]') || log.includes('[DNS-FAIL]')) colorClass = 'text-red-400';
                else if (log.includes('[WAF]') || log.includes('[DNS]')) colorClass = 'text-emerald-400';
                else if (log.includes('[BANNER]') || log.includes('[ENGINE]')) colorClass = 'text-cyan-400';
                else if (log.includes('[CVE]') || log.includes('[AUDIT]')) colorClass = 'text-amber-300';
                else if (log.includes('[SUMMARY]')) colorClass = 'text-purple-300 font-semibold';

                return (
                  <div key={idx} className="flex gap-2">
                    <span className="text-slate-400 select-none tabular-nums font-mono text-[10px]">
                      {String(idx + 1).padStart(2, '0')}
                    </span>
                    <span className={colorClass}>{log}</span>
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>

    </div>
  );
};
