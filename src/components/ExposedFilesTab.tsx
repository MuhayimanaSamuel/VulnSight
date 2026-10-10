import React, { useState } from 'react';
import { AlertOctagon, ShieldAlert, CheckCircle, FileCode, Copy, Check, Lock, Wrench } from 'lucide-react';
import { DirectoryResult } from '../types/scanner';

interface ExposedFilesTabProps {
  discoveredPaths: string[];
  allDirectories: DirectoryResult[];
}

export const ExposedFilesTab: React.FC<ExposedFilesTabProps> = ({ discoveredPaths, allDirectories }) => {
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null);

  const copyCode = (key: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedSnippet(key);
    setTimeout(() => setCopiedSnippet(null), 2000);
  };

  const criticalFindings = allDirectories.filter(d => d.accessible && d.risk !== 'SECURE');

  const getRemediation = (path: string): { impact: string; snippet: string } => {
    if (path.includes('.env')) {
      return {
        impact: 'Exposes database passwords, secret JWT signing keys, and third-party SaaS API credentials.',
        snippet: '# In /etc/nginx/sites-available/default\nlocation ~ /\\.env {\n    deny all;\n    return 404;\n}'
      };
    }
    if (path.includes('.git')) {
      return {
        impact: 'Permits complete offline reconstruction of entire proprietary source code repository via git-dumper.',
        snippet: '# Deny all hidden dotfile directories\nlocation ~ /\\.(git|svn) {\n    deny all;\n    return 404;\n}'
      };
    }
    if (path.includes('admin')) {
      return {
        impact: 'Unauthenticated administrative portal directly reachable by external threat actors.',
        snippet: '# Enforce IP allowlisting on administrative paths\nlocation /admin/ {\n    allow 10.0.0.0/8;\n    deny all;\n}'
      };
    }
    if (path.includes('backup') || path.includes('dump')) {
      return {
        impact: 'Permits unauthenticated download of compressed database backups and sensitive customer records.',
        snippet: '# Block compressed backup extensions\nlocation ~* \\.(zip|tar|gz|bak|sql)$ {\n    deny all;\n}'
      };
    }
    return {
      impact: 'Informational crawler policy or public endpoint disclosure.',
      snippet: '# Restrict disallowed crawler routes\nUser-agent: *\nDisallow: /admin/\nDisallow: /private/'
    };
  };

  return (
    <div className="space-y-6">
      
      {/* Overview Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-mono uppercase text-red-400 font-semibold tracking-wider flex items-center gap-2">
            <AlertOctagon className="h-4 w-4" />
            Exposed Sensitive Assets & Files (200 OK Discovery)
          </div>
          <h3 className="text-base font-bold font-mono text-white mt-1">
            Critical Data Leakage & Secret Disclosures
          </h3>
          <p className="text-xs text-slate-300 mt-1">
            Directly discoverable administrative endpoints, secret configuration keys, and version control metadata.
          </p>
        </div>

        <div className={`px-4 py-2 rounded-lg border font-mono text-right shrink-0 ${
          criticalFindings.length > 0 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
        }`}>
          <div className="text-[10px] uppercase font-bold">200 OK Leaks Found</div>
          <div className="text-xl font-bold tabular-nums">{criticalFindings.length} Active Files</div>
        </div>
      </div>

      {/* Findings List */}
      {criticalFindings.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-950 p-8 text-center space-y-2">
          <CheckCircle className="h-8 w-8 text-emerald-400 mx-auto" />
          <h4 className="font-mono text-sm font-bold text-white">No Sensitive File Exposures Detected</h4>
          <p className="text-xs text-slate-400">
            Common critical paths (/.env, /admin/, /.git/HEAD, /backup.zip) returned 404/403 responses.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {criticalFindings.map((item) => {
            const { impact, snippet } = getRemediation(item.path);

            return (
              <div
                key={item.path}
                className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 hover:border-slate-700 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-sm font-bold text-white flex items-center gap-2">
                      <FileCode className="h-4 w-4 text-cyan-400" />
                      {item.path}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-red-950 border border-red-800 text-red-300">
                      HTTP {item.statusCode} OK
                    </span>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className={`px-2 py-0.5 rounded font-bold ${
                      item.risk === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border border-red-500/30' :
                      item.risk === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {item.risk} RISK
                    </span>
                    <span className="text-slate-400 tabular-nums">
                      {item.contentLength > 0 ? `${item.contentLength} Bytes` : ''}
                    </span>
                  </div>
                </div>

                {/* Threat Impact */}
                <div>
                  <div className="text-xs font-mono text-slate-400 uppercase mb-1">Threat Impact:</div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">{impact}</p>
                </div>

                {/* Hardening Snippet */}
                <div className="rounded-lg bg-slate-950 p-3.5 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                      <Wrench className="h-3.5 w-3.5" />
                      Administrator Remediation (Web Server Directive):
                    </span>
                    <button
                      onClick={() => copyCode(item.path, snippet)}
                      className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                    >
                      {copiedSnippet === item.path ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      {copiedSnippet === item.path ? 'Copied' : 'Copy Fix'}
                    </button>
                  </div>
                  <pre className="font-mono text-xs text-cyan-200 overflow-x-auto leading-relaxed">
                    {snippet}
                  </pre>
                </div>

              </div>
            );
          })}
        </div>
      )}

    </div>
  );
};
