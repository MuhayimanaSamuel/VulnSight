import React, { useState } from 'react';
import { KNOWN_SERVICE_CVES } from '../data/cveDatabase';
import { CVEItem } from '../types/scanner';
import { Database, Search, ShieldAlert, Wrench, Terminal, Copy, Check, SlidersHorizontal, ChevronDown, X, RotateCcw } from 'lucide-react';

export const CveDatabaseView: React.FC = () => {
  const [selectedPort, setSelectedPort] = useState<number | 'all'>('all');
  const [search, setSearch] = useState('');
  const [showFilters, setShowFilters] = useState<boolean>(false);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const allCves: { port: number; cve: CVEItem }[] = Object.entries(KNOWN_SERVICE_CVES).flatMap(
    ([portStr, cves]) => cves.map(cve => ({ port: parseInt(portStr, 10), cve }))
  );

  const filtered = allCves.filter(({ port, cve }) => {
    if (selectedPort !== 'all' && port !== selectedPort) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchId = cve.id.toLowerCase().includes(q);
      const matchTitle = cve.title.toLowerCase().includes(q);
      const matchDesc = cve.description.toLowerCase().includes(q);
      const matchVer = cve.affectedVersions.toLowerCase().includes(q);
      if (!matchId && !matchTitle && !matchDesc && !matchVer) return false;
    }
    return true;
  });

  const copyScript = (id: string, code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const resetFilters = () => {
    setSelectedPort('all');
    setSearch('');
  };

  const isPortFiltered = selectedPort !== 'all';

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <div className="max-w-2xl">
          <div className="text-xs font-mono uppercase text-cyan-400 font-semibold tracking-wider flex items-center gap-2">
            <Database className="h-4 w-4" />
            Vulnerability Knowledge Base
          </div>
          <h2 className="text-xl font-bold font-mono text-white mt-1">
            CVE Intelligence & Exploitation Remediation Library
          </h2>
          <p className="text-sm text-slate-300 mt-2">
            Pre-correlated database of high-severity CVEs for network services (FTP, SSH, HTTP, HTTPS, HTTP-Alt) with CVSS 3.1 vectors and operational hardening scripts.
          </p>
        </div>
      </div>

      {/* Refined Search Bar & Collapsible Filters Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3 sm:p-4 space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          
          {/* Refined Search Bar */}
          <div className="relative flex-1 group">
            <div className="flex items-center w-full rounded-lg border border-slate-800 bg-slate-950/80 transition-all duration-150 group-focus-within:border-cyan-500 group-focus-within:ring-2 group-focus-within:ring-cyan-500/20">
              <div className="pl-3 pr-2 text-slate-500 group-focus-within:text-cyan-400 transition-colors">
                <Search className={`h-4 w-4 ${search ? 'text-cyan-400' : 'text-slate-500'}`} />
              </div>
              <input
                type="text"
                placeholder="Search CVE ID, vulnerability title, or affected package..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-transparent py-2 pr-2 font-mono text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  aria-label="Clear CVE search"
                  className="p-1 mr-2 text-slate-400 hover:text-white rounded hover:bg-slate-800"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Action Row: Showing count + Filters toggle */}
          <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0">
            <div className="text-xs text-slate-400 font-mono">
              Showing <span className="text-cyan-400 font-bold">{filtered.length}</span> of {allCves.length} CVEs
            </div>

            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono transition-all border ${
                showFilters
                  ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 shadow-sm shadow-cyan-500/10'
                  : isPortFiltered
                  ? 'bg-amber-500/10 border-amber-500/40 text-amber-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700'
              }`}
            >
              <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
              <span>Filters</span>
              {isPortFiltered && (
                <span className="text-[10px] px-1.5 py-0.2 rounded-full font-bold bg-amber-500/20 text-amber-300">
                  Port {selectedPort}
                </span>
              )}
              <ChevronDown className={`h-3 w-3 transition-transform duration-200 ${showFilters ? 'rotate-180 text-cyan-400' : 'text-slate-400'}`} />
            </button>
          </div>

        </div>

        {/* EXPANDABLE PORT FILTERS (Hidden until clicked) */}
        {showFilters && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 sm:p-4 space-y-3 animate-in fade-in duration-150">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-2">
                <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
                Filter by Service Port
              </span>
              <div className="flex items-center gap-2">
                {(isPortFiltered || search) && (
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="text-xs text-slate-400 hover:text-white font-mono flex items-center gap-1 px-2 py-1 rounded hover:bg-slate-800"
                  >
                    <RotateCcw className="h-3 w-3" />
                    Reset
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setShowFilters(false)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-mono px-2 py-0.5 rounded bg-cyan-950/50 border border-cyan-800/60"
                >
                  Hide
                </button>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {[
                { label: 'All Ports', val: 'all' as const },
                { label: 'Port 21 (FTP)', val: 21 },
                { label: 'Port 22 (SSH)', val: 22 },
                { label: 'Port 80 (HTTP)', val: 80 },
                { label: 'Port 443 (HTTPS)', val: 443 },
                { label: 'Port 8080 (HTTP-Alt)', val: 8080 },
              ].map((item) => (
                <button
                  key={item.label}
                  type="button"
                  onClick={() => setSelectedPort(item.val)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-mono transition-all border ${
                    selectedPort === item.val
                      ? 'bg-cyan-500/20 text-cyan-300 font-bold border-cyan-500/50 shadow-sm shadow-cyan-500/10'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        )}

      </div>

      {/* CVE Grid Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map(({ port, cve }) => (
          <div
            key={cve.id}
            className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4 hover:border-slate-700 transition-colors"
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-400">
                    {cve.id}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                    Port {port}/tcp
                  </span>
                </div>
                <h4 className="font-mono text-sm font-bold text-white mt-1">
                  {cve.title}
                </h4>
              </div>

              <div className={`px-2.5 py-1 rounded-md border font-mono text-right shrink-0 ${
                cve.severity === 'CRITICAL' ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-orange-500/10 border-orange-500/30 text-orange-400'
              }`}>
                <div className="text-[9px] font-bold uppercase">{cve.severity}</div>
                <div className="text-sm font-bold tabular-nums">{cve.cvss}</div>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {cve.description}
            </p>

            <div className="text-xs font-mono text-slate-400">
              Affected: <span className="text-slate-200">{cve.affectedVersions}</span>
            </div>

            {cve.remediationSnippet && (
              <div className="border-t border-slate-800 pt-3 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                  <span className="flex items-center gap-1.5 text-emerald-400">
                    <Wrench className="h-3.5 w-3.5" />
                    Hardening Patch
                  </span>
                  <button
                    onClick={() => copyScript(cve.id, cve.remediationSnippet!.code)}
                    className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedCode === cve.id ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    {copiedCode === cve.id ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="rounded-lg bg-slate-950 p-2.5 font-mono text-[11px] text-cyan-200 overflow-x-auto leading-relaxed border border-slate-800/80">
                  {cve.remediationSnippet.code}
                </pre>
              </div>
            )}
          </div>
        ))}
      </div>

    </div>
  );
};
