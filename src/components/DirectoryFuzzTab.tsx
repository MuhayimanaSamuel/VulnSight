import React, { useState } from 'react';
import { DirectoryResult } from '../types/scanner';
import { FolderSearch, AlertTriangle, ShieldCheck, CheckCircle2, Lock, Search, SlidersHorizontal, ChevronDown, X, RotateCcw } from 'lucide-react';

interface DirectoryFuzzTabProps {
  directories: DirectoryResult[];
}

export const DirectoryFuzzTab: React.FC<DirectoryFuzzTabProps> = ({ directories }) => {
  const [search, setSearch] = useState('');
  const [filterMode, setFilterMode] = useState<'ALL' | 'ACCESSIBLE' | 'CRITICAL'>('ALL');
  const [showFilters, setShowFilters] = useState(false);

  const accessibleCount = directories.filter(d => d.accessible).length;

  const filtered = directories.filter(d => {
    if (filterMode === 'ACCESSIBLE' && !d.accessible) return false;
    if (filterMode === 'CRITICAL' && (d.risk !== 'CRITICAL' && d.risk !== 'HIGH')) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchPath = d.path.toLowerCase().includes(q);
      const matchImpact = d.description.toLowerCase().includes(q);
      if (!matchPath && !matchImpact) return false;
    }
    return true;
  });

  const resetFilters = () => {
    setSearch('');
    setFilterMode('ALL');
  };

  const hasActiveFilters = filterMode !== 'ALL' || !!search;

  return (
    <div className="space-y-6">
      
      {/* Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-mono uppercase text-cyan-400 font-semibold tracking-wider flex items-center gap-2">
            <FolderSearch className="h-4 w-4" />
            Sensitive Endpoint & Directory Fuzzing
          </div>
          <h3 className="text-base font-bold font-mono text-white mt-1">
            Web Perimeter Exposure Assessment
          </h3>
          <p className="text-xs text-slate-300 mt-1">
            Automated probing of high-risk web paths to identify unauthenticated administrative interfaces, source code repositories, and configuration leaks.
          </p>
        </div>

        <div className={`px-4 py-2 rounded-lg border font-mono text-right shrink-0 ${
          accessibleCount > 0 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
        }`}>
          <div className="text-[10px] uppercase font-bold">Endpoints Exposed</div>
          <div className="text-xl font-bold tabular-nums">{accessibleCount} / {directories.length}</div>
        </div>
      </div>

      {/* Refined Search Bar & Collapsible Filters */}
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
                placeholder="Search sensitive paths (e.g. .env, /admin, .git, config)..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-transparent py-2 pr-2 font-mono text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  aria-label="Clear path search"
                  className="p-1 mr-2 text-slate-400 hover:text-white rounded hover:bg-slate-800"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Action Row */}
          <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0">
            <div className="text-xs text-slate-400 font-mono">
              Showing <span className="text-cyan-400 font-bold">{filtered.length}</span> of {directories.length}
            </div>

            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono transition-all border ${
                showFilters
                  ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 shadow-sm shadow-cyan-500/10'
                  : filterMode !== 'ALL'
                  ? 'bg-amber-500/10 border-amber-500/40 text-amber-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700'
              }`}
            >
              <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
              <span>Filters</span>
              {filterMode !== 'ALL' && (
                <span className="text-[10px] px-1.5 py-0.2 rounded-full font-bold bg-amber-500/20 text-amber-300">
                  1
                </span>
              )}
              <ChevronDown className={`h-3 w-3 transition-transform duration-200 ${showFilters ? 'rotate-180 text-cyan-400' : 'text-slate-400'}`} />
            </button>
          </div>

        </div>

        {/* EXPANDABLE FILTER CONTROLS (Hidden until clicked) */}
        {showFilters && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 sm:p-4 space-y-3 animate-in fade-in duration-150">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-2">
                <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
                Filter Discovered Web Endpoints
              </span>
              <div className="flex items-center gap-2">
                {hasActiveFilters && (
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
                { id: 'ALL' as const, label: 'All Endpoints', count: directories.length },
                { id: 'ACCESSIBLE' as const, label: '200 OK Exposed Only', count: accessibleCount },
                { id: 'CRITICAL' as const, label: 'High & Critical Risk Only', count: directories.filter(d => d.risk === 'CRITICAL' || d.risk === 'HIGH').length },
              ].map((m) => {
                const isSelected = filterMode === m.id;
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => setFilterMode(m.id)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                      isSelected
                        ? 'bg-cyan-500/20 text-cyan-300 font-bold border-cyan-500/50 shadow-sm shadow-cyan-500/10'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                    }`}
                  >
                    <span>{m.label}</span>
                    <span className="text-[10px] opacity-75 tabular-nums">({m.count})</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

      </div>

      {/* Directory Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/70 font-mono text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4">Endpoint Path</th>
              <th className="py-3 px-4">Status Code</th>
              <th className="py-3 px-4">Accessibility</th>
              <th className="py-3 px-4">Risk Severity</th>
              <th className="py-3 px-4">Exposure Impact</th>
              <th className="py-3 px-4 text-right">Payload Size</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-400 font-mono">
                  No endpoints found matching your filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((dir) => {
              return (
                <tr key={dir.path} className="hover:bg-slate-800/30 transition-colors">
                  
                  {/* Path */}
                  <td className="py-3 px-4 font-bold text-white flex items-center gap-2">
                    <span className="text-cyan-400">{dir.path}</span>
                  </td>

                  {/* Status Code */}
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      dir.statusCode === 200 ? 'bg-red-950 text-red-300 border border-red-800' :
                      dir.statusCode === 403 ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                      dir.statusCode === 404 ? 'bg-slate-800 text-slate-400' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {dir.statusCode > 0 ? `${dir.statusCode} ${dir.statusCode === 200 ? 'OK' : dir.statusCode === 403 ? 'Forbidden' : 'Not Found'}` : 'Unreachable'}
                    </span>
                  </td>

                  {/* Accessible */}
                  <td className="py-3 px-4">
                    {dir.accessible ? (
                      <span className="inline-flex items-center gap-1.5 text-red-400 font-bold">
                        <AlertTriangle className="h-3.5 w-3.5" />
                        Accessible
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-slate-400">
                        <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                        Blocked / 404
                      </span>
                    )}
                  </td>

                  {/* Risk */}
                  <td className="py-3 px-4 font-bold">
                    <span className={
                      dir.risk === 'CRITICAL' ? 'text-red-400' :
                      dir.risk === 'HIGH' ? 'text-orange-400' :
                      dir.risk === 'MEDIUM' ? 'text-yellow-400' :
                      dir.risk === 'LOW' ? 'text-cyan-400' :
                      'text-emerald-400'
                    }>
                      {dir.risk}
                    </span>
                  </td>

                  {/* Description */}
                  <td className="py-3 px-4 text-slate-300 text-[11px]">
                    {dir.description}
                  </td>

                  {/* Content Length */}
                  <td className="py-3 px-4 text-right text-slate-400 tabular-nums">
                    {dir.contentLength > 0 ? `${dir.contentLength} B` : '—'}
                  </td>

                </tr>
              );
            }))}
          </tbody>
        </table>
      </div>

    </div>
  );
};
