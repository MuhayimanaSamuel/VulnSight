import React, { useState } from 'react';
import { Network, Copy, Check, Search, ExternalLink, ShieldAlert, Globe, Server, SlidersHorizontal, ChevronDown, X, RotateCcw } from 'lucide-react';

interface SubdomainMapProps {
  subdomains: string[];
  target: string;
}

const CATEGORIES = [
  { id: 'ALL', label: 'All Subdomains' },
  { id: 'Administrative Ingress', label: 'Admin / VPN Ingress' },
  { id: 'Pre-Production / Dev', label: 'Dev & Staging' },
  { id: 'API Infrastructure', label: 'API & Gateways' },
  { id: 'Mail Exchange', label: 'Mail Servers' },
  { id: 'Edge / Public Web', label: 'Edge & Public' },
];

export const SubdomainMap: React.FC<SubdomainMapProps> = ({ subdomains, target }) => {
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [showFilters, setShowFilters] = useState<boolean>(false);
  const [copied, setCopied] = useState(false);

  const categorizeSubdomain = (name: string): { category: string; badgeColor: string } => {
    if (name.includes('admin') || name.includes('panel') || name.includes('vpn')) {
      return { category: 'Administrative Ingress', badgeColor: 'bg-red-950 text-red-300 border-red-800' };
    }
    if (name.includes('dev') || name.includes('staging') || name.includes('test') || name.includes('sandbox')) {
      return { category: 'Pre-Production / Dev', badgeColor: 'bg-amber-950 text-amber-300 border-amber-800' };
    }
    if (name.includes('api') || name.includes('graphql') || name.includes('gateway')) {
      return { category: 'API Infrastructure', badgeColor: 'bg-cyan-950 text-cyan-300 border-cyan-800' };
    }
    if (name.includes('mail') || name.includes('smtp') || name.includes('mx')) {
      return { category: 'Mail Exchange', badgeColor: 'bg-purple-950 text-purple-300 border-purple-800' };
    }
    return { category: 'Edge / Public Web', badgeColor: 'bg-slate-800 text-slate-300 border-slate-700' };
  };

  const filtered = subdomains.filter(s => {
    if (selectedCategory !== 'ALL') {
      const { category } = categorizeSubdomain(s);
      if (category !== selectedCategory) return false;
    }
    if (search.trim()) {
      return s.toLowerCase().includes(search.toLowerCase());
    }
    return true;
  });

  const getCategoryCount = (catId: string) => {
    if (catId === 'ALL') return subdomains.length;
    return subdomains.filter(s => categorizeSubdomain(s).category === catId).length;
  };

  const copyAll = () => {
    navigator.clipboard.writeText(subdomains.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const resetFilters = () => {
    setSearch('');
    setSelectedCategory('ALL');
  };

  const hasActiveFilters = selectedCategory !== 'ALL' || !!search;

  return (
    <div className="space-y-6">
      
      {/* Overview Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-mono uppercase text-cyan-400 font-semibold tracking-wider flex items-center gap-2">
            <Network className="h-4 w-4" />
            Passive Certificate Transparency Subdomain Map (CRT.sh)
          </div>
          <h3 className="text-base font-bold font-mono text-white mt-1">
            Extended Subdomain Perimeter for {target}
          </h3>
          <p className="text-xs text-slate-300 mt-1">
            Historical public SSL/TLS certificate transparency records scraped without sending a single active packet to target hosts.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={copyAll}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-xs font-mono text-slate-200 hover:text-white hover:border-slate-600 transition-colors"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-cyan-400" />}
            {copied ? 'Copied All' : `Copy All (${subdomains.length})`}
          </button>
          <div className="px-3.5 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/20 text-cyan-300 font-mono text-xs font-bold tabular-nums">
            {subdomains.length} Total Discovered
          </div>
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
                placeholder="Search subdomains (e.g. dev, api, admin, vpn)..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-transparent py-2 pr-2 font-mono text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  aria-label="Clear subdomain search"
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
              Showing <span className="text-cyan-400 font-bold">{filtered.length}</span> of {subdomains.length}
            </div>

            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono transition-all border ${
                showFilters
                  ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 shadow-sm shadow-cyan-500/10'
                  : selectedCategory !== 'ALL'
                  ? 'bg-amber-500/10 border-amber-500/40 text-amber-300'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700'
              }`}
            >
              <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
              <span>Filters</span>
              {selectedCategory !== 'ALL' && (
                <span className="text-[10px] px-1.5 py-0.2 rounded-full font-bold bg-amber-500/20 text-amber-300">
                  1
                </span>
              )}
              <ChevronDown className={`h-3 w-3 transition-transform duration-200 ${showFilters ? 'rotate-180 text-cyan-400' : 'text-slate-400'}`} />
            </button>
          </div>

        </div>

        {/* EXPANDABLE CATEGORY FILTERS (Hidden until clicked) */}
        {showFilters && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 sm:p-4 space-y-3 animate-in fade-in duration-150">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <span className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-2">
                <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
                Filter by Perimeter Role / Category
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
              {CATEGORIES.map((cat) => {
                const isSelected = selectedCategory === cat.id;
                const count = getCategoryCount(cat.id);
                return (
                  <button
                    key={cat.id}
                    type="button"
                    onClick={() => setSelectedCategory(cat.id)}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-all border ${
                      isSelected
                        ? 'bg-cyan-500/20 text-cyan-300 font-bold border-cyan-500/50 shadow-sm shadow-cyan-500/10'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                    }`}
                  >
                    <span>{cat.label}</span>
                    <span className="text-[10px] opacity-75 tabular-nums">({count})</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

      </div>

      {/* Subdomain Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.map((sub, idx) => {
          const { category, badgeColor } = categorizeSubdomain(sub);
          const isRoot = sub === target;

          return (
            <div
              key={idx}
              className={`rounded-lg border p-3 font-mono transition-colors ${
                isRoot
                  ? 'border-cyan-500/50 bg-cyan-950/30'
                  : 'border-slate-800/80 bg-slate-950/60 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${badgeColor}`}>
                  {category}
                </span>
                <span className="text-[10px] text-slate-500 tabular-nums">
                  #{String(idx + 1).padStart(2, '0')}
                </span>
              </div>

              <div className="mt-2 text-xs font-bold text-white truncate flex items-center gap-1.5" title={sub}>
                <Globe className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                <span className="truncate">{sub}</span>
              </div>

              <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-400">
                <span className="flex items-center gap-1">
                  <Server className="h-3 w-3 text-slate-500" />
                  CRT.sh Indexed
                </span>
                <span className="text-slate-500">Zero Active Packets</span>
              </div>
            </div>
          );
        })}
      </div>

    </div>
  );
};
