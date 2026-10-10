import React, { useState } from 'react';
import { PortScanResult, ScanResponse, CVEItem } from '../types/scanner';
import { Search, Shield, AlertTriangle, ExternalLink, ShieldCheck, Clock, CheckCircle, SlidersHorizontal, ChevronDown, X, RotateCcw } from 'lucide-react';

interface ResultsTableProps {
  scan: ScanResponse;
  onSelectPort: (port: PortScanResult) => void;
  onSelectCve: (cve: CVEItem, port: PortScanResult) => void;
}

export const ResultsTable: React.FC<ResultsTableProps> = ({ scan, onSelectPort, onSelectCve }) => {
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'OPEN' | 'CLOSED'>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [showFilters, setShowFilters] = useState<boolean>(false);

  const filteredPorts = scan.ports.filter((p) => {
    // Status filter
    if (filterStatus === 'OPEN' && p.status !== 'OPEN') return false;
    if (filterStatus === 'CLOSED' && p.status === 'OPEN') return false;

    // Severity filter
    if (filterSeverity !== 'ALL' && p.riskLevel !== filterSeverity) return false;

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchPort = p.port.toString().includes(q);
      const matchService = p.service.toLowerCase().includes(q);
      const matchBanner = p.banner?.toLowerCase().includes(q) || false;
      const matchCve = p.vulnerabilities.some(c => c.id.toLowerCase().includes(q) || c.title.toLowerCase().includes(q));
      if (!matchPort && !matchService && !matchBanner && !matchCve) return false;
    }

    return true;
  });

  const activeFiltersCount = (filterStatus !== 'ALL' ? 1 : 0) + (filterSeverity !== 'ALL' ? 1 : 0);

  const resetFilters = () => {
    setFilterStatus('ALL');
    setFilterSeverity('ALL');
    setSearchQuery('');
  };

  const getSeverityCount = (sev: string) => {
    if (sev === 'ALL') return scan.ports.length;
    return scan.ports.filter(p => p.riskLevel === sev).length;
  };

  return (
    <div className="space-y-6">
      
      {/* Executive Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        
        {/* Metric 1 */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-xs font-mono uppercase text-slate-400">Total Ports Probed</div>
          <div className="mt-2 text-2xl font-bold font-mono text-white tabular-nums">
            {scan.totalPortsScanned}
          </div>
          <div className="mt-1 text-xs text-slate-400 flex items-center gap-1.5 font-mono">
            <Clock className="h-3.5 w-3.5 text-cyan-400" />
            <span className="tabular-nums">{scan.durationMs}ms</span> execution
          </div>
        </div>

        {/* Metric 2 */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-xs font-mono uppercase text-slate-400">Open Listening Ports</div>
          <div className={`mt-2 text-2xl font-bold font-mono tabular-nums ${scan.openPortsCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {scan.openPortsCount}
          </div>
          <div className="mt-1 text-xs text-slate-400 flex items-center gap-1.5 font-mono">
            {scan.openPortsCount > 0 ? (
              <span className="text-amber-300">Exposed to network</span>
            ) : (
              <span className="text-emerald-300">Zero public ports open</span>
            )}
          </div>
        </div>

        {/* Metric 3 */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-xs font-mono uppercase text-slate-400">Highest CVSS Score</div>
          <div className={`mt-2 text-2xl font-bold font-mono tabular-nums ${
            scan.maxCvss >= 9 ? 'text-red-400' : scan.maxCvss >= 7 ? 'text-orange-400' : scan.maxCvss > 0 ? 'text-yellow-400' : 'text-emerald-400'
          }`}>
            {scan.maxCvss > 0 ? scan.maxCvss.toFixed(1) : '0.0'}
            <span className="text-xs text-slate-400 font-normal"> / 10.0</span>
          </div>
          <div className="mt-1 text-xs text-slate-400 font-mono">
            {scan.maxCvss >= 9 ? 'Critical Remote Threat' : scan.maxCvss >= 7 ? 'High Risk Exposure' : scan.maxCvss > 0 ? 'Medium/Low Severity' : 'No Flaws Found'}
          </div>
        </div>

        {/* Metric 4 */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="text-xs font-mono uppercase text-slate-400">Perimeter Threat Rating</div>
          <div className={`mt-2 text-2xl font-bold font-mono ${
            scan.overallRisk === 'CRITICAL' ? 'text-red-400' :
            scan.overallRisk === 'HIGH' ? 'text-orange-400' :
            scan.overallRisk === 'MEDIUM' ? 'text-yellow-400' :
            'text-emerald-400'
          }`}>
            {scan.overallRisk}
          </div>
          <div className="mt-1 text-xs text-slate-400 font-mono">
            Engine: {scan.engine}
          </div>
        </div>

      </div>

      {/* Refined Search Bar & Collapsible Filters Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3 sm:p-4 space-y-3">
        
        {/* Main Toolbar Row: Refined Search Bar + Filter Trigger */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          
          {/* Refined Search Bar */}
          <div className="relative flex-1 group">
            <div className="flex items-center w-full rounded-lg border border-slate-800 bg-slate-950/80 transition-all duration-150 group-focus-within:border-cyan-500 group-focus-within:ring-2 group-focus-within:ring-cyan-500/20">
              <div className="pl-3 pr-2 text-slate-500 group-focus-within:text-cyan-400 transition-colors">
                <Search className={`h-4 w-4 ${searchQuery ? 'text-cyan-400' : 'text-slate-500'}`} />
              </div>
              <input
                type="text"
                placeholder="Search ports, services, banners, or CVE IDs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-transparent py-2 pr-2 font-mono text-xs text-slate-200 placeholder-slate-500 focus:outline-none"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  aria-label="Clear port search"
                  className="p-1 mr-2 text-slate-400 hover:text-white rounded hover:bg-slate-800"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Action Buttons: Filters Toggle + Results Summary */}
          <div className="flex items-center justify-between sm:justify-end gap-2 shrink-0">
            <div className="text-xs text-slate-400 font-mono">
              Showing <span className="text-cyan-400 font-bold">{filteredPorts.length}</span> of {scan.ports.length}
            </div>

            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono transition-all border ${
                showFilters
                  ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300 shadow-sm shadow-cyan-500/10'
                  : activeFiltersCount > 0
                  ? 'bg-amber-500/10 border-amber-500/40 text-amber-300 hover:bg-amber-500/20'
                  : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700'
              }`}
            >
              <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
              <span>Filters</span>
              {activeFiltersCount > 0 && (
                <span className="text-[10px] px-1.5 py-0.2 rounded-full font-bold bg-amber-500/20 text-amber-300">
                  {activeFiltersCount}
                </span>
              )}
              <ChevronDown className={`h-3 w-3 transition-transform duration-200 ${showFilters ? 'rotate-180 text-cyan-400' : 'text-slate-400'}`} />
            </button>
          </div>

        </div>

        {/* EXPANDABLE FILTER DRAWER (Hidden until clicked) */}
        {showFilters && (
          <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3 sm:p-4 space-y-4 animate-in fade-in duration-150">
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
              <span className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider flex items-center gap-2">
                <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
                Configure Table Display Filters
              </span>
              
              <div className="flex items-center gap-2">
                {(activeFiltersCount > 0 || searchQuery) && (
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="text-xs text-slate-400 hover:text-white font-mono flex items-center gap-1 px-2 py-1 rounded hover:bg-slate-800 transition-colors"
                  >
                    <RotateCcw className="h-3 w-3" />
                    Reset All Filters
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

            {/* Filter Section: Port Status */}
            <div>
              <div className="text-[11px] font-mono uppercase text-slate-400 mb-2">
                Port Reachability Status:
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {(['ALL', 'OPEN', 'CLOSED'] as const).map((status) => (
                  <button
                    key={status}
                    type="button"
                    onClick={() => setFilterStatus(status)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-mono transition-all border ${
                      filterStatus === status
                        ? 'bg-cyan-500/20 text-cyan-300 font-bold border-cyan-500/50 shadow-sm shadow-cyan-500/10'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
                    }`}
                  >
                    {status === 'ALL' ? 'All Ports' : status === 'OPEN' ? 'Open Listening Only' : 'Closed / Filtered'}
                  </button>
                ))}
              </div>
            </div>

            {/* Filter Section: Severity Levels */}
            <div>
              <div className="text-[11px] font-mono uppercase text-slate-400 mb-2">
                Vulnerability Risk Severity:
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {[
                  { id: 'ALL', label: 'All Severities', color: 'text-slate-300 border-slate-800 bg-slate-900' },
                  { id: 'CRITICAL', label: 'Critical', color: 'text-red-400 border-red-900/60 bg-red-950/30' },
                  { id: 'HIGH', label: 'High', color: 'text-orange-400 border-orange-900/60 bg-orange-950/30' },
                  { id: 'MEDIUM', label: 'Medium', color: 'text-yellow-400 border-yellow-900/60 bg-yellow-950/30' },
                  { id: 'LOW', label: 'Low', color: 'text-blue-400 border-blue-900/60 bg-blue-950/30' },
                  { id: 'SECURE', label: 'Secure', color: 'text-emerald-400 border-emerald-900/60 bg-emerald-950/30' },
                ].map((item) => {
                  const count = getSeverityCount(item.id);
                  const isSelected = filterSeverity === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setFilterSeverity(item.id)}
                      className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-mono transition-all border ${
                        isSelected
                          ? `${item.color} ring-1 ring-cyan-400 font-bold shadow-sm`
                          : 'bg-slate-900/60 border-slate-800/80 text-slate-400 hover:text-white hover:border-slate-700'
                      }`}
                    >
                      <span>{item.label}</span>
                      <span className="text-[10px] opacity-75 tabular-nums">({count})</span>
                    </button>
                  );
                })}
              </div>
            </div>

          </div>
        )}

      </div>

      {/* Main Interactive Results Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/40">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-950/70 font-mono text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4">Port</th>
              <th className="py-3 px-4">Service</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Banner / Version</th>
              <th className="py-3 px-4">Vulnerability / CVE ID</th>
              <th className="py-3 px-4">Risk Level</th>
              <th className="py-3 px-4">Mitigation Summary</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filteredPorts.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-400">
                  No matching ports found for the selected filter criteria.
                </td>
              </tr>
            ) : (
              filteredPorts.map((p) => {
                const isOpen = p.status === 'OPEN';
                return (
                  <tr
                    key={p.port}
                    className="hover:bg-slate-800/30 transition-colors group"
                  >
                    {/* Port */}
                    <td className="py-3 px-4 font-bold text-white tabular-nums">
                      {p.port}
                      <span className="text-[11px] font-normal text-slate-400">/tcp</span>
                    </td>

                    {/* Service */}
                    <td className="py-3 px-4 font-semibold text-slate-200 uppercase">
                      {p.service}
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center gap-1.5 font-bold ${
                        isOpen ? 'text-red-400' : 'text-slate-400'
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${isOpen ? 'bg-red-400' : 'bg-slate-500'}`} />
                        {p.status}
                      </span>
                    </td>

                    {/* Banner / Version */}
                    <td className="py-3 px-4 text-slate-300 max-w-[200px] truncate" title={p.banner || 'None'}>
                      {p.version ? (
                        <span className="text-cyan-300 font-medium">{p.version}</span>
                      ) : p.banner ? (
                        <span className="text-slate-300 text-[11px]">{p.banner}</span>
                      ) : (
                        <span className="text-slate-400 italic">No banner grabbed</span>
                      )}
                    </td>

                    {/* Vulnerabilities / CVEs */}
                    <td className="py-3 px-4">
                      {p.vulnerabilities.length > 0 ? (
                        <div className="flex flex-col gap-1">
                          {p.vulnerabilities.slice(0, 2).map((cve) => (
                            <button
                              key={cve.id}
                              onClick={() => onSelectCve(cve, p)}
                              className="inline-flex items-center gap-1 text-left text-[11px] text-cyan-400 hover:text-cyan-300 hover:underline"
                            >
                              <span>{cve.id}</span>
                              <span className="text-slate-400 tabular-nums">({cve.cvss})</span>
                            </button>
                          ))}
                          {p.vulnerabilities.length > 2 && (
                            <span className="text-[10px] text-slate-400">
                              +{p.vulnerabilities.length - 2} more CVEs
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-400 flex items-center gap-1">
                          <CheckCircle className="h-3 w-3 text-emerald-400" />
                          None detected
                        </span>
                      )}
                    </td>

                    {/* Risk Level */}
                    <td className="py-3 px-4 font-bold">
                      <span className={
                        p.riskLevel === 'CRITICAL' ? 'text-red-400' :
                        p.riskLevel === 'HIGH' ? 'text-orange-400' :
                        p.riskLevel === 'MEDIUM' ? 'text-yellow-400' :
                        p.riskLevel === 'LOW' ? 'text-cyan-400' :
                        'text-emerald-400'
                      }>
                        {p.riskLevel}
                      </span>
                    </td>

                    {/* Mitigation Tip */}
                    <td className="py-3 px-4 text-slate-300 text-[11px] max-w-[240px] truncate" title={p.mitigationTip}>
                      {p.mitigationTip}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onSelectPort(p)}
                        className="inline-flex items-center gap-1 rounded border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-medium text-slate-200 hover:border-cyan-500 hover:text-cyan-300 transition-colors"
                      >
                        Inspect
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    </td>

                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

    </div>
  );
};
