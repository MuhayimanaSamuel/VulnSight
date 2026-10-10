import React, { useState } from 'react';
import { Search, ShieldAlert, Cpu, CheckCircle2, AlertTriangle, Layers, RotateCcw, SlidersHorizontal, ChevronDown, ChevronUp, X, Sparkles, Server } from 'lucide-react';

interface ScanFormProps {
  onScan: (target: string, ports: number[]) => void;
  isLoading: boolean;
  rateLimitRemaining: number;
}

const PRESETS = [
  { label: 'Vulnerable Lab Host', target: 'demo-lab.vulnsight.local', desc: 'Simulated multi-tier vulnerable testbed (CVEs & Banners)' },
  { label: 'Nmap Testbed', target: 'scanme.nmap.org', desc: 'Authorized public port test server' },
  { label: 'Localhost Lab', target: 'localhost', desc: 'Active DevSecOps application port' },
  { label: 'Public Web', target: 'example.com', desc: 'Standard HTTPS 443 & HTTP 80' },
];

const AVAILABLE_PORTS = [
  { port: 21, service: 'FTP', riskHint: 'vsftpd backdoor & cleartext auth', category: 'shell' },
  { port: 22, service: 'SSH', riskHint: 'OpenSSH versioning & PKCS#11 flaws', category: 'shell' },
  { port: 23, service: 'Telnet', riskHint: 'Unencrypted cleartext credentials', category: 'shell' },
  { port: 80, service: 'HTTP', riskHint: 'Apache / Nginx path traversal', category: 'web' },
  { port: 443, service: 'HTTPS', riskHint: 'TLS & OpenSSL buffer overruns', category: 'web' },
  { port: 445, service: 'SMB', riskHint: 'SMBv1 EternalBlue worms', category: 'infra' },
  { port: 3306, service: 'MySQL', riskHint: 'Direct database exposure', category: 'db' },
  { port: 8080, service: 'HTTP-Alt', riskHint: 'Spring & Log4j2 JNDI vectors', category: 'web' },
];

export const ScanForm: React.FC<ScanFormProps> = ({ onScan, isLoading, rateLimitRemaining }) => {
  const [target, setTarget] = useState('demo-lab.vulnsight.local');
  const [selectedPorts, setSelectedPorts] = useState<number[]>([21, 22, 23, 80, 443, 445, 3306, 8080]);
  const [showFilters, setShowFilters] = useState<boolean>(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const validateTarget = (val: string): boolean => {
    const trimmed = val.trim();
    if (!trimmed) {
      setValidationError('Target IP or hostname is required.');
      return false;
    }

    // Command injection detection
    const injectionCheck = /[;&|`$><*?!{}\[\]\\]/;
    if (injectionCheck.test(trimmed)) {
      setValidationError('Security Alert: Illegal shell metacharacter detected. Input strictly sanitized to prevent OS command injection.');
      return false;
    }

    // SSRF detection
    if (trimmed.includes('169.254.169.254') || trimmed.includes('metadata.google')) {
      setValidationError('SSRF Protection Active: Cloud metadata endpoints are blocked.');
      return false;
    }

    setValidationError(null);
    return true;
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setTarget(val);
    if (val) validateTarget(val);
  };

  const handleClearTarget = () => {
    setTarget('');
    setValidationError(null);
  };

  const togglePort = (port: number) => {
    if (selectedPorts.includes(port)) {
      if (selectedPorts.length === 1) return; // Keep at least one
      setSelectedPorts(selectedPorts.filter(p => p !== port));
    } else {
      setSelectedPorts([...selectedPorts, port].sort((a, b) => a - b));
    }
  };

  const selectAllPorts = () => {
    setSelectedPorts(AVAILABLE_PORTS.map(p => p.port));
  };

  const selectWebOnly = () => {
    setSelectedPorts([80, 443, 8080]);
  };

  const selectShellOnly = () => {
    setSelectedPorts([21, 22, 23, 445]);
  };

  const resetFiltersToDefault = () => {
    setSelectedPorts([21, 22, 23, 80, 443, 445, 3306, 8080]);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateTarget(target) && !isLoading) {
      onScan(target.trim(), selectedPorts);
    }
  };

  const isCustomScope = selectedPorts.length !== AVAILABLE_PORTS.length;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 sm:p-6 backdrop-blur-md shadow-xl shadow-black/40 space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4">
        
        {/* Row 1: Target Input Bar Header */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label htmlFor="target-input" className="text-xs font-semibold tracking-wider uppercase text-slate-300 font-mono flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            <span>Target Host / Perimeter IP</span>
          </label>
          
          <div className="flex items-center gap-2">
            <div className="text-[11px] text-slate-400 font-mono bg-slate-950/80 px-2.5 py-1 rounded-md border border-slate-800/80">
              Rate Limit: <span className="text-cyan-400 font-semibold">{rateLimitRemaining}</span>/12 scans left
            </div>
          </div>
        </div>

        {/* Refined Search Bar */}
        <div className="relative group">
          <div className={`flex items-center w-full rounded-xl border bg-slate-950/90 transition-all duration-200 shadow-inner ${
            validationError
              ? 'border-red-500/80 ring-2 ring-red-500/20'
              : 'border-slate-800 hover:border-slate-700 focus-within:border-cyan-500 focus-within:ring-2 focus-within:ring-cyan-500/25'
          }`}>
            
            {/* Left Search Icon with Active State */}
            <div className="pl-4 pr-2 text-slate-500 group-focus-within:text-cyan-400 transition-colors">
              <Search className={`h-4 w-4 ${target ? 'text-cyan-400' : 'text-slate-500'}`} />
            </div>

            {/* Input Field */}
            <input
              id="target-input"
              type="text"
              value={target}
              onChange={handleInputChange}
              placeholder="Enter host, IP or domain (e.g. scanme.nmap.org, 192.168.1.1)..."
              disabled={isLoading}
              className="flex-1 bg-transparent py-3.5 pr-2 font-mono text-sm text-white placeholder-slate-500 focus:outline-none min-w-0"
            />

            {/* Clear Input Button */}
            {target && !isLoading && (
              <button
                type="button"
                onClick={handleClearTarget}
                aria-label="Clear target input"
                className="p-1.5 mr-2 rounded-md text-slate-400 hover:text-white hover:bg-slate-800/80 transition-colors"
                title="Clear input"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}

            {/* Filter Toggle Button Inside or Beside Search Bar */}
            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className={`flex items-center gap-1.5 px-3 py-2 mr-2 rounded-lg text-xs font-mono transition-all border shrink-0 ${
                showFilters
                  ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-300 shadow-sm shadow-cyan-500/10'
                  : isCustomScope
                  ? 'bg-amber-500/10 border-amber-500/40 text-amber-300 hover:bg-amber-500/20'
                  : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700'
              }`}
              title="Click to configure port scopes, presets and scan filters"
            >
              <SlidersHorizontal className="h-3.5 w-3.5 text-cyan-400" />
              <span className="hidden xs:inline">Filters</span>
              <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${
                isCustomScope ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-300'
              }`}>
                {selectedPorts.length}
              </span>
              <ChevronDown className={`h-3 w-3 transition-transform duration-200 ${showFilters ? 'rotate-180 text-cyan-400' : 'text-slate-400'}`} />
            </button>

            {/* Initiate Audit Submit Button */}
            <div className="pr-1.5 shrink-0">
              <button
                type="submit"
                disabled={isLoading || !!validationError || selectedPorts.length === 0}
                className={`flex items-center gap-2 rounded-lg px-4 sm:px-5 py-2.5 text-xs font-bold font-mono uppercase tracking-wider transition-all ${
                  isLoading
                    ? 'bg-cyan-500/40 text-cyan-200 cursor-wait'
                    : validationError || selectedPorts.length === 0
                    ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-gradient-to-r from-cyan-500 to-cyan-400 text-slate-950 hover:brightness-110 active:scale-95 shadow-lg shadow-cyan-500/25 cursor-pointer'
                }`}
              >
                {isLoading ? (
                  <>
                    <RotateCcw className="h-3.5 w-3.5 animate-spin" />
                    <span className="hidden sm:inline">Probing Target...</span>
                    <span className="sm:hidden">Probing</span>
                  </>
                ) : (
                  <>
                    <Search className="h-3.5 w-3.5" />
                    <span>Initiate Audit</span>
                  </>
                )}
              </button>
            </div>

          </div>
        </div>

        {/* Validation Error Banner */}
        {validationError && (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-950/30 px-3.5 py-2 text-xs text-red-300 font-mono">
            <AlertTriangle className="h-4 w-4 shrink-0 text-red-400" />
            <span>{validationError}</span>
          </div>
        )}

        {/* Collapsed Filter Quick Summary (Shown when filters are hidden to keep view clean) */}
        {!showFilters && (
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-xs font-mono text-slate-400">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-slate-300 text-[11px]">Active Scope:</span>
              <span className="inline-flex items-center gap-1 rounded bg-slate-950 px-2 py-0.5 border border-slate-800 text-[11px] text-cyan-300">
                <Layers className="h-3 w-3 text-cyan-400" />
                {selectedPorts.length} Ports Selected ({selectedPorts.join(', ')})
              </span>
              {isCustomScope && (
                <span className="text-[10px] text-amber-400 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-800/60">
                  Custom Scope
                </span>
              )}
            </div>

            <button
              type="button"
              onClick={() => setShowFilters(true)}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 underline underline-offset-4 flex items-center gap-1 transition-colors"
            >
              <SlidersHorizontal className="h-3 w-3" />
              Configure Ports & Presets
            </button>
          </div>
        )}

        {/* EXPANDABLE FILTERS & SCOPE PANEL (Hidden until user clicks Filters) */}
        {showFilters && (
          <div className="rounded-xl border border-cyan-500/30 bg-slate-950/90 p-4 sm:p-5 space-y-5 animate-in fade-in duration-200 shadow-xl shadow-black/50">
            
            {/* Header of Filters Panel */}
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <SlidersHorizontal className="h-4 w-4 text-cyan-400" />
                <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                  Scan Configuration & Port Scope Filters
                </h4>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={resetFiltersToDefault}
                  className="text-xs text-slate-400 hover:text-white font-mono flex items-center gap-1 px-2 py-1 rounded hover:bg-slate-800 transition-colors"
                  title="Reset to all default standard ports"
                >
                  <RotateCcw className="h-3 w-3" />
                  Reset
                </button>
                <button
                  type="button"
                  onClick={() => setShowFilters(false)}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-mono font-semibold px-2.5 py-1 rounded bg-cyan-950/40 border border-cyan-800/50 hover:bg-cyan-900/40 transition-colors"
                >
                  Done
                </button>
              </div>
            </div>

            {/* Filter Section 1: Lab Target Presets */}
            <div>
              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-300 font-semibold mb-2 flex items-center gap-1.5">
                <Server className="h-3.5 w-3.5 text-cyan-400" />
                Target Environment Presets
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                {PRESETS.map((p) => {
                  const isCurrent = target === p.target;
                  return (
                    <button
                      key={p.target}
                      type="button"
                      onClick={() => {
                        setTarget(p.target);
                        setValidationError(null);
                      }}
                      disabled={isLoading}
                      className={`text-left rounded-lg border p-2.5 transition-all ${
                        isCurrent
                          ? 'border-cyan-500/80 bg-cyan-950/40 text-cyan-200 ring-1 ring-cyan-500/30'
                          : 'border-slate-800 bg-slate-900/60 text-slate-300 hover:border-slate-700 hover:text-white'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold">{p.label}</span>
                        {isCurrent && <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400 shrink-0" />}
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5">{p.target}</div>
                      <div className="text-[10px] text-slate-400 mt-1 line-clamp-1">{p.desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Filter Section 2: Port Scope Controls */}
            <div className="border-t border-slate-800/80 pt-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-[11px] font-mono uppercase tracking-wider text-slate-300 font-semibold flex items-center gap-1.5">
                  <Layers className="h-3.5 w-3.5 text-cyan-400" />
                  Target Port Filter ({selectedPorts.length} Selected)
                </div>
                
                {/* Quick Scope Presets */}
                <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
                  <button
                    type="button"
                    onClick={selectAllPorts}
                    className="px-2 py-0.5 rounded border border-slate-800 bg-slate-900 text-slate-300 hover:text-white hover:border-slate-700 transition-colors"
                  >
                    All (8)
                  </button>
                  <button
                    type="button"
                    onClick={selectWebOnly}
                    className="px-2 py-0.5 rounded border border-slate-800 bg-slate-900 text-slate-300 hover:text-white hover:border-slate-700 transition-colors"
                  >
                    Web (80, 443, 8080)
                  </button>
                  <button
                    type="button"
                    onClick={selectShellOnly}
                    className="px-2 py-0.5 rounded border border-slate-800 bg-slate-900 text-slate-300 hover:text-white hover:border-slate-700 transition-colors"
                  >
                    Shell/SMB (21, 22, 23, 445)
                  </button>
                </div>
              </div>

              {/* Port Checkbox Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                {AVAILABLE_PORTS.map((p) => {
                  const active = selectedPorts.includes(p.port);
                  return (
                    <button
                      key={p.port}
                      type="button"
                      onClick={() => togglePort(p.port)}
                      disabled={isLoading}
                      className={`flex flex-col text-left rounded-lg border p-2.5 transition-all ${
                        active
                          ? 'border-cyan-500/50 bg-cyan-950/30 text-white shadow-sm shadow-cyan-500/10'
                          : 'border-slate-800/80 bg-slate-900/30 text-slate-400 opacity-60 hover:opacity-100 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold">
                          {p.port} <span className="text-[10px] font-normal text-slate-400">/tcp</span>
                        </span>
                        {active ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400" />
                        ) : (
                          <div className="h-3.5 w-3.5 rounded-full border border-slate-700" />
                        )}
                      </div>
                      <div className="text-[11px] font-semibold text-slate-200 mt-0.5 uppercase font-mono">
                        {p.service}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate mt-0.5">
                        {p.riskHint}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Filter Section 3: Engine Protections */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800/80 text-xs text-slate-400 font-mono">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/50" />
                <span className="text-slate-300">WAF Input Sanitization</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400/50" />
                <span className="text-slate-300">SSRF Cloud Guard</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-purple-400 shadow-sm shadow-purple-400/50" />
                <span className="text-slate-300">Non-blocking TCP Banners</span>
              </div>
            </div>

          </div>
        )}

      </form>
    </div>
  );
};

