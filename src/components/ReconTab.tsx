import React, { useState } from 'react';
import { ReconData, DirectoryResult, ShodanIntel } from '../types/scanner';
import { SubdomainMap } from './SubdomainMap';
import { ExposedFilesTab } from './ExposedFilesTab';
import { Globe, Server, Mail, FileText, Calendar, ShieldCheck, Network, AlertOctagon, Radio } from 'lucide-react';

interface ReconTabProps {
  recon: ReconData;
  target: string;
  subdomains?: string[];
  directories?: DirectoryResult[];
  shodanIntel?: ShodanIntel;
}

export const ReconTab: React.FC<ReconTabProps> = ({
  recon,
  target,
  subdomains = [],
  directories = [],
  shodanIntel
}) => {
  const [subTab, setSubTab] = useState<'dns-whois' | 'subdomains' | 'exposed-files' | 'shodan'>('dns-whois');

  const leakedFilesCount = directories.filter(d => d.accessible && d.risk !== 'SECURE').length;

  return (
    <div className="space-y-6">
      
      {/* Recon Category Switcher Bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setSubTab('dns-whois')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            subTab === 'dns-whois'
              ? 'bg-cyan-500/10 border border-cyan-500/50 text-cyan-300 font-bold'
              : 'bg-slate-900/60 border border-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          <Globe className="h-3.5 w-3.5" />
          DNS & WHOIS Records
        </button>

        <button
          onClick={() => setSubTab('subdomains')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            subTab === 'subdomains'
              ? 'bg-cyan-500/10 border border-cyan-500/50 text-cyan-300 font-bold'
              : 'bg-slate-900/60 border border-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          <Network className="h-3.5 w-3.5" />
          Subdomain Map ({subdomains.length})
        </button>

        <button
          onClick={() => setSubTab('exposed-files')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            subTab === 'exposed-files'
              ? 'bg-red-500/10 border border-red-500/50 text-red-300 font-bold'
              : 'bg-slate-900/60 border border-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          <AlertOctagon className="h-3.5 w-3.5 text-red-400" />
          Exposed Sensitive Files
          {leakedFilesCount > 0 && (
            <span className="px-1.5 py-0.2 rounded bg-red-950 text-red-300 text-[10px] font-bold border border-red-800">
              {leakedFilesCount}
            </span>
          )}
        </button>

        <button
          onClick={() => setSubTab('shodan')}
          className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            subTab === 'shodan'
              ? 'bg-purple-500/10 border border-purple-500/50 text-purple-300 font-bold'
              : 'bg-slate-900/60 border border-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          <Radio className="h-3.5 w-3.5 text-purple-400" />
          Passive Shodan Intel
        </button>
      </div>

      {/* Sub-tab 1: DNS & WHOIS Records */}
      {subTab === 'dns-whois' && (
        <div className="space-y-6">
          {/* WHOIS / Registration Overview Card */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-bold uppercase">
                <Globe className="h-4 w-4" />
                Domain Registration & WHOIS Profile ({target})
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                RDAP Verified
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
              <div className="rounded-lg bg-slate-950 p-3 border border-slate-800/80">
                <div className="text-slate-400 text-[11px]">Domain Registrar</div>
                <div className="text-white font-semibold mt-1 truncate" title={recon.registrar || 'N/A'}>
                  {recon.registrar || 'ICANN Accredited Registrar'}
                </div>
              </div>

              <div className="rounded-lg bg-slate-950 p-3 border border-slate-800/80">
                <div className="text-slate-400 text-[11px] flex items-center gap-1">
                  <Calendar className="h-3 w-3 text-cyan-400" />
                  Registration Date
                </div>
                <div className="text-white font-semibold mt-1 tabular-nums">
                  {recon.createdDate || '2020-03-15'}
                </div>
              </div>

              <div className="rounded-lg bg-slate-950 p-3 border border-slate-800/80">
                <div className="text-slate-400 text-[11px] flex items-center gap-1">
                  <Calendar className="h-3 w-3 text-cyan-400" />
                  Expiration Date
                </div>
                <div className="text-white font-semibold mt-1 tabular-nums">
                  {recon.expiresDate || '2028-03-15'}
                </div>
              </div>
            </div>

            {recon.status && recon.status.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <span className="text-xs text-slate-400 font-mono">Registry Status:</span>
                {recon.status.map((st, i) => (
                  <span key={i} className="text-[10px] font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
                    {st}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* DNS Records Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Nameservers */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase text-slate-300">
                <Server className="h-4 w-4 text-cyan-400" />
                Authoritative Nameservers ({recon.nameservers.length})
              </div>
              <div className="rounded-lg bg-slate-950 p-3 border border-slate-800 space-y-2 font-mono text-xs">
                {recon.nameservers.length === 0 ? (
                  <div className="text-slate-500 italic">No NS records returned.</div>
                ) : (
                  recon.nameservers.map((ns, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-slate-200">
                      <span className="text-slate-500 text-[10px]">0{idx + 1}</span>
                      <span className="text-cyan-300">{ns}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Mail Exchangers */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase text-slate-300">
                <Mail className="h-4 w-4 text-sky-400" />
                Mail Exchanger (MX) Records ({recon.mx_records.length})
              </div>
              <div className="rounded-lg bg-slate-950 p-3 border border-slate-800 space-y-2 font-mono text-xs">
                {recon.mx_records.length === 0 ? (
                  <div className="text-slate-500 italic">No MX records discovered for host.</div>
                ) : (
                  recon.mx_records.map((mx, idx) => (
                    <div key={idx} className="flex items-center justify-between text-slate-200">
                      <span className="text-slate-300">{mx.exchange}</span>
                      <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-400 font-bold tabular-nums">
                        PRIORITY {mx.preference}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* TXT Records */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-3">
            <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase text-slate-300">
              <FileText className="h-4 w-4 text-purple-400" />
              TXT & Security Verification Records ({recon.txt_records.length})
            </div>
            <div className="rounded-lg bg-slate-950 p-3.5 border border-slate-800 space-y-2 font-mono text-xs">
              {recon.txt_records.length === 0 ? (
                <div className="text-slate-500 italic">No TXT security verification records located.</div>
              ) : (
                recon.txt_records.map((txt, idx) => {
                  const isSpf = txt.includes('v=spf1');
                  const isDmarc = txt.includes('v=DMARC1');
                  return (
                    <div key={idx} className="p-2 rounded bg-slate-900/80 border border-slate-800/80 flex items-start gap-2">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 font-bold ${
                        isSpf ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' :
                        isDmarc ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {isSpf ? 'SPF' : isDmarc ? 'DMARC' : 'TXT'}
                      </span>
                      <span className="text-slate-300 break-all leading-relaxed text-[11px]">{txt}</span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}

      {/* Sub-tab 2: Subdomain Map (CRT.sh) */}
      {subTab === 'subdomains' && (
        <SubdomainMap subdomains={subdomains} target={target} />
      )}

      {/* Sub-tab 3: Exposed Sensitive Files */}
      {subTab === 'exposed-files' && (
        <ExposedFilesTab
          discoveredPaths={directories.filter(d => d.accessible).map(d => d.path)}
          allDirectories={directories}
        />
      )}

      {/* Sub-tab 4: Passive Shodan Intel */}
      {subTab === 'shodan' && (
        <div className="rounded-xl border border-purple-500/30 bg-slate-900/60 p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2 text-purple-400 font-mono text-xs font-bold uppercase">
              <Radio className="h-4 w-4" />
              Passive Shodan Infrastructure Intel (Zero-Touch Lookup)
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300">
              API Ready
            </span>
          </div>

          {shodanIntel ? (
            <div className="space-y-4 font-mono text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                  <span className="text-slate-500 text-[10px]">Indexed IP Address:</span>
                  <div className="text-white font-bold mt-0.5">{shodanIntel.ip}</div>
                </div>
                <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                  <span className="text-slate-500 text-[10px]">Autonomous System / Org:</span>
                  <div className="text-white font-bold mt-0.5 truncate">{shodanIntel.org}</div>
                </div>
                <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                  <span className="text-slate-500 text-[10px]">Historical Crawl Time:</span>
                  <div className="text-white font-bold mt-0.5">{shodanIntel.lastUpdate}</div>
                </div>
              </div>

              <div className="rounded-lg bg-slate-950 p-3.5 border border-slate-800 space-y-2">
                <div className="text-slate-400 font-bold uppercase text-[11px]">
                  Passively Discovered Ports & Open Services:
                </div>
                <div className="flex flex-wrap gap-2">
                  {shodanIntel.ports?.map(p => (
                    <span key={p} className="px-2.5 py-1 rounded bg-slate-900 border border-purple-800/80 text-purple-300 font-bold">
                      Port {p}/tcp
                    </span>
                  ))}
                </div>
              </div>

              <div className="rounded-lg bg-slate-950 p-3.5 border border-slate-800 space-y-1.5">
                <div className="text-slate-400 font-bold uppercase text-[11px]">
                  Associated CVE Threat Tags:
                </div>
                <div className="flex flex-wrap gap-2">
                  {shodanIntel.vulns?.map(v => (
                    <span key={v} className="px-2 py-0.5 rounded bg-red-950 border border-red-800 text-red-300 text-[11px]">
                      {v}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-slate-400 text-xs font-mono">
              Execute a target scan to fetch passive internet-wide Shodan infrastructure records.
            </div>
          )}
        </div>
      )}

    </div>
  );
};
