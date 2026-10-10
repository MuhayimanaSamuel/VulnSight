import React from 'react';
import { Shield, FileDown, Terminal, Server, Database, BookOpen } from 'lucide-react';
import { ScanResponse } from '../types/scanner';
import { exportSecurityReportToPdf } from '../services/pdfExport';

export type AppTab = 'scanner' | 'recon' | 'ports-dirs' | 'ai-advice' | 'architecture' | 'docs';

interface HeaderProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
  lastScan: ScanResponse | null;
}

export const Header: React.FC<HeaderProps> = ({ activeTab, setActiveTab, lastScan }) => {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-8 px-6 py-3.5">
        
        {/* Zone 1: Wordmark Brand */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <span className="font-bold tracking-tight text-lg text-white font-mono flex items-center gap-1.5">
              Vuln<span className="text-cyan-400">Sight</span>
            </span>
          </div>
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="hidden md:flex items-center gap-5 text-xs font-mono font-medium text-slate-300">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'scanner' ? 'text-cyan-400 border-b-2 border-cyan-400 font-bold' : 'hover:text-white'
            }`}
          >
            Scanner
          </button>

          <button
            onClick={() => setActiveTab('recon')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'recon' ? 'text-cyan-400 border-b-2 border-cyan-400 font-bold' : 'hover:text-white'
            }`}
          >
            DNS & WHOIS Recon
          </button>

          <button
            onClick={() => setActiveTab('ports-dirs')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'ports-dirs' ? 'text-cyan-400 border-b-2 border-cyan-400 font-bold' : 'hover:text-white'
            }`}
          >
            Ports & Dirs
          </button>

          <button
            onClick={() => setActiveTab('ai-advice')}
            className={`whitespace-nowrap transition-colors py-1 flex items-center gap-1 ${
              activeTab === 'ai-advice' ? 'text-cyan-400 border-b-2 border-cyan-400 font-bold' : 'hover:text-white'
            }`}
          >
            AI Threat Report
          </button>

          <button
            onClick={() => setActiveTab('architecture')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'architecture' ? 'text-cyan-400 border-b-2 border-cyan-400 font-bold' : 'hover:text-white'
            }`}
          >
            Architecture
          </button>

          <button
            onClick={() => setActiveTab('docs')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'docs' ? 'text-cyan-400 border-b-2 border-cyan-400 font-bold' : 'hover:text-white'
            }`}
          >
            Docs & README
          </button>
        </nav>

        {/* Zone 3: Primary Action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => {
              if (lastScan) {
                exportSecurityReportToPdf(lastScan);
              }
            }}
            disabled={!lastScan}
            title={lastScan ? 'Download formatted PDF security audit' : 'Perform a scan to export PDF report'}
            className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-semibold whitespace-nowrap transition-all ${
              lastScan
                ? 'bg-cyan-500 text-slate-950 hover:bg-cyan-400 shadow-md shadow-cyan-500/20 active:scale-95 cursor-pointer'
                : 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700/50'
            }`}
          >
            <FileDown className="h-4 w-4" />
            Export Report to PDF
          </button>
        </div>

      </div>
    </header>
  );
};
