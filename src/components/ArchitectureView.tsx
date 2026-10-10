import React, { useState } from 'react';
import { Server, ShieldCheck, Terminal, Layers, Cpu, Sparkles, Folder, CheckCircle2, Copy, Check, Smartphone } from 'lucide-react';

export const ArchitectureView: React.FC = () => {
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  const copyToClipboard = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(key);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const dockerComposeSnippet = `version: '3.8'

services:
  # Folder 1: Next.js Frontend & API Gateway
  frontend-api:
    build:
      context: ./frontend-api
      dockerfile: Dockerfile
    container_name: vulnsight-frontend
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - SCANNER_CORE_URL=http://scanner-core:8000
      - GEMINI_API_KEY=\${GEMINI_API_KEY}
    depends_on:
      - scanner-core
    networks:
      - vulnsight-net
    restart: unless-stopped

  # Folder 2: Python Scanner & Recon Core
  scanner-core:
    build:
      context: ./scanner-core
      dockerfile: Dockerfile
    container_name: vulnsight-core
    expose:
      - "8000"
    environment:
      - GEMINI_API_KEY=\${GEMINI_API_KEY}
    networks:
      - vulnsight-net
    restart: unless-stopped

networks:
  vulnsight-net:
    driver: bridge`;

  return (
    <div className="space-y-8">
      
      {/* Intro Header */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <div className="max-w-3xl">
          <div className="text-xs font-mono uppercase text-cyan-400 font-semibold tracking-wider flex items-center gap-2">
            <Layers className="h-4 w-4" />
            Two-Folder Clean Architecture
          </div>
          <h2 className="text-xl font-bold font-mono text-white mt-1">
            VulnSight: `frontend-api` & `scanner-core`
          </h2>
          <p className="text-sm text-slate-300 mt-2 leading-relaxed">
            Lightweight, decoupled design optimized for mobile-based development environments (Termux / VS Code Web / GitHub Codespaces) and enterprise AppSec portfolio showcases.
          </p>
        </div>
      </div>

      {/* Two Folder Visual Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Folder 1: frontend-api */}
        <div className="rounded-xl border border-cyan-500/40 bg-slate-900/80 p-6 space-y-4 hover:border-cyan-500/70 transition-colors">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs font-bold uppercase">
              <Folder className="h-4 w-4" />
              Folder 1: frontend-api/
            </div>
            <span className="text-[10px] font-mono bg-cyan-950 border border-cyan-800 text-cyan-300 px-2 py-0.5 rounded">
              Next.js 15 / App Router
            </span>
          </div>

          <h3 className="font-mono text-base font-bold text-white">
            Frontend UI & API Gateway Layer
          </h3>

          <ul className="text-xs text-slate-300 space-y-2 font-mono">
            <li>• <strong className="text-cyan-300">app/page.tsx:</strong> Dark-themed cybersecurity dashboard</li>
            <li>• <strong className="text-cyan-300">app/api/scan/route.ts:</strong> Rate limiting & WAF sanitization</li>
            <li>• <strong className="text-cyan-300">app/api/recon/route.ts:</strong> DNS & WHOIS query proxy</li>
            <li>• <strong className="text-cyan-300">app/api/ai-advice/route.ts:</strong> Gemini API prompt synthesis</li>
            <li>• <strong className="text-cyan-300">types/index.ts:</strong> Strict TypeScript interfaces for Recon, Ports, & AI</li>
          </ul>

          <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 font-mono flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            OWASP Input Sanitization & Command Injection Defense
          </div>
        </div>

        {/* Folder 2: scanner-core */}
        <div className="rounded-xl border border-purple-500/40 bg-slate-900/80 p-6 space-y-4 hover:border-purple-500/70 transition-colors">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-purple-400 font-mono text-xs font-bold uppercase">
              <Folder className="h-4 w-4" />
              Folder 2: scanner-core/
            </div>
            <span className="text-[10px] font-mono bg-purple-950 border border-purple-800 text-purple-300 px-2 py-0.5 rounded">
              Python 3.11 / FastAPI
            </span>
          </div>

          <h3 className="font-mono text-base font-bold text-white">
            Security Scanner & Recon Engine
          </h3>

          <ul className="text-xs text-slate-300 space-y-2 font-mono">
            <li>• <strong className="text-purple-300">modules/recon.py:</strong> dnspython & WHOIS/RDAP resolver</li>
            <li>• <strong className="text-purple-300">modules/port_scanner.py:</strong> Ports (21, 22, 23, 80, 443, 445, 3306, 8080)</li>
            <li>• <strong className="text-purple-300">modules/directory_fuzzer.py:</strong> Fuzzes /.env, /admin, /config.php</li>
            <li>• <strong className="text-purple-300">modules/ai_advisor.py:</strong> Gemini AI exploitation & remediation</li>
            <li>• <strong className="text-purple-300">main.py:</strong> High-speed async FastAPI microservice</li>
          </ul>

          <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 font-mono flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-cyan-400" />
            Gemini 3.8 Flash Generative Exploit Walkthroughs
          </div>
        </div>

      </div>

      {/* Mobile Dev & Termux Tips */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-4">
        <div className="flex items-center gap-2 text-xs font-mono font-bold uppercase text-slate-300">
          <Smartphone className="h-4 w-4 text-cyan-400" />
          Mobile Development Friendly Architecture
        </div>
        <p className="text-xs text-slate-300 leading-relaxed font-sans">
          This split repository structure allows full development from mobile devices (e.g. running Node.js and Python inside <strong>Termux</strong>, or editing via <strong>GitHub Codespaces</strong> on a mobile browser). Both folders remain completely self-contained with minimal dependencies.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
          <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
            <span className="text-cyan-400 font-bold">Terminal 1 (Python Core):</span>
            <pre className="text-slate-300 mt-1 text-[11px]">cd scanner-core && uvicorn main:app --reload</pre>
          </div>
          <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
            <span className="text-cyan-400 font-bold">Terminal 2 (Next.js UI):</span>
            <pre className="text-slate-300 mt-1 text-[11px]">cd frontend-api && npm run dev</pre>
          </div>
        </div>
      </div>

      {/* Docker Compose Production Orchestration */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-4 flex flex-col">
        <div className="flex items-center justify-between">
          <div className="text-xs font-mono uppercase text-slate-400 flex items-center gap-2">
            <Server className="h-4 w-4 text-cyan-400" />
            docker-compose.yml (Two-Folder Production Stack)
          </div>
          <button
            onClick={() => copyToClipboard('compose', dockerComposeSnippet)}
            className="flex items-center gap-1 text-xs font-mono text-cyan-400 hover:text-cyan-300"
          >
            {copiedCode === 'compose' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
            {copiedCode === 'compose' ? 'Copied' : 'Copy Compose File'}
          </button>
        </div>
        <pre className="rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed scrollbar-thin">
          {dockerComposeSnippet}
        </pre>
      </div>

    </div>
  );
};
