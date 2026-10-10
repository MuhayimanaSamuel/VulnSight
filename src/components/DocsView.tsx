import React, { useState } from 'react';
import { BookOpen, Copy, Check, Terminal, Shield, AlertTriangle, GitBranch, Server, Cpu } from 'lucide-react';

export const DocsView: React.FC = () => {
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  const copyText = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(key);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      
      {/* Disclaimer Banner */}
      <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-5 space-y-2">
        <div className="flex items-center gap-2 text-red-400 font-mono text-sm font-bold uppercase">
          <AlertTriangle className="h-5 w-5" />
          Mandatory Ethical Hacking & Legal Disclaimer
        </div>
        <p className="text-xs text-red-200/90 leading-relaxed font-sans">
          VulnSight is developed strictly for authorized security auditing, defensive DevSecOps education, and vulnerability assessment on systems you own or have explicit written permission to test. Unauthorized port scanning or automated probing against non-consenting network infrastructure may violate national computer crime statutes (such as the CFAA in the United States or equivalent international legislation). Always obtain explicit authorization prior to initiating security assessments.
        </p>
      </div>

      {/* Overview & Portfolio Context */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <span className="text-xs font-mono uppercase text-cyan-400 font-semibold tracking-wider">
              Project Specification
            </span>
            <h2 className="text-2xl font-bold font-mono text-white mt-1">
              VulnSight // Enterprise DevSecOps Security Scanner
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-cyan-300">
              v1.0.0-PROD
            </span>
          </div>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">
          VulnSight is a production-grade microservices vulnerability scanner designed to demonstrate modern DevSecOps architectural patterns: defense-in-depth API rate limiting, strict command-injection input validation, non-blocking TCP socket banner grabbing, and automated NVD/CVE correlation with actionable remediation runbooks.
        </p>
      </div>

      {/* Quickstart Guide */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-4">
        <h3 className="text-lg font-bold font-mono text-white flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400" />
          Production Deployment via Docker Compose
        </h3>
        <p className="text-xs text-slate-300">
          Run both the Node.js API Gateway and the Python Socket Engine in an isolated Docker bridge network:
        </p>
        
        <div className="relative">
          <pre className="rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs text-cyan-300 overflow-x-auto">
{`# 1. Clone the repository
git clone https://github.com/your-username/vulnsight.git
cd vulnsight

# 2. Build and launch all microservices in detached mode
docker-compose up --build -d

# 3. Access the dashboard
# Open http://localhost:3000 in your browser
# API Gateway: http://localhost:3000/api/health
# Python Engine: http://localhost:8000/health`}
          </pre>
          <button
            onClick={() => copyText('quickstart', `git clone https://github.com/your-username/vulnsight.git\ncd vulnsight\ndocker-compose up --build -d`)}
            className="absolute top-3 right-3 flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-xs font-mono text-slate-300 hover:text-white"
          >
            {copiedSection === 'quickstart' ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {copiedSection === 'quickstart' ? 'Copied' : 'Copy Commands'}
          </button>
        </div>
      </div>

      {/* API Reference */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-4">
        <h3 className="text-lg font-bold font-mono text-white flex items-center gap-2">
          <Server className="h-4 w-4 text-sky-400" />
          API Specification: POST /api/scan
        </h3>
        <p className="text-xs text-slate-300">
          The API Gateway exposes a hardened JSON endpoint secured with rate-limiting and regex input sanitization:
        </p>

        <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 space-y-3 font-mono text-xs">
          <div className="text-cyan-400 font-bold">Request Payload:</div>
          <pre className="text-slate-300">
{`{
  "target": "scanme.nmap.org",
  "ports": [21, 22, 80, 443, 8080]
}`}
          </pre>
          <div className="text-emerald-400 font-bold border-t border-slate-800 pt-2">Security Response Headers:</div>
          <div className="text-slate-400 space-y-1 text-[11px]">
            <div>X-RateLimit-Limit: 12</div>
            <div>X-RateLimit-Remaining: 11</div>
            <div>X-Content-Type-Options: nosniff</div>
            <div>X-XSS-Protection: 1; mode=block</div>
          </div>
        </div>
      </div>

    </div>
  );
};
