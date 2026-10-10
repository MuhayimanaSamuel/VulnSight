# VulnSight // Enterprise Application Security & DevSecOps Platform

<div align="center">

![DevSecOps](https://img.shields.io/badge/Security-DevSecOps%20%7C%20AppSec-cyan?style=for-the-badge&logo=shield)
![Frontend](https://img.shields.io/badge/frontend--api-Next.js%2015%20%7C%20TypeScript-06B6D4?style=for-the-badge&logo=nextdotjs)
![Core](https://img.shields.io/badge/scanner--core-Python%203.11%20%7C%20FastAPI-009688?style=for-the-badge&logo=fastapi)
![AI](https://img.shields.io/badge/AI-Google%20Gemini%203.8%20Flash-4285F4?style=for-the-badge&logo=google)
![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey?style=for-the-badge)

**An enterprise-grade, two-folder microservice cybersecurity platform featuring automated DNS/WHOIS reconnaissance, sensitive web endpoint fuzzing, TCP socket port auditing, and Gemini AI exploitation threat modeling with administrator remediation.**

</div>

---

> ### ⚠️ PROMINENT ETHICAL HACKING & LEGAL DISCLAIMER
> **VulnSight is developed and intended strictly for authorized educational purposes and ethical penetration testing.**
> 
> Scanning, probing, or enumerating targets without prior explicit written permission from the system owner is illegal and violates the **U.S. Computer Fraud and Abuse Act (CFAA)**, the **UK Computer Misuse Act**, and international cyber crime laws. The authors assume zero liability for unauthorized activity. **Always verify authorization before auditing any target.**

---

## 1. Clean Two-Folder Architecture

VulnSight is split cleanly into two independent, lightweight folders optimized for mobile-based development (e.g. running via Termux on Android, VS Code Web, or GitHub Codespaces) and cloud production deployment:

```
vulnsight/
├── frontend-api/                  # Next.js 15 (App Router, TypeScript, Tailwind CSS)
│   ├── app/
│   │   ├── page.tsx               # Master Cybersecurity Dashboard (Dark Cyberpunk Theme)
│   │   ├── layout.tsx             # Root layout with font optimization
│   │   └── api/
│   │       ├── scan/route.ts      # Gateway with WAF regex command injection sanitizer
│   │       ├── recon/route.ts     # DNS & WHOIS reconnaissance forwarding
│   │       └── ai-advice/route.ts # Gemini API threat analysis endpoint
│   ├── types/
│   │   └── index.ts               # Strict TypeScript interfaces (Recon, Ports, Dirs, AI)
│   ├── Dockerfile
│   └── package.json
│
├── scanner-core/                  # Python 3.11 (FastAPI Asynchronous Engine)
│   ├── modules/
│   │   ├── recon.py               # DNS resolver (NS, MX, TXT, A) & RDAP registrar
│   │   ├── port_scanner.py        # Asynchronous TCP sockets (21, 22, 23, 80, 443, 445, 3306, 8080)
│   │   ├── directory_fuzzer.py    # Sensitive path brute-forcer (/.env, /admin, /config.php, /robots.txt)
│   │   └── ai_advisor.py          # Google Gemini 3.8 Flash API prompt synthesis & threat modeling
│   ├── main.py                    # FastAPI microservice routes
│   ├── Dockerfile
│   └── requirements.txt
│
└── docker-compose.yml             # Multi-container orchestration with bridge network
```

---

## 2. Key Modules & Features

### A. Massive Reconnaissance & Enumeration (`scanner-core/modules/recon.py`)
- **DNS Record Queries**: Automatically queries Authoritative Nameservers (`NS`), Mail Exchangers (`MX`), SPF/DMARC Security Policies (`TXT`), and Address mappings (`A`) using `dnspython`.
- **WHOIS & RDAP Metadata**: Pulls registration timestamps, expiration dates, domain registrars, and registry lock statuses.

### B. TCP Port Probing & Banner Grabbing (`scanner-core/modules/port_scanner.py`)
- Asynchronous TCP socket auditing across 8 high-risk standard ports:
  - **21 (FTP)**: `vsftpd` / `ProFTPD` backdoors and cleartext logins.
  - **22 (SSH)**: `OpenSSH` PKCS#11 forwarding vulnerabilities and version banners.
  - **23 (Telnet)**: Legacy unencrypted remote administration listeners.
  - **80 / 443 (HTTP/HTTPS)**: Web daemons (`Apache 2.4.49`, `Nginx`, OpenSSL buffer flaws).
  - **445 (SMB)**: Windows Server Message Block / EternalBlue vectors.
  - **3306 (MySQL)**: Direct exposure of relational database listeners.
  - **8080 (HTTP-Alt)**: Spring Boot, Apache Tomcat, and Log4j2 JNDI endpoints.
- Socket timeout guard (`1.5s`) prevents hung connections or zombie threads.

### C. Sensitive Directory Fuzzing (`scanner-core/modules/directory_fuzzer.py`)
- Probes high-risk web endpoints for unauthorized access:
  - `/.env`: Leaked cryptographic secrets and database connection strings.
  - `/admin`: Exposed management portals.
  - `/.git/HEAD`: Publicly downloadable source code repositories.
  - `/config.php`: Legacy configuration scripts.
  - `/robots.txt`: Search engine crawling disclosures.
  - `/backup.zip`: Forgotten compressed database dumps.

### D. AI Threat Modeling & Remediation (`scanner-core/modules/ai_advisor.py`)
- Wraps the aggregated reconnaissance profile into a structured prompt sent to **Google Gemini 3.8 Flash**.
- Dynamically outputs:
  1. **Executive Leadership Synopsis**: High-level risk summary for leadership.
  2. **Correlated Vulnerability Findings**: CVE/CWE numbers, CVSS scores, and theoretical exploit mechanics.
  3. **Educational Attack Walkthrough**: Conceptual explanation of the adversary attack chain (reconnaissance $\rightarrow$ initial access $\rightarrow$ lateral pivot) without functional exploit code.
  4. **Defensive Remediation Runbook**: Step-by-step administrator hardening commands.

---

## 3. Quickstart & Deployment

### Running via Docker Compose
```bash
# 1. Clone repository
git clone https://github.com/your-username/vulnsight.git
cd vulnsight

# 2. Configure environment
export GEMINI_API_KEY="your-api-key-here"

# 3. Launch both microservices
docker-compose up --build -d

# 4. Access the dashboard
# Frontend & API: http://localhost:3000
# Scanner Core: http://localhost:8000/docs
```

### Running on Mobile (Termux / Android)
VulnSight's clean two-folder separation allows native development directly on a smartphone:

```bash
# In Termux Terminal 1: Launch Python Core
pkg install python git
cd vulnsight/scanner-core
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# In Termux Terminal 2: Launch Next.js Gateway
pkg install nodejs
cd vulnsight/frontend-api
npm install
npm run dev
```

---

## 4. Security & Input Validation Controls

- **Anti-Command Injection Filter**: Strict regex check blocks shell metacharacters (`;&|`$><*?!{}[]\`) before any network execution.
- **SSRF Cloud Perimeter Protection**: Disallows requests targeting AWS/GCP/Azure link-local metadata endpoints (`169.254.169.254`).
- **Sliding Token Bucket Rate Limiting**: Enforces a strict threshold of 12 assessments/minute per IP, returning `429 Too Many Requests` with `Retry-After` headers.

---

## 5. License & Attribution

Distributed under the Apache 2.0 License. Designed for application security portfolios and DevSecOps engineering showcases.
