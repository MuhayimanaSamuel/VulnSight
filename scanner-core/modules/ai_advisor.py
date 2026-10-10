"""
VulnSight Scanner Core - Gemini AI Exploitation & Remediation Module
Constructs a target security profile and connects to Google Gemini API
to synthesize CVE mappings, educational threat mechanics, and administrator remediation.
"""

import os
import json
from typing import Dict, Any, List
import httpx

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

def build_offline_fallback_advice(profile: Dict[str, Any]) -> Dict[str, Any]:
    open_ports = [p for p in profile.get("ports", []) if p.get("status") == "OPEN"]
    leaked_dirs = [d for d in profile.get("directories", []) if d.get("accessible")]

    vulnerabilities: List[Dict[str, Any]] = []
    
    for p in open_ports:
        port_num = p.get("port")
        banner = p.get("banner", "")
        if port_num == 21:
            vulnerabilities.append({
                "cve": "CVE-2011-2523",
                "title": "Cleartext FTP & Legacy Authentication Vulnerability",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "affectedComponent": f"Port 21 ({banner or 'FTP'})",
                "exploitationMechanic": "Attackers sniff plaintext authentication credentials on unencrypted transport or trigger known daemon command injection bugs.",
                "remediation": "Decommission standalone FTP. Enforce SFTP (SSH File Transfer Protocol) or FTPS with TLS 1.3, and block port 21 via host firewall."
            })
        elif port_num == 22:
            vulnerabilities.append({
                "cve": "CVE-2023-38408",
                "title": "OpenSSH Forwarding & Brute-Force Exposure",
                "severity": "HIGH",
                "cvss": 8.5,
                "affectedComponent": f"Port 22 ({banner or 'SSH'})",
                "exploitationMechanic": "Exposed SSH ports are subjected to continuous automated dictionary brute-force attacks and targeted PKCS#11 agent forwarding memory corruption.",
                "remediation": "Disable password authentication (PasswordAuthentication no), enforce public key or FIDO2 tokens, configure Fail2Ban/CrowdSec, and restrict access to bastion VPNs."
            })
        elif port_num in [80, 8080]:
            vulnerabilities.append({
                "cve": "CVE-2021-41773",
                "title": "HTTP Path Traversal & Unencrypted Channel Risk",
                "severity": "HIGH",
                "cvss": 7.5,
                "affectedComponent": f"Port {port_num} ({banner or 'HTTP'})",
                "exploitationMechanic": "Attackers can intercept sensitive session cookies over unencrypted HTTP or exploit path traversal flaws in legacy web server versions.",
                "remediation": "Enforce HTTP to HTTPS 301 redirection. Apply strict Strict-Transport-Security (HSTS) headers and update web daemon packages."
            })
        elif port_num == 3306:
            vulnerabilities.append({
                "cve": "CVE-2012-2122",
                "title": "Publicly Exposed MySQL Database Listener",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "affectedComponent": "Port 3306 (MySQL)",
                "exploitationMechanic": "Exposing relational databases directly to the public Internet permits remote password spray attacks, SQL injection pivoting, and direct data exfiltration.",
                "remediation": "Bind MySQL strictly to localhost (bind-address = 127.0.0.1) or internal VPC interfaces. Require SSH tunnels or VPNs for administrative access."
            })

    for d in leaked_dirs:
        path = d.get("path")
        vulnerabilities.append({
            "cve": "CWE-538 / CWE-200",
            "title": f"Sensitive File Exposure: {path}",
            "severity": "CRITICAL" if path in ["/.env", "/.git/HEAD"] else "HIGH",
            "cvss": 9.1 if path in ["/.env", "/.git/HEAD"] else 7.5,
            "affectedComponent": path,
            "exploitationMechanic": f"Directly downloading {path} leaks environment variables, cryptographic signing keys, database passwords, or administrative interfaces.",
            "remediation": f"Block web server access to dotfiles and hidden files in Nginx/Apache configuration: location ~ /\\. {{ deny all; }}"
        })

    return {
        "engine": "VulnSight-Heuristic-Rule-Engine",
        "executiveSummary": f"Assessment identified {len(open_ports)} exposed network ports and {len(leaked_dirs)} accessible sensitive web endpoints. Perimeter requires immediate hardening.",
        "vulnerabilities": vulnerabilities,
        "educationalAttackWalkthrough": (
            "In an engagement, an adversary starts by mapping open ports to discover exposed services. "
            "Publicly listening daemons (like SSH or MySQL) are scanned for known CVE banners and targeted with automated credential sprays. "
            "Concurrently, web directories are enumerated to locate unauthenticated assets (such as /.env or /admin). "
            "Once an admin panel or credentials file is discovered, the adversary pivots internally into backend databases."
        ),
        "defensiveHardeningChecklist": [
            "Enforce a default-deny ingress firewall rule on cloud security groups.",
            "Decommission unnecessary network listeners (ports 21, 23, 3306).",
            "Add web server rewrite rules blocking all requests to dotfiles (/.env, /.git).",
            "Implement multi-factor authentication (MFA) and rate limiting on all exposed administrative endpoints."
        ]
    }

async def generate_ai_exploitation_advice(profile: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return build_offline_fallback_advice(profile)

    prompt = f"""
You are an expert DevSecOps and Application Security Architect analyzing a vulnerability scan.
Target Profile:
- Target: {profile.get('target')}
- Resolved IP: {profile.get('resolvedIp')}
- Open Ports: {json.dumps(profile.get('ports', []))}
- Directory Fuzzing Results: {json.dumps(profile.get('directories', []))}
- DNS Nameservers & Records: {json.dumps(profile.get('recon', {}))}

Analyze this target profile and generate a comprehensive defensive security assessment.
Return strictly valid JSON with this exact schema:
{{
  "engine": "gemini-3.8-flash",
  "executiveSummary": "Concise high-level threat synopsis for leadership",
  "vulnerabilities": [
    {{
      "cve": "CVE-XXXX-XXXX or CWE-XXX",
      "title": "Clear vulnerability title",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "cvss": 9.8,
      "affectedComponent": "Port/Service or URL Path",
      "exploitationMechanic": "Educational explanation of how an adversary theoretically leverages this weakness",
      "remediation": "Step-by-step administrator hardening instruction"
    }}
  ],
  "educationalAttackWalkthrough": "High-level theoretical attack path description explaining how the weaknesses link together",
  "defensiveHardeningChecklist": [
    "Concrete actionable hardening item 1",
    "Concrete actionable hardening item 2",
    "Concrete actionable hardening item 3"
  ]
}}
Do NOT output functional exploit scripts, payloads, or copy-paste attack commands. Focus strictly on educational threat analysis and defense.
"""

    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"}
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                result = resp.json()
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(text)
    except Exception:
        pass

    return build_offline_fallback_advice(profile)
