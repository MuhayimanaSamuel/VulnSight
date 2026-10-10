"""
VulnSight Scanner Core - Main FastAPI Service
Integrates DNS/WHOIS recon, TCP port probing, directory fuzzing, and Gemini AI advice.
"""

import time
import socket
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from modules.recon import extract_dns_records, extract_whois_rdap
from modules.port_scanner import scan_all_ports, DEFAULT_TARGET_PORTS
from modules.directory_fuzzer import fuzz_sensitive_paths
from modules.ai_advisor import generate_ai_exploitation_advice

app = FastAPI(
    title="VulnSight Scanner Core",
    description="Python Network Reconnaissance, Port Scanner, Directory Fuzzer, and AI Remediation Engine",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FullScanRequest(BaseModel):
    target: str = Field(..., description="Target hostname or IP address")
    ports: Optional[List[int]] = Field(default=DEFAULT_TARGET_PORTS, description="Ports to scan")
    enableRecon: Optional[bool] = Field(default=True, description="Perform DNS & WHOIS reconnaissance")
    enableFuzzing: Optional[bool] = Field(default=True, description="Enumerate sensitive directories")
    enableAI: Optional[bool] = Field(default=True, description="Generate AI exploitation & remediation report")

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "VulnSight-Scanner-Core",
        "version": "2.0.0",
        "modules": ["dns-whois-recon", "tcp-port-banner", "dir-fuzzer", "gemini-ai-advisor"]
    }

@app.post("/scan")
async def execute_full_security_scan(req: FullScanRequest):
    start_time = time.perf_counter()
    logs: List[str] = [f"[INIT] Received scan request for target: {req.target}"]

    # 1. Resolve DNS
    try:
        resolved_ip = socket.gethostbyname(req.target)
        logs.append(f"[DNS] Resolved target '{req.target}' to {resolved_ip}")
    except socket.gaierror as e:
        logs.append(f"[ERROR] Failed to resolve target: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to resolve host: {req.target}"
        )

    # 2. Reconnaissance (DNS records & WHOIS)
    recon_data = {}
    if req.enableRecon:
        logs.append("[RECON] Querying Nameservers, MX records, TXT records, and RDAP registration...")
        dns_data = await extract_dns_records(req.target)
        whois_data = await extract_whois_rdap(req.target)
        recon_data = {**dns_data, **whois_data}
        logs.append(f"[RECON] Found {len(recon_data.get('nameservers', []))} NS records and {len(recon_data.get('mx_records', []))} MX records.")

    # 3. Port Scanning & Banner Grabbing
    ports_to_probe = req.ports or DEFAULT_TARGET_PORTS
    logs.append(f"[PORTS] Probing {len(ports_to_probe)} standard TCP ports with banner extraction...")
    port_results = await scan_all_ports(resolved_ip, ports_to_probe)
    open_ports = [p for p in port_results if p["status"] == "OPEN"]
    logs.append(f"[PORTS] Port probe complete: {len(open_ports)} listening services identified.")

    # 4. Sensitive Directory Fuzzing
    directory_results = []
    if req.enableFuzzing:
        logs.append("[FUZZ] Enumerating sensitive administrative and config paths (e.g., /.env, /admin, /robots.txt)...")
        directory_results = await fuzz_sensitive_paths(req.target)
        accessible_dirs = [d for d in directory_results if d["accessible"]]
        logs.append(f"[FUZZ] Directory fuzzing complete: {len(accessible_dirs)} accessible paths found.")

    # 5. Profile Assembly & AI Advice Generation
    target_profile = {
        "target": req.target,
        "resolvedIp": resolved_ip,
        "ports": port_results,
        "directories": directory_results,
        "recon": recon_data
    }

    ai_advice = {}
    if req.enableAI:
        logs.append("[AI-ADVICE] Synthesizing vulnerability profile and querying Gemini API for remediation...")
        ai_advice = await generate_ai_exploitation_advice(target_profile)
        logs.append(f"[AI-ADVICE] Generated report using engine: {ai_advice.get('engine', 'standard')}")

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    logs.append(f"[COMPLETE] Assessment finished in {duration_ms}ms.")

    return {
        "scanId": f"VS-{int(time.time())}-{req.target[:6]}",
        "target": req.target,
        "resolvedIp": resolved_ip,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "durationMs": duration_ms,
        "recon": recon_data,
        "ports": port_results,
        "directories": directory_results,
        "aiAdvice": ai_advice,
        "logs": logs
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
