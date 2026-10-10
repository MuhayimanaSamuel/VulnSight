"""
VulnSight - Security Scanner Engine Microservice
Production-grade Python FastAPI service performing TCP socket scanning,
banner grabbing, service version identification, and CVE risk correlation.
"""

import asyncio
import re
import socket
import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="VulnSight Scanner Engine",
    description="High-performance asynchronous TCP port prober and banner grabber with CVE intelligence.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Standard DevSecOps audit ports
DEFAULT_PORTS = [21, 22, 80, 443, 8080]

PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    80: "http",
    443: "https",
    8080: "http-alt"
}

# Curated CVE and Threat Intelligence Knowledge Base
CVE_INTELLIGENCE_BASE = {
    "ftp": [
        {
            "id": "CVE-2011-2523",
            "title": "vsftpd 2.3.4 Backdoor Command Execution",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "The vsftpd version 2.3.4 archive contained a backdoor triggered by a smile smiley in the username.",
            "affectedVersions": "vsftpd 2.3.4",
            "mitigation": "Immediately upgrade vsftpd to >= 3.0.5 and enforce firewall rules."
        },
        {
            "id": "CVE-2020-9273",
            "title": "ProFTPD Use-After-Free in Data Transfer Pool",
            "cvss": 8.8,
            "severity": "HIGH",
            "description": "ProFTPD before 1.3.7 contains an uncaught use-after-free issue in pool memory management.",
            "affectedVersions": "ProFTPD < 1.3.7a",
            "mitigation": "Upgrade ProFTPD to 1.3.7a+ and require encrypted TLS/FTPS."
        }
    ],
    "ssh": [
        {
            "id": "CVE-2023-38408",
            "title": "OpenSSH PKCS#11 Provider Remote Code Execution",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "Flaw in ssh-agent forwarding allows loading untrusted shared libraries via PKCS#11.",
            "affectedVersions": "OpenSSH 5.5p1 - 9.3p1",
            "mitigation": "Upgrade OpenSSH to version 9.3p2 or newer and disable agent forwarding."
        },
        {
            "id": "CVE-2020-15778",
            "title": "OpenSSH scp Command Injection via Shell Metacharacters",
            "cvss": 7.8,
            "severity": "HIGH",
            "description": "scp allows command execution when specially crafted filename strings are transferred.",
            "affectedVersions": "OpenSSH <= 8.3p1",
            "mitigation": "Switch to sftp or rsync over ssh; patch OpenSSH."
        }
    ],
    "http": [
        {
            "id": "CVE-2021-41773",
            "title": "Apache HTTP Server Path Traversal & RCE",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "Path normalization bypass allows reading files outside root directory or remote script execution.",
            "affectedVersions": "Apache 2.4.49, 2.4.50",
            "mitigation": "Upgrade Apache HTTP Server to version 2.4.51 or later immediately."
        },
        {
            "id": "CVE-2021-23017",
            "title": "Nginx DNS Resolver 1-Byte Overwrite",
            "cvss": 7.7,
            "severity": "HIGH",
            "description": "1-byte overwrite in resolver code triggers worker process crash or arbitrary memory write.",
            "affectedVersions": "Nginx 0.6.18 - 1.20.0",
            "mitigation": "Upgrade to Nginx >= 1.20.1."
        }
    ],
    "https": [
        {
            "id": "CVE-2022-3786",
            "title": "OpenSSL X.509 Buffer Overrun Vulnerability",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "Buffer overrun triggered in name constraint checking within X.509 certificates.",
            "affectedVersions": "OpenSSL 3.0.0 - 3.0.6",
            "mitigation": "Upgrade OpenSSL to version 3.0.7 or later and cycle certificates."
        }
    ],
    "http-alt": [
        {
            "id": "CVE-2021-44228",
            "title": "Apache Log4j2 JNDI Injection (Log4Shell)",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": "Unauthenticated RCE via JNDI lookup strings sent in HTTP headers or parameters.",
            "affectedVersions": "Log4j 2.0-beta9 to 2.15.0",
            "mitigation": "Upgrade Log4j to >= 2.17.1 or set log4j2.formatMsgNoLookups=true."
        },
        {
            "id": "CVE-2022-22965",
            "title": "Spring Framework Data Binding RCE (Spring4Shell)",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "Data binding exploitation on JDK 9+ Tomcat environments leading to webshell injection.",
            "affectedVersions": "Spring Framework 5.3.0 - 5.3.17",
            "mitigation": "Upgrade Spring Framework to 5.3.18+ or 5.2.20+."
        }
    ]
}


class ScanTargetRequest(BaseModel):
    target: str = Field(..., description="Target hostname or IP address")
    ports: Optional[List[int]] = Field(default=DEFAULT_PORTS, description="TCP ports to scan")
    timeout: Optional[float] = Field(default=1.5, description="Socket connect timeout in seconds")


class CVEModel(BaseModel):
    id: str
    title: str
    cvss: float
    severity: str
    description: str
    affectedVersions: str
    mitigation: str


class PortScanModel(BaseModel):
    port: int
    service: str
    status: str
    banner: Optional[str] = None
    version: Optional[str] = None
    latencyMs: float
    vulnerabilities: List[CVEModel]
    riskLevel: str
    mitigationTip: str


class ScanResultResponse(BaseModel):
    scanId: str
    target: str
    resolvedIp: str
    timestamp: str
    durationMs: float
    engine: str
    totalPortsScanned: int
    openPortsCount: int
    overallRisk: str
    maxCvss: float
    ports: List[PortScanModel]
    logs: List[str]


def sanitize_banner(raw: bytes) -> str:
    """Decodes and cleans raw TCP socket banners."""
    try:
        decoded = raw.decode("utf-8", errors="ignore").strip()
        # Clean control characters
        cleaned = re.sub(r"[\r\n\x00-\x1f\x7f-\x9f]+", " ", decoded)
        return cleaned[:200]
    except Exception:
        return ""


def extract_version_hint(banner: str, service: str) -> Optional[str]:
    """Identifies software names and versions from banner strings."""
    if not banner:
        return None
    patterns = [
        r"(SSH-[0-9\.\w\-]+)",
        r"(OpenSSH[_\s][0-9\.\w\-]+)",
        r"(Apache/[0-9\.]+)",
        r"(nginx/[0-9\.]+)",
        r"(vsftpd\s+[0-9\.]+)",
        r"(ProFTPD\s+[0-9\.]+)",
        r"(Werkzeug/[0-9\.]+)",
        r"(Express)",
        r"(Node\.js)"
    ]
    for p in patterns:
        match = re.search(p, banner, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


async def probe_single_port(ip: str, port: int, timeout: float = 1.5) -> PortScanModel:
    """Probes a single TCP port using asynchronous non-blocking sockets."""
    service_name = PORT_SERVICE_MAP.get(port, f"service-{port}")
    start_time = time.perf_counter()
    banner = None
    status_str = "CLOSED"

    try:
        # Non-blocking socket connect
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        status_str = "OPEN"
        
        # Banner Grabbing Protocol Handshake
        try:
            if port in [80, 8080]:
                probe_payload = b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: VulnSight-Scanner/1.0\r\n\r\n"
                writer.write(probe_payload)
                await writer.drain()
            elif port == 21:
                # FTP typically sends 220 greeting immediately
                pass
            
            raw_data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            if raw_data:
                banner = sanitize_banner(raw_data)
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    except asyncio.TimeoutError:
        status_str = "FILTERED"
    except (ConnectionRefusedError, OSError):
        status_str = "CLOSED"
    except Exception:
        status_str = "FILTERED"

    latency = round((time.perf_counter() - start_time) * 1000, 2)
    version = extract_version_hint(banner or "", service_name)

    # Vulnerability correlation
    cves: List[CVEModel] = []
    if status_str == "OPEN":
        raw_cves = CVE_INTELLIGENCE_BASE.get(service_name, [])
        for item in raw_cves:
            cves.append(CVEModel(**item))

    # Compute risk
    if not cves or status_str != "OPEN":
        risk_level = "SECURE" if status_str == "CLOSED" else "LOW"
        mitigation = "Port is closed or filtered. Maintain least privilege firewall rules."
    else:
        max_score = max(c.cvss for c in cves)
        if max_score >= 9.0:
            risk_level = "CRITICAL"
        elif max_score >= 7.0:
            risk_level = "HIGH"
        elif max_score >= 4.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        mitigation = f"Audit {service_name.upper()} configurations and apply vendor security patches."

    return PortScanModel(
        port=port,
        service=service_name,
        status=status_str,
        banner=banner,
        version=version,
        latencyMs=latency,
        vulnerabilities=cves,
        riskLevel=risk_level,
        mitigationTip=mitigation
    )


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "VulnSight-Engine", "version": "1.0.0"}


@app.post("/scan", response_model=ScanResultResponse)
async def execute_security_scan(request: ScanTargetRequest):
    start_total = time.perf_counter()
    logs: List[str] = []
    
    logs.append(f"[INIT] VulnSight Scanner Engine received target: {request.target}")
    
    # DNS Resolution
    try:
        resolved_ip = socket.gethostbyname(request.target)
        logs.append(f"[DNS] Successfully resolved {request.target} -> {resolved_ip}")
    except socket.gaierror as e:
        logs.append(f"[ERROR] Failed to resolve target host {request.target}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to resolve host: {request.target}"
        )

    ports_to_scan = request.ports or DEFAULT_PORTS
    logs.append(f"[TASK] Initiating asynchronous socket probe across {len(ports_to_scan)} ports: {ports_to_scan}")

    # Run port scans concurrently with asyncio.gather
    tasks = [probe_single_port(resolved_ip, p, request.timeout) for p in ports_to_scan]
    port_results = await asyncio.gather(*tasks)

    open_ports = [p for p in port_results if p.status == "OPEN"]
    logs.append(f"[AUDIT] Probing completed. Discovered {len(open_ports)} open listening port(s).")

    all_cves = [v for p in port_results for v in p.vulnerabilities]
    max_cvss = max([c.cvss for c in all_cves], default=0.0)

    if max_cvss >= 9.0:
        overall_risk = "CRITICAL"
    elif max_cvss >= 7.0:
        overall_risk = "HIGH"
    elif max_cvss >= 4.0:
        overall_risk = "MEDIUM"
    elif open_ports:
        overall_risk = "LOW"
    else:
        overall_risk = "SECURE"

    total_duration = round((time.perf_counter() - start_total) * 1000, 2)
    logs.append(f"[SUMMARY] Assessment finalized in {total_duration}ms. Threat severity: {overall_risk}")

    return ScanResultResponse(
        scanId=f"SCAN-{int(time.time())}-{resolved_ip.replace('.', '')[:6]}",
        target=request.target,
        resolvedIp=resolved_ip,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        durationMs=total_duration,
        engine="python-fastapi",
        totalPortsScanned=len(ports_to_scan),
        openPortsCount=len(open_ports),
        overallRisk=overall_risk,
        maxCvss=max_cvss,
        ports=port_results,
        logs=logs
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
