"""
VulnSight Scanner Core - Port Scanning & Banner Grabbing Module
Scans ports 21, 22, 23, 80, 443, 445, 3306, 8080 and extracts service banners.
"""

import asyncio
import re
import time
from typing import Dict, List, Any, Optional

DEFAULT_TARGET_PORTS = [21, 22, 23, 80, 443, 445, 3306, 8080]

PORT_SERVICE_DIRECTORY: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    445: "smb",
    3306: "mysql",
    8080: "http-alt"
}

def clean_banner_text(raw_bytes: bytes) -> str:
    try:
        decoded = raw_bytes.decode('utf-8', errors='ignore').strip()
        cleaned = re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]+', ' ', decoded)
        return cleaned[:160]
    except Exception:
        return ""

async def probe_tcp_port(ip: str, port: int, timeout: float = 1.5) -> Dict[str, Any]:
    service = PORT_SERVICE_DIRECTORY.get(port, f"service-{port}")
    start = time.perf_counter()
    status = "CLOSED"
    banner = None

    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        status = "OPEN"

        # Protocol specific banner grab triggers
        try:
            if port in [80, 8080]:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: VulnSight/1.0\r\n\r\n")
                await writer.drain()
            elif port == 21 or port == 22 or port == 23:
                # FTP, SSH, Telnet greeting sent by daemon immediately
                pass
            
            raw_data = await asyncio.wait_for(reader.read(256), timeout=0.8)
            if raw_data:
                banner = clean_banner_text(raw_data)
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except asyncio.TimeoutError:
        status = "FILTERED"
    except (ConnectionRefusedError, OSError):
        status = "CLOSED"
    except Exception:
        status = "FILTERED"

    latency = round((time.perf_counter() - start) * 1000, 2)

    return {
        "port": port,
        "service": service,
        "status": status,
        "banner": banner,
        "latencyMs": latency
    }

async def scan_all_ports(ip: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    target_ports = ports or DEFAULT_TARGET_PORTS
    tasks = [probe_tcp_port(ip, p) for p in target_ports]
    return await asyncio.gather(*tasks)
