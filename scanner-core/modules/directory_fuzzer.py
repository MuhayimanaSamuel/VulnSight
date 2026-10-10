"""
VulnSight Scanner Core - Sensitive Directory & Endpoint Enumeration Module
Checks critical web endpoints (e.g., /.env, /admin, /config.php, /robots.txt).
"""

import asyncio
from typing import List, Dict, Any
import httpx

SENSITIVE_PATHS = [
    {"path": "/robots.txt", "description": "Search Engine Crawler Disclosures", "risk": "INFORMATIONAL"},
    {"path": "/.env", "description": "Environment Secrets & API Credentials", "risk": "CRITICAL"},
    {"path": "/admin", "description": "Administrative Portal / Control Panel", "risk": "HIGH"},
    {"path": "/config.php", "description": "Application Configuration File", "risk": "HIGH"},
    {"path": "/.git/HEAD", "description": "Exposed Version Control Repository", "risk": "CRITICAL"},
    {"path": "/api/v1", "description": "Public API Schema / Endpoints", "risk": "LOW"},
    {"path": "/backup.zip", "description": "Legacy Compressed Database / Source Backup", "risk": "CRITICAL"},
    {"path": "/server-status", "description": "Apache / Server Telemetry Diagnostic Page", "risk": "MEDIUM"}
]

async def check_single_path(client: httpx.AsyncClient, base_url: str, item: Dict[str, str]) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{item['path']}"
    try:
        resp = await client.get(url)
        is_accessible = resp.status_code in [200, 206, 301, 302, 401, 403]
        return {
            "path": item["path"],
            "statusCode": resp.status_code,
            "accessible": resp.status_code == 200,
            "description": item["description"],
            "risk": item["risk"] if resp.status_code == 200 else "SECURE",
            "contentLength": len(resp.content)
        }
    except Exception:
        return {
            "path": item["path"],
            "statusCode": 0,
            "accessible": False,
            "description": item["description"],
            "risk": "SECURE",
            "contentLength": 0
        }

async def fuzz_sensitive_paths(target: str) -> List[Dict[str, Any]]:
    base_url = f"https://{target}"
    headers = {"User-Agent": "VulnSight-Audit-Engine/1.0"}
    
    async with httpx.AsyncClient(timeout=2.0, verify=False, follow_redirects=False, headers=headers) as client:
        # Check HTTPS first, if unreachable fallback to HTTP
        try:
            await client.get(base_url)
        except Exception:
            base_url = f"http://{target}"

        tasks = [check_single_path(client, base_url, item) for item in SENSITIVE_PATHS]
        return await asyncio.gather(*tasks)
