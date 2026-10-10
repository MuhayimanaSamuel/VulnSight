import { NextRequest, NextResponse } from 'next/server';

const SCANNER_CORE_URL = process.env.SCANNER_CORE_URL || 'http://localhost:8000';
const COMMAND_INJECTION_REGEX = /[;&|`$><*?!{}\[\]\\]/;

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const rawTarget = body?.target;

    if (!rawTarget || typeof rawTarget !== 'string') {
      return NextResponse.json({ error: 'Target host is required' }, { status: 400 });
    }

    const cleanTarget = rawTarget.trim().toLowerCase().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];

    // Anti-Command Injection Validation
    if (COMMAND_INJECTION_REGEX.test(cleanTarget)) {
      return NextResponse.json(
        { error: 'SECURITY REJECTION: Shell metacharacters detected in target string' },
        { status: 400 }
      );
    }

    // SSRF Cloud Metadata Defense
    if (cleanTarget === '169.254.169.254' || cleanTarget.includes('metadata.google')) {
      return NextResponse.json(
        { error: 'SECURITY REJECTION: Access to cloud metadata IPs is strictly prohibited' },
        { status: 403 }
      );
    }

    // Forward to Python Scanner Core
    const coreResponse = await fetch(`${SCANNER_CORE_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: cleanTarget,
        ports: body?.ports || [21, 22, 23, 80, 443, 445, 3306, 8080],
        enableRecon: body?.enableRecon ?? true,
        enableFuzzing: body?.enableFuzzing ?? true,
        enableAI: body?.enableAI ?? true
      }),
      signal: AbortSignal.timeout(20000)
    });

    if (!coreResponse.ok) {
      const errData = await coreResponse.json().catch(() => ({}));
      return NextResponse.json(
        { error: errData.detail || 'Scanner Core returned an error' },
        { status: coreResponse.status }
      );
    }

    const data = await coreResponse.json();
    return NextResponse.json(data);
  } catch (error: any) {
    return NextResponse.json(
      { error: `Gateway forwarding error: ${error.message}` },
      { status: 502 }
    );
  }
}
