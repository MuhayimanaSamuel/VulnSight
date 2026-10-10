import { NextRequest, NextResponse } from 'next/server';

const SCANNER_CORE_URL = process.env.SCANNER_CORE_URL || 'http://localhost:8000';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const target = body?.target?.trim();

    if (!target) {
      return NextResponse.json({ error: 'Target is required' }, { status: 400 });
    }

    const res = await fetch(`${SCANNER_CORE_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, enableRecon: true, enableFuzzing: false, enableAI: false }),
      signal: AbortSignal.timeout(10000)
    });

    const data = await res.json();
    return NextResponse.json(data.recon || {});
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
