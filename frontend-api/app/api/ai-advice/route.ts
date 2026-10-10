import { NextRequest, NextResponse } from 'next/server';
import { GoogleGenAI } from '@google/genai';

export async function POST(req: NextRequest) {
  try {
    const profile = await req.json();
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return NextResponse.json({
        engine: 'Rule-Based-Engine',
        executiveSummary: 'Security profile processed. Set GEMINI_API_KEY for dynamic generative analysis.',
        vulnerabilities: [],
        educationalAttackWalkthrough: 'Standard network audit complete.',
        defensiveHardeningChecklist: ['Audit perimeter firewalls', 'Decommission obsolete listeners']
      });
    }

    const ai = new GoogleGenAI({ apiKey });
    const prompt = `
You are an expert Application Security and DevSecOps Engineer analyzing a network scan.
Profile: ${JSON.stringify(profile)}

Provide educational threat modeling and defensive remediation in strictly valid JSON:
{
  "engine": "gemini-3.8-flash",
  "executiveSummary": "Executive summary of exposure",
  "vulnerabilities": [
    {
      "cve": "CVE ID or CWE ID",
      "title": "Vulnerability title",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "cvss": 8.5,
      "affectedComponent": "Port or Path",
      "exploitationMechanic": "Theoretical explanation of how an adversary leverages this weakness",
      "remediation": "Step-by-step administrator hardening guide"
    }
  ],
  "educationalAttackWalkthrough": "High-level concept walkthrough of the exploit path",
  "defensiveHardeningChecklist": [
    "Concrete hardening step 1",
    "Concrete hardening step 2"
  ]
}
`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json'
      }
    });

    const parsed = JSON.parse(response.text || '{}');
    return NextResponse.json(parsed);
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
