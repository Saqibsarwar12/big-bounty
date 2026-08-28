import { NextResponse } from 'next/server';
import { runScan } from '../../../lib/scanner';

export const maxDuration = 60;

export async function POST(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const target = (body.target || '').trim();
  const mode = body.mode === 'advanced' || body.mode === 'custom' ? body.mode : 'basic';
  const custom = typeof body.custom === 'string' ? body.custom : undefined;

  if (!target) {
    return NextResponse.json({ error: 'target URL is required' }, { status: 400 });
  }
  if (mode === 'custom' && !custom) {
    return NextResponse.json({ error: 'custom mode requires instructions in "custom"' }, { status: 400 });
  }

  const started = Date.now();
  try {
    const result = await runScan(target, mode, custom);
    return NextResponse.json({ ...result, apiDurationMs: Date.now() - started }, {
      headers: {
        'Cache-Control': 'no-store',
        'Access-Control-Allow-Origin': '*',
      },
    });
  } catch (e) {
    return NextResponse.json(
      { error: 'Scan failed: ' + (e && e.message ? e.message : String(e)) },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json({
    service: 'Big Bounty',
    version: '2.0',
    real: true,
    note: 'All findings are backed by live HTTP/DNS/RDAP evidence. No simulated data.',
    usage: {
      'POST /api/scan': { target: 'https://example.com', mode: 'basic|advanced|custom', custom: '(custom mode) free-text instructions' },
    },
    modules: [
      'recon (DNS A/AAAA/MX/NS/TXT/SPF/DMARC via Cloudflare DoH + RDAP)',
      'subdomains (crt.sh + DoH brute of 80-entry curated list)',
      'ports (HTTP probes of 12 common web ports)',
      'dirs (120-entry SecLists-derived path list, soft-404 baseline + content signatures)',
      'exposure (.env/.git/backup verification with content signatures)',
      'headers (security header analysis with actual values as evidence)',
      'cors (wildcard + Origin reflection with credentials)',
      'tech (wappalyzer-style fingerprinting)',
      'secrets (email/API-key/JWT/internal-URL regex harvesting from HTML)',
      'xss (canary reflection + contextual payload probes)',
      'sqli (SQL error signature matching)',
      'redirect (open redirect Location observation)',
      'cves (NVD API 2.0 lookups for detected tech versions)',
    ],
  });
}