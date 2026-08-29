import { NextResponse } from 'next/server';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

export const maxDuration = 60;

const SEV_COLORS = {
  critical: rgb(0.7, 0.05, 0.05),
  high: rgb(0.85, 0.3, 0.05),
  medium: rgb(0.85, 0.65, 0.05),
  low: rgb(0.2, 0.45, 0.85),
  info: rgb(0.45, 0.45, 0.45),
};

const WIN = { "\u2192": "->", "\u2190": "<-", "\u2713": "OK", "\u2717": "X", "\u2022": "-", "\u00b7": "-", "\u2014": "--", "\u2013": "-", "\u2018": "\x27", "\u2019": "\x27", "\u201c": "\x22", "\u201d": "\x22", "\u2026": "...", "\u00a0": " ", "\u21b3": "|-", "\u2b07": "", "\u2705": "OK", "\u274c": "X" };
function clean(s) {
  return String(s == null ? "" : s).replace(/[\u2190-\u21FF\u2713-\u27BF\u2B00-\u2BFF\u2600-\u26FF\u2700-\u27BF\uFE0F\u200D]/g, (c) => WIN[c] || "").replace(/[\u2018\u2019]/g, "\x27").replace(/[\u201C\u201D]/g, "\x22").replace(/[\u2013\u2014]/g, "-").replace(/\u2026/g, "...").replace(/\u00b7/g, "-").replace(/[^\x20-\x7E\n]/g, (c) => (c.codePointAt(0) < 256 ? c : "?"));
}
function esc(s) {
  return clean(s).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
}
// crude line wrap for Helvetica 10pt (~5.4px per char at this width)
function wrap(text, max = 92) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (line.length <= max) { out.push(line); continue; }
    let cur = '';
    for (const w of line.split(/\s+/)) {
      if ((cur + ' ' + w).trim().length > max) { out.push(cur); cur = w; }
      else cur = (cur + ' ' + w).trim();
    }
    if (cur) out.push(cur);
  }
  return out;
}

function mdReport(d) {
  const host = (() => { try { return new URL(d.finalTarget || d.target).host; } catch { return 'target'; } })();
  const date = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const L = [];
  L.push(`# Big Bounty — Security Assessment: ${host}`);
  L.push('');
  L.push(`- **Target:** ${d.target}`);
  if (d.finalTarget && d.finalTarget !== d.target) L.push(`- **Final URL:** ${d.finalTarget}`);
  L.push(`- **Scan mode:** ${d.scanMode || 'basic'}`);
  L.push(`- **Date:** ${date}`);
  if (d.httpStatus) L.push(`- **HTTP status:** ${d.httpStatus}`);
  L.push('');
  const s = d.summary || {};
  L.push(`## Executive Summary`);
  L.push('');
  L.push(`| Severity | Count |`);
  L.push(`|---|---|`);
  L.push(`| CRITICAL | ${s.critical || 0} |`);
  L.push(`| HIGH | ${s.high || 0} |`);
  L.push(`| MEDIUM | ${s.medium || 0} |`);
  L.push(`| LOW | ${s.low || 0} |`);
  L.push(`| INFO | ${s.info || 0} |`);
  L.push('');
  L.push(`**Total findings:** ${(d.findings || []).length} · **Tools used:** ${(d.toolsUsed || []).join(', ')}`);
  const ai = d.ai || null;
  if (ai && ai.executiveSummary) {
    L.push(`## AI Analyst Summary (${ai.aiProvider || 'AI'}, AI-generated)`);
    L.push('');
    if (ai.riskVerdict) L.push(`**Risk verdict:** ${ai.riskVerdict}${ai.riskReason ? ` — ${ai.riskReason}` : ''}`);
    L.push('');
    L.push(ai.executiveSummary);
    L.push('');
    if (ai.attackNarrative) { L.push(`### Attack narrative`); L.push(''); L.push(ai.attackNarrative); L.push(''); }
    if (Array.isArray(ai.remediation) && ai.remediation.length) {
      L.push(`### Remediation plan`); L.push('');
      ai.remediation.forEach((r, i) => L.push(`${i + 1}. **${r.title}** — ${r.howto || ''}`));
      L.push('');
    }
    if (Array.isArray(ai.nextAttacks) && ai.nextAttacks.length) {
      L.push(`### Next manual attacks`); L.push('');
      ai.nextAttacks.forEach((a) => L.push(`- ${a}`));
      L.push('');
    }
  }
  if (ai && ai.executiveSummary) {
    L.push(`## AI Analyst Summary`);
    L.push('');
    if (ai.riskVerdict) L.push(`**Risk verdict:** ${ai.riskVerdict}${ai.riskReason ? ' - ' + ai.riskReason : ''}`);
    L.push('');
    L.push(ai.executiveSummary);
    L.push('');
    if (ai.attackNarrative) { L.push('**How a real attacker would chain this:**'); L.push(''); L.push(ai.attackNarrative); L.push(''); }
    if (Array.isArray(ai.remediation) && ai.remediation.length) {
      L.push('**Remediation plan (in order):**');
      L.push('');
      ai.remediation.slice(0, 8).forEach((r, i) => L.push(`${i + 1}. **${r.title}** - ${r.howto || ''}`));
      L.push('');
    }
    if (Array.isArray(ai.fpSuspects) && ai.fpSuspects.length) {
      L.push('**Possible false positives to double-check:**');
      L.push('');
      ai.fpSuspects.slice(0, 6).forEach((f) => L.push(`- ${f}`));
      L.push('');
    }
    if (Array.isArray(ai.nextAttacks) && ai.nextAttacks.length) {
      L.push('**Suggested next manual attacks:**');
      L.push('');
      ai.nextAttacks.slice(0, 5).forEach((a) => L.push(`- ${a}`));
      L.push('');
    }
    L.push('_AI-generated analysis (nemotron via ' + (ai.aiProvider || 'AI') + ') - verify before acting._');
    L.push('');
    L.push('---');
    L.push('');
  }
  L.push(`## Findings`);
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const fs2 = [...(d.findings || [])].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  fs2.forEach((f, i) => {
    L.push('');
    L.push(`### ${i + 1}. [${String(f.severity).toUpperCase()}] ${f.title}`);
    L.push('');
    L.push(`- **Tool:** ${f.tool}`);
    if (f.fix) L.push(`- **Recommendation:** ${f.fix}`);
    if (f.curl) { L.push('- **Reproduce:**'); L.push('```bash'); L.push(f.curl); L.push('```'); }
    if (f.evidence) { L.push('- **Evidence:**'); L.push('```json'); L.push(JSON.stringify(f.evidence, null, 2).slice(0, 1200)); L.push('```'); }
  });
  L.push('');
  L.push('---');
  L.push('_Generated by Big Bounty (big-bounty.vercel.app). Findings are observations from automated testing — verify each one before acting. Only test targets you are authorized to test._');
  return L.join('\n');
}

export async function POST(request) {
  let scan;
  try {
    scan = await request.json();
  } catch {
    return NextResponse.json({ error: 'Send the scan result JSON in the request body' }, { status: 400 });
  }
  if (!scan || typeof scan !== 'object' || !scan.target) {
    return NextResponse.json({ error: 'Invalid scan result payload' }, { status: 400 });
  }

  const url = new URL(request.url);
  const format = (url.searchParams.get('format') || 'pdf').toLowerCase();
  const host = (() => { try { return new URL(scan.finalTarget || scan.target).host; } catch { return 'target'; } })();
  const fname = `bigbounty-${host.replace(/[^a-z0-9.-]/gi, '-')}-${new Date().toISOString().slice(0, 10)}`;

  if (format === 'md') {
    return new NextResponse(mdReport(scan), {
      headers: {
        'Content-Type': 'text/markdown; charset=utf-8',
        'Content-Disposition': `attachment; filename="${fname}.md"`,
        'Cache-Control': 'no-store',
      },
    });
  }

  if (format === 'html') {
    const ai = scan.ai || {};
    const h = (x) => String(x == null ? '' : x).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sevColor = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#6b7280' };
    const frows = [...(scan.findings || [])].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9)).map((f, i) => `
  <div class="f">
    <div class="fh"><span class="sev ${f.severity}">#${i + 1} ${h(String(f.severity).toUpperCase())}</span> <b>${h(f.title)}</b> <span class="tool">[${h(f.tool)}]</span></div>
    ${f.fix ? `<div class="fix"><b>Fix:</b> ${h(f.fix)}</div>` : ''}
    ${f.curl ? `<pre class="curl">${h(f.curl)}</pre>` : ''}
    ${f.evidence ? `<details><summary>Evidence</summary><pre>${h(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2).slice(0, 1200))}</pre></details>` : ''}
  </div>`).join('\n');
    const aiHtml = ai.executiveSummary ? `
  <section class="ai">
    <h2>AI Analyst Summary <span class="prov">(${h(ai.aiProvider || 'AI')} · ${h(ai.aiModel || '')})</span></h2>
    ${ai.riskVerdict ? `<p class="verdict"><b>Risk verdict:</b> ${h(ai.riskVerdict)}${ai.riskReason ? ' - ' + h(ai.riskReason) : ''}</p>` : ''}
    <p>${h(ai.executiveSummary)}</p>
    ${ai.attackNarrative ? `<h3>How a real attacker would chain this</h3><p>${h(ai.attackNarrative)}</p>` : ''}
    ${Array.isArray(ai.remediation) && ai.remediation.length ? `<h3>Remediation plan</h3><ol>${ai.remediation.slice(0, 8).map((r) => `<li><b>${h(r.title)}</b> - ${h(r.howto || '')}</li>`).join('')}</ol>` : ''}
    ${Array.isArray(ai.fpSuspects) && ai.fpSuspects.length ? `<h3>Possible false positives</h3><ul>${ai.fpSuspects.slice(0, 6).map((x) => `<li>${h(x)}</li>`).join('')}</ul>` : ''}
    ${Array.isArray(ai.nextAttacks) && ai.nextAttacks.length ? `<h3>Next manual attacks</h3><ul>${ai.nextAttacks.slice(0, 5).map((a) => `<li>${h(a)}</li>`).join('')}</ul>` : ''}
    <p class="note">AI-generated analysis - verify before acting.</p>
  </section>` : '';
    const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Big Bounty Report - ${h(host)}</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:860px;margin:0 auto;padding:20px;color:#1a1a2e;line-height:1.55;background:#fafafa}
header{background:#0b1020;color:#fff;padding:24px;border-radius:12px;margin-bottom:18px}
header h1{margin:0 0 4px;font-size:22px}
header p{margin:2px 0;color:#9fb0d0;font-size:13px}
.f{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:14px;margin:10px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.fh{display:flex;gap:8px;flex-wrap:wrap;align-items:baseline}
.sev{font-weight:800;font-size:11px;padding:2px 8px;border-radius:5px;color:#fff}
.sev.critical{background:#dc2626}.sev.high{background:#ea580c}.sev.medium{background:#ca8a04}.sev.low{background:#2563eb}.sev.info{background:#6b7280}
.tool{color:#6b7280;font-size:12px}
.fix{margin-top:8px;font-size:13px;color:#166534}
pre{background:#0f172a;color:#d7dce3;padding:10px;border-radius:8px;font-size:12px;overflow-x:auto}
.fix{font-size:13px;color:#475569}
details{margin-top:8px}summary{cursor:pointer;color:#2563eb;font-size:12px}
.ai{background:#f4f7ff;border:1px solid #dbe6ff;border-radius:12px;padding:16px;margin:14px 0}
.ai h2{margin-top:0}.prov{font-size:12px;color:#6b7280;font-weight:400}
.verdict{font-size:15px}.note{font-size:11px;color:#6b7280}
table{border-collapse:collapse}td,th{border:1px solid #d5d9e0;padding:6px 14px;font-size:13px}
footer{color:#6b7280;font-size:11px;margin-top:24px;border-top:1px solid #e4e7ec;padding-top:10px}
</style></head>
<body>
<header><h1>BIG BOUNTY - Security Assessment</h1>
<p><b>Target:</b> ${h(scan.target)}${scan.finalTarget && scan.finalTarget !== scan.target ? ` (resolved: ${h(scan.finalTarget)})` : ''}</p>
<p><b>Mode:</b> ${h(String(scan.scanMode || 'basic').toUpperCase())} &nbsp; <b>HTTP:</b> ${h(scan.httpStatus ?? 'n/a')} &nbsp; <b>Date:</b> ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC</p>
</header>
${aiHtml}
<section><h2>Findings by severity</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
<tr><td>Critical</td><td>${(scan.summary || {}).critical || 0}</td></tr>
<tr><td>High</td><td>${(scan.summary || {}).high || 0}</td></tr>
<tr><td>Medium</td><td>${(scan.summary || {}).medium || 0}</td></tr>
<tr><td>Low</td><td>${(scan.summary || {}).low || 0}</td></tr>
<tr><td>Info</td><td>${(scan.summary || {}).info || 0}</td></tr></table>
<p><b>Total:</b> ${(scan.findings || []).length} findings</p></section>
<section><h2>Findings (${(scan.findings || []).length})</h2>
${frows || '<p>No findings recorded for this scan.</p>'}</section>
<footer>Generated by Big Bounty (big-bounty.vercel.app). Findings are observations from automated testing - verify each one before acting. Only test targets you are authorized to test.</footer>
</body></html>`;
    return new NextResponse(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Disposition': `attachment; filename="${fname}.html"`,
        'Cache-Control': 'no-store',
      },
    });
  }

  // ---- PDF ----
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont('Helvetica');
  const bold = await pdf.embedFont('Helvetica-Bold');
  const mono = await pdf.embedFont('Courier');

  const W = 612, H = 792, M = 54;
  let page = pdf.addPage([W, H]);
  let y = H - M;
  const ink = rgb(0.1, 0.1, 0.12);

  const newPage = () => { page = pdf.addPage([W, H]); y = H - M; };
  const need = (n) => { if (y - n < M + 30) newPage(); };

  function text(str, { f = 'reg', size = 9.5, color = ink, x = M, max = W - 2 * M, gap = 4 } = {}) {
    const useFont = f === 'bold' ? bold : f === 'mono' ? mono : font;
    str = clean(str);
    for (const line of wrap(str, Math.floor(max / (size * 0.56)))) {
      need(size + gap);
      page.drawText(line, { x, y, size, font: useFont, color });
      y -= size + gap;
    }
  }
  function heading(str, size = 15) {
    need(size + 14);
    y -= 8;
    page.drawText(esc(str).slice(0, 110), { x: M, y, size, font: bold, color: rgb(0.05, 0.05, 0.08) });
    y -= size + 8;
    page.drawLine({ start: { x: M, y: y + 4 }, end: { x: W - M, y: y + 4 }, thickness: 0.8, color: rgb(0.75, 0.75, 0.8) });
    y -= 10;
  }

  // Cover header
  page.drawRectangle({ x: 0, y: H - 110, width: W, height: 110, color: rgb(0.06, 0.06, 0.1) });
  page.drawText('BIG BOUNTY', { x: M, y: H - 52, size: 24, font: bold, color: rgb(1, 1, 1) });
  page.drawText('SECURITY ASSESSMENT REPORT', { x: M, y: H - 74, size: 10, font: bold, color: rgb(0.65, 0.7, 0.85) });
  page.drawText(`Generated ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`, { x: M, y: H - 94, size: 8.5, color: rgb(0.6, 0.62, 0.7) });
  y = H - 130;

  const s = scan.summary || {};
  const findings = [...(scan.findings || [])].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
  });

  heading('Assessment Overview', 14);
  text(`Target: ${scan.target}`, { f: 'bold', size: 10 });
  if (scan.finalTarget && scan.finalTarget !== scan.target) text(`Resolved to: ${scan.finalTarget}`, { size: 9 });
  text(`Scan mode: ${String(scan.scanMode || 'basic').toUpperCase()}    HTTP status: ${scan.httpStatus ?? 'n/a'}    Duration: ${scan.durationMs ? Math.round(scan.durationMs / 1000) + 's' : 'n/a'}`, { size: 9.5 });
  text(`Tools: ${(scan.toolsUsed || []).join(', ') || 'n/a'}`, { size: 9 });

  y -= 6; need(90);
  page.drawText('Findings by severity', { x: M, y, size: 11, font: bold, color: ink }); y -= 16;
  const rows = [['CRITICAL', s.critical || 0], ['HIGH', s.high || 0], ['MEDIUM', s.medium || 0], ['LOW', s.low || 0], ['INFO', s.info || 0]];
  const total = rows.reduce((n, r) => n + r[1], 0);
  for (const [name, count] of rows) {
    const barW = total ? Math.max(2, (count / total) * 320) : 0;
    page.drawRectangle({ x: M + 90, y: y - 2, width: 320, height: 10, color: rgb(0.93, 0.93, 0.96) });
    if (count > 0) page.drawRectangle({ x: M + 90, y: y - 2, width: barW, height: 10, color: SEV_COLORS[name.toLowerCase()] });
    page.drawText(name, { x: M, y, size: 9, font: bold, color: ink });
    page.drawText(String(count), { x: M + 90 + 328, y, size: 9.5, font: bold, color: ink });
    y -= 17;
  }
  y -= 6;

  const ai = scan.ai || null;
  if (ai && ai.executiveSummary) {
    heading(`AI Analyst Summary (${ai.aiProvider || 'AI'})`, 14);
    if (ai.riskVerdict) text(`Risk verdict: ${ai.riskVerdict}${ai.riskReason ? ' - ' + ai.riskReason : ''}`, { f: 'bold', size: 10 });
    text(ai.executiveSummary, { size: 9.5 });
    if (ai.attackNarrative) { y -= 4; text('Attack narrative:', { f: 'bold', size: 9.5 }); text(ai.attackNarrative, { size: 9 }); }
    if (Array.isArray(ai.remediation) && ai.remediation.length) {
      y -= 4; text('Remediation plan:', { f: 'bold', size: 9.5 });
      ai.remediation.slice(0, 8).forEach((r, i) => text(`${i + 1}. ${r.title} - ${r.howto || ''}`, { size: 9, x: M + 10 }));
    }
    if (Array.isArray(ai.nextAttacks) && ai.nextAttacks.length) {
      y -= 4; text('Next manual attacks:', { f: 'bold', size: 9.5 });
      ai.nextAttacks.slice(0, 5).forEach((a) => text('- ' + a, { size: 9, x: M + 10 }));
    }
    text('(AI-generated analysis - verify before acting.)', { size: 7.5, color: rgb(0.45, 0.45, 0.52) });
    y -= 6;
  }

  heading(`Findings (${findings.length})`, 14);
  if (!findings.length) text('No findings recorded for this scan.', { size: 10 });

  findings.forEach((f, i) => {
    need(70);
    y -= 6;
    const col = SEV_COLORS[String(f.severity).toLowerCase()] || SEV_COLORS.info;
    page.drawRectangle({ x: M, y: y - 4, width: 4, height: 16, color: col });
    page.drawText(`#${i + 1}  ${clean(String(f.severity).toUpperCase())}`, { x: M + 10, y, size: 10, font: bold, color: col });
    page.drawText(`[${clean(f.tool)}]`, { x: M + 80, y, size: 8.5, color: rgb(0.4, 0.4, 0.48) });
    y -= 14;
    text(f.title, { f: 'bold', size: 10 });
    if (f.evidence) {
      text('Evidence:', { f: 'bold', size: 8.5, color: rgb(0.35, 0.35, 0.4) });
      text(JSON.stringify(f.evidence, null, 1).slice(0, 900), { f: 'mono', size: 7.5, color: rgb(0.25, 0.25, 0.3) });
    }
    if (f.curl) {
      text('Reproduce (PoC):', { f: 'bold', size: 8.5, color: rgb(0.35, 0.35, 0.4) });
      text(f.curl.slice(0, 500), { f: 'mono', size: 7.5, color: rgb(0.15, 0.3, 0.15) });
    }
    if (f.fix) {
      text(`Fix: ${f.fix}`.slice(0, 700), { size: 8.5, color: rgb(0.3, 0.3, 0.38) });
    }
  });

  // Footer on every page
  const pages = pdf.getPages();
  pages.forEach((pg, idx) => {
    pg.drawText(`Big Bounty - automated security assessment - page ${idx + 1}/${pages.length}`, { x: M, y: 30, size: 7.5, color: rgb(0.55, 0.55, 0.6) });
    pg.drawText('Findings are observations - verify before acting. Test only authorized targets.', { x: W - M - 250, y: 30, size: 7.5, color: rgb(0.55, 0.55, 0.6) });
  });

  const bytes = await pdf.save();
  return new NextResponse(Buffer.from(bytes), {
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${fname}.pdf"`,
      'Cache-Control': 'no-store',
    },
  });
}