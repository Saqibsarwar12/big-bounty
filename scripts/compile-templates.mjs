// Compiles raw nuclei YAML templates into a compact JSON pack for the runtime engine.
import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const yaml = require('js-yaml');

const dir = path.join(process.cwd(), 'templates');
const files = fs.readdirSync(dir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
const out = [];
let skipped = 0;

for (const f of files) {
  let raw;
  try { raw = fs.readFileSync(path.join(dir, f), 'utf8'); } catch { skipped++; continue; }
  if (!raw || raw.length < 20 || raw.startsWith('404')) { skipped++; continue; }
  let doc;
  try { doc = yaml.load(raw); } catch { skipped++; continue; }
  if (!doc || !doc.id || !doc.info || !doc.http) { skipped++; continue; }
  // skip flow-language templates (need real nuclei flow semantics) and payloads/fuzz attacks
  if (doc.flow || doc.atomic) { skipped++; continue; }
  const info = doc.info;
  const sev = String(info.severity || 'info').toLowerCase();
  if (!['critical', 'high', 'medium', 'low', 'info'].includes(sev)) { skipped++; continue; }
  const reqs = [];
  for (const r of doc.http) {
    if (!r || !r.path) continue;
    reqs.push({
      method: String(r.method || 'GET').toUpperCase(),
      path: Array.isArray(r.path) ? r.path : [r.path],
      headers: r.headers && typeof r.headers === 'object' ? r.headers : null,
      body: r.body || null,
      redirects: r.redirects === true,
      maxRedirects: typeof r['max-redirects'] === 'number' ? r['max-redirects'] : undefined,
      stopAtFirstMatch: r['stop-at-first-match'] === true,
      matchersCondition: r['matchers-condition'] || null,
      matchers: Array.isArray(r.matchers) ? r.matchers : [],
      extractors: Array.isArray(r.extractors) ? r.extractors : [],
      raw: r.raw || null,
    });
  }
  if (!reqs.length) { skipped++; continue; }
  const emitCount = reqs.reduce((n, r) => n + (r.matchers || []).filter((m) => m && !m.internal && ['status', 'word', 'regex'].includes(m.type)).length, 0);
  if (emitCount === 0) { skipped++; continue; }
  const verified = !!(info.metadata && info.metadata.verified === true) || !!(info.classification && info.classification['cvss-score'] > 0);
  out.push({
    id: String(doc.id).slice(0, 120),
    name: String(info.name || doc.id).slice(0, 140),
    severity: sev,
    tags: Array.isArray(info.tags) ? info.tags : String(info.tags || '').split(',').map((t) => t.trim()).filter(Boolean),
    classification: info.classification || null,
    verified,
    reqs,
  });
}

fs.mkdirSync(path.join(process.cwd(), 'lib'), { recursive: true });
fs.writeFileSync(path.join(process.cwd(), 'lib', 'nuclei-pack.json'), JSON.stringify(out));
console.log(`compiled ${out.length} templates, skipped ${skipped}, size ${(JSON.stringify(out).length / 1024 / 1024).toFixed(2)} MB`);
