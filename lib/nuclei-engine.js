/**
 * Mini-nuclei engine — executes real projectdiscovery/nuclei-templates against a target.
 * Templates are pre-compiled from YAML into lib/nuclei-pack.json (scripts/compile-templates.mjs).
 * Matcher support: status, word, regex (AND/OR conditions). Skips dsl/binary/fuzzing.
 */
const fs = require('fs');
const path = require('path');
const { makeFinding } = require('./attacks');

let PACK = null;
function loadPack() {
  if (PACK) return PACK;
  try {
    PACK = JSON.parse(fs.readFileSync(path.join(__dirname, 'nuclei-pack.json'), 'utf8'));
  } catch {
    PACK = [];
  }
  return PACK;
}

function partText(part, body, headers) {
  const p = (part || 'body').toLowerCase();
  if (p.startsWith('header')) return JSON.stringify(headers || {}).slice(0, 20000);
  if (p === 'body') return body || '';
  if (p.startsWith('interactsh')) return '';
  return (body || '') + '\n' + JSON.stringify(headers || {}).slice(0, 8000);
}

function wordsMatch(words, cond, text) {
  if (cond === 'and') return words.every((w) => text.includes(String(w).toLowerCase()));
  return words.some((w) => text.includes(String(w).toLowerCase()));
}

function regexMatch(pats, cond, text) {
  const test = (p) => { try { return new RegExp(p, 'i').test(text); } catch { return false; } };
  if (cond === 'and') return pats.every(test);
  return pats.some(test);
}

function evalMatcher(m, res) {
  const cond = (m.condition || 'or').toLowerCase();
  if (m.type === 'status') {
    const codes = Array.isArray(m.status) ? m.status : [m.status];
    return codes.includes(res.status);
  }
  const text = partText(m.part, res.body, res.headers);
  if (m.type === 'word') {
    const words = Array.isArray(m.words) ? m.words : [m.words];
    return wordsMatch(words, cond, text.toLowerCase());
  }
  if (m.type === 'regex') {
    const pats = Array.isArray(m.regex) ? m.regex : [m.regex];
    return regexMatch(pats, cond, text);
  }
  return false; // dsl / binary unsupported
}

function evalMatchers(matchers, condition, res) {
  if (!matchers || !matchers.length) return false;
  // internal matchers only gate flows — never sufficient on their own (real nuclei semantics)
  const usable = matchers.filter((m) => m && !m.internal && ['status', 'word', 'regex'].includes(m.type));
  if (!usable.length) return false;
  const cond = (condition || 'or').toLowerCase();
  if (cond === 'and') return usable.every((m) => evalMatcher(m, res));
  return usable.some((m) => evalMatcher(m, res));
}

async function sendReq(method, url, headers, body, ms) {
  try {
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), ms);
    const res = await fetch(url, { method, headers: headers || undefined, body: body || undefined, signal: c.signal, redirect: 'manual' });
    clearTimeout(t);
    const hh = {};
    res.headers.forEach((v, k) => { hh[k] = v; });
    const text = method === 'HEAD' ? '' : (await res.text().catch(() => '')).slice(0, 60000);
    return { status: res.status, headers: hh, body: text };
  } catch { return null; }
}

function curlForTemplate(method, url, headers, body) {
  const hs = Object.entries(headers || {}).map(([k, v]) => `-H ${JSON.stringify(`${k}: ${v}`)}`).join(' ');
  const b = body ? ` --data-raw ${JSON.stringify(body)}` : '';
  return `curl -sk -X ${method} ${JSON.stringify(url)}${hs ? ' ' + hs : ''}${b}`;
}

// Resolve a template path like "{{BaseURL}}/wp-login.php" against the target.
function resolvePath(base, rawPath) {
  if (!rawPath.includes('{{BaseURL}}')) return null;
  let out = rawPath;
  // support {{BaseURL}}:port form
  out = out.replace(/\{\{BaseURL\}\}:(\d+)/, (m, port) => {
    try { const u = new URL(base); u.port = port; return u.toString().replace(/\/$/, ''); } catch { return m; }
  });
  out = out.replace(/\{\{BaseURL\}\}\.?/g, base.replace(/\/+$/, ''));
  if (!/^https?:\/\//.test(out)) return null;
  return out;
}

async function pMap(items, worker, concurrency) {
  const queue = items.slice();
  const runners = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length) {
      const item = queue.shift();
      try { await worker(item); } catch {}
    }
  });
  await Promise.all(runners);
}

async function runNuclei({ url, onProgress, deadlineMs = 150000, concurrency = 12, timeoutPerReq = 8000, severities = null }) {
  const pack = loadPack();
  const allowed = severities ? new Set(severities) : null;
  const targets = allowed ? pack.filter((t) => allowed.has(t.severity)) : pack;
  const findings = [];
  let ran = 0;
  const start = Date.now();

  await pMap(targets, async (tpl) => {
    if (Date.now() - start > deadlineMs) return;
    for (const req of tpl.reqs) {
      if (req.raw || req.payloads) continue;
      if (req.extractors && req.extractors.some((e) => e && (e.type === 'interactsh'))) continue;
      for (const rawPath of (req.path || []).slice(0, 2)) {
        const urlStr = resolvePath(url, rawPath);
        if (!urlStr) continue;
        const res = await sendReq(req.method, urlStr, req.headers, req.body, timeoutPerReq);
        ran++;
        if (onProgress && ran % 100 === 0) onProgress(ran, targets.length);
        if (!res) continue;
        if (!evalMatchers(req.matchers, req.matchersCondition, res)) continue;
        // Unverified status-only matches are noise — downgrade instead of crying wolf
        const onlyStatus = (req.matchers || []).every((m) => m.type === 'status');
        let severity = tpl.severity;
        if (onlyStatus && !tpl.verified && (severity === 'critical' || severity === 'high')) severity = 'info';
        findings.push(makeFinding({
          id: `nuclei-${tpl.id}`,
          tool: 'nuclei',
          severity,
          title: `${tpl.name} [${tpl.id}]`,
          evidence: {
            template: tpl.id,
            url: urlStr,
            status: res.status,
            matched: (req.matchers || []).map((m) => `${m.type}: ${JSON.stringify(m.words || m.regex || m.status || '').slice(0, 80)}`).slice(0, 3),
            snippet: (res.body || '').replace(/\s+/g, ' ').slice(0, 300),
          },
          curl: curlForTemplate(req.method, urlStr, req.headers, req.body),
          fix: (tpl.classification && tpl.classification['remediation-guidance']) || `Review against nuclei template ${tpl.id}`,
        }));
        return; // one hit per template is enough
      }
    }
  }, concurrency);

  return { findings, ran, total: targets.length };
}

module.exports = { runNuclei, loadPack };