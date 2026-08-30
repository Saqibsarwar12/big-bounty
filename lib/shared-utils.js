/**
 * Shared utilities — single source of truth for makeFinding / curlFor / timeoutFetch
 * (attacks.js, advanced.js, redteam.js, browserbot.js all import from here)
 */
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 BigBounty/1.0';
const CANARY = 'bbx';

function now() { return Date.now(); }

function timeoutFetch(url, opts = {}, ms = 10000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return fetch(url, { ...opts, signal: c.signal, headers: { 'User-Agent': UA, ...(opts.headers || {}) } })
    .finally(() => clearTimeout(t));
}

function curlFor(url, opts = {}) {
  const parts = [`curl -sk -X ${opts.method || 'GET'} '${String(url).replace(/'/g, `'\\''`)}'`];
  for (const [k, v] of Object.entries(opts.headers || {})) parts.push(`-H '${k}: ${v}'`);
  if (opts.body) parts.push(`--data-raw '${String(opts.body).replace(/'/g, `'\\''`)}'`);
  return parts.join(' ');
}

function fid(prefix) { return `${prefix}-${Math.random().toString(36).slice(2, 10)}`; }

function makeFinding(o) {
  return {
    id: fid(o.tool || 'bbx'),
    tool: o.tool || 'bbx',
    severity: o.severity || 'info',
    title: o.title || 'Untitled finding',
    evidence: o.evidence || {},
    fix: o.fix || '',
    curl: o.curl || curlFor(o.url || ''),
    url: o.url || '',
    description: o.description || '',
    remediation: o.remediation || '',
    howBypassed: o.howBypassed || '',
    param: o.param || '',
    payload: o.payload || '',
    tags: o.tags || [],
  };
}

module.exports = { UA, CANARY, now, timeoutFetch, curlFor, fid, makeFinding };
