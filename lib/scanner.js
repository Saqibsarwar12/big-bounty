'use strict';
/**
 * Big Bounty — real scanning engine (serverless-safe, Vercel-compatible).
 * No simulated results: every finding carries evidence from actual
 * HTTP responses, DNS-over-HTTPS answers, crt.sh, or the NVD API.
 *
 * Modules: recon, subdomains, dirs, exposure, headers, cors, tech,
 *          secrets, xss, sqli, redirect, cves
 */

const crypto = require('crypto');
const { runAttacks } = require('./attacks');
const { runBrowserBot } = require('./browserbot');
function BBKEY() { return process.env.BROWSERBASE_API_KEY; }

// ---------------- wordlists (SecLists-derived, curated) ----------------
const DIR_PATHS = [
  '.env', '.git/HEAD', '.git/config', '.git/logs/HEAD', '.svn/entries',
  '.DS_Store', '.htaccess', 'backup.zip', 'backup.tar.gz', 'backup.sql',
  'db.sql', 'database.sql', 'dump.sql', 'site.zip', 'www.zip',
  'wp-config.php.bak', 'config.php.bak', 'config.php.old', 'web.config.bak',
  'phpinfo.php', 'info.php', 'test.php', 'admin/', 'admin/login', 'administrator/',
  'wp-admin/', 'wp-login.php', 'xmlrpc.php', 'wp-json/wp/v2/users',
  'api/', 'api/v1/', 'api/v2/', 'graphql', 'graphiql', 'swagger', 'swagger.json',
  'api-docs', 'docs/', 'documentation/', 'openapi.json', 'api/openapi.json',
  'robots.txt', 'sitemap.xml', 'crossdomain.xml', '.well-known/security.txt',
  'server-status', 'server-info', '.htpasswd', '.ssh/id_rsa',
  'actuator', 'actuator/health', 'actuator/env', 'actuator/heapdump',
  'console/', 'jenkins/', 'jenkins/script', 'kibana/', 'elasticsearch/',
  '.aws/credentials', 'composer.json', 'package.json', 'yarn.lock',
  'debug/', 'trace', 'status', 'health', 'metrics', 'env',
  'adminer.php', 'phpmyadmin/', 'pma/', 'sql/', 'install.php',
  'rest/', 'v1/', 'v2/', 'users', 'config/', '.config/', 'settings.py',
  'appsettings.json', 'web.config', 'local.settings.json', 'credentials.json',
];

const SUBDOMAINS = [
  'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp',
  'secure', 'vpn', 'm', 'shop', 'ftp', 'mail2', 'test', 'portal', 'ns', 'ww1',
  'host', 'support', 'dev', 'web', 'bbs', 'mx', 'email', 'cloud', '1', 'mail1',
  '2', 'forum', 'owa', 'www2', 'gw', 'admin', 'store', 'mx1', 'cdn', 'api',
  'exchange', 'app', 'gov', '2tty', 'vps', 'govyty', 'hgfgdf', 'news', '1rer',
  'lkjkui', 'beta', 'staging', 'stg', 'prod', 'qa', 'uat', 'demo', 'sandbox',
  'internal', 'intranet', 'git', 'gitlab', 'jira', 'confluence', 'wiki', 'docs',
  'status', 'monitor', 'grafana', 'prometheus', 'kibana', 'elastic', 'db',
  'database', 'mysql', 'postgres', 'redis', 'mongo', 's3', 'assets', 'static',
  'img', 'images', 'media', 'files', 'download', 'downloads', 'auth', 'sso',
  'login', 'account', 'id', 'oauth', 'token', 'gateway', 'gw', 'proxy', 'edge',
  'lb', 'loadbalancer', 'backup', 'old', 'new', 'legacy', 'archive', 'crm',
  'erp', 'hr', 'intranet2', 'cpanel', 'whm', 'plesk', 'direct', 'direct-connect',
];

const XSS_CANARY = 'bbx' + Math.floor(Math.random() * 100000) + 'z';
const XSS_PAYLOADS = [
  `"><svg onload=alert(1)>`,
  `'><img src=x onerror=alert(1)>`,
  `"><script>alert(1)</script>`,
  `javascript:alert(1)`,
  `-alert(1)-"'};alert(1);//`,
];
const SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' ORDER BY 1-- -", "')-- -", "1 UNION SELECT NULL-- -"];
const SQL_ERRORS = [
  'you have an error in your sql syntax', 'warning: mysql', 'unclosed quotation mark',
  'quoted string not properly terminated', 'mysql_fetch', 'mysqli_', 'pg_query',
  'postgresql', 'syntax error at or near', 'ora-', 'oracle error', 'odbc',
  'microsoft sql', 'sqlite3.', 'sqlite_master', 'unterminated quoted string',
  'jdbc', 'sqlstate', 'odbc drivers error', 'invalid query', 'sql syntax',
];
const REDIRECT_PARAMS = ['next', 'redirect', 'return', 'url', 'goto', 'dest', 'target', 'link', 'out', 'continue', 'r', 'u', 'to', 'returnUrl', 'returnTo', 'redirect_uri', 'redirect_url', 'forward'];
const HTTP_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090];

const TECH_SIGNATURES = [
  { name: 'WordPress', m: /wp-content|wp-includes/i },
  { name: 'Next.js', m: /__NEXT_DATA__|\/_next\// },
  { name: 'React', m: /data-reactroot|react-dom|__REACT_DEVTOOLS/i },
  { name: 'Vue.js', m: /data-v-[0-9a-f]{8}|vue\.runtime|vuex/i },
  { name: 'Angular', m: /ng-version|angular\.min\.js|ng-app/i },
  { name: 'jQuery', m: /jquery[.\-/]/i },
  { name: 'Shopify', m: /cdn\.shopify\.com|shopify\.theme/i },
  { name: 'Cloudflare', m: /cloudflare/i, header: 'server' },
  { name: 'Nginx', m: /nginx/i, header: 'server' },
  { name: 'Apache', m: /apache/i, header: 'server' },
  { name: 'Express', m: /express/i, header: 'x-powered-by' },
  { name: 'PHP', m: /php/i, header: 'x-powered-by' },
  { name: 'ASP.NET', m: /asp\.net/i, header: 'x-powered-by' },
  { name: 'Laravel', m: /laravel_session|csrftoken/i },
  { name: 'Django', m: /csrfmiddlewaretoken|__cfhost/i },
  { name: 'Rails', m: /x-request-id|rails/i, header: 'x-powered-by' },
  { name: 'Cloudflare CDN', m: /cloudflare/i, header: 'cf-ray' },
  { name: 'Vercel', m: /.*/, header: 'x-vercel-id' },
  { name: 'Google Analytics', m: /google-analytics\.com|gtag\/js/i },
  { name: 'Stripe', m: /js\.stripe\.com/i },
];

const VERSION_MAP = [
  { rx: /(?:php[/ ])([\d.]+)/i, product: 'PHP', cpe: 'php:php' },
  { rx: /(?:nginx[/ ])([\d.]+)/i, product: 'Nginx', cpe: 'f5:nginx' },
  { rx: /(?:apache[/ ])([\d.]+)/i, product: 'Apache', cpe: 'apache:http_server' },
  { rx: /(?:jquery[/ -])([\d.]+)/i, product: 'jQuery', cpe: 'jquery:jquery' },
  { rx: /(?:wp-content[^\s"]*?ver=)([\d.]+)/i, product: 'WordPress', cpe: 'wordpress:wordpress' },
];

const API_KEY_PATTERNS = [
  { name: 'Google API key', rx: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'AWS Access Key', rx: /AKIA[0-9A-Z]{16}/g },
  { name: 'Stripe key', rx: /(?:sk|pk)_live_[0-9a-zA-Z]{20,}/g },
  { name: 'OpenAI key', rx: /sk-[a-zA-Z0-9]{32,}/g },
  { name: 'GitHub token', rx: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { name: 'JWT', rx: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g },
  { name: 'Slack token', rx: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g },
  { name: 'Firebase', rx: /[0-9a-f]{7}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{13}/g },
];
const EMAIL_RX = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

// ---------------- helpers ----------------
function timeoutFetch(url, opts = {}, ms = 8000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  return fetch(url, { ...opts, signal: ac.signal, redirect: opts.redirect || 'manual' }).finally(() => clearTimeout(t));
}

async function doh(name, type = 'A') {
  try {
    const r = await timeoutFetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } }, 6000);
    if (!r.ok) return null;
    const j = await r.json();
    if (!j.Answer) return [];
    return j.Answer.map(a => ({ type: a.type, data: a.data }));
  } catch { return null; }
}

function hdrs(res) {
  const h = {};
  if (res && res.headers && typeof res.headers.forEach === 'function') {
    res.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
  }
  return h;
}

function nowIso() { return new Date().toISOString(); }

function fid(prefix) { return `${prefix}-${crypto.randomBytes(4).toString('hex')}`; }

// ---------------- modules ----------------
async function moduleRecon(hostname) {
  const out = [];
  const [a, mx, txt, ns, crt] = await Promise.all([
    doh(hostname, 'A'), doh(hostname, 'MX'), doh(hostname, 'TXT'), doh(hostname, 'NS'),
    timeoutFetch(`https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`, {}, 12000).then(r => r.ok ? r.json() : null).catch(() => null),
  ]);

  if (a && a.length) {
    out.push({ id: fid('recon'), tool: 'dns', severity: 'info', title: `A records for ${hostname}`, evidence: a.map(x => x.data) });
    // Reverse-lookup IP origin (whois-style info via RDAP)
    for (const rec of a.slice(0, 2)) {
      const ip = rec.data;
      if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
        try {
          const rd = await timeoutFetch(`https://rdap.arin.net/registry/ip/${ip}`, {}, 6000);
          if (rd.ok) {
            const j = await rd.json();
            out.push({ id: fid('recon'), tool: 'rdap', severity: 'info', title: `IP ${ip} network info`, evidence: { name: j.name, country: j.country, startAddress: j.startAddress, endAddress: j.endAddress } });
          }
        } catch {}
      }
    }
  }
  if (mx && mx.length) out.push({ id: fid('recon'), tool: 'dns', severity: 'info', title: `MX records (mail hosts)`, evidence: mx.map(x => x.data) });
  if (ns && ns.length) out.push({ id: fid('recon'), tool: 'dns', severity: 'info', title: 'Name servers', evidence: ns.map(x => x.data) });
  if (txt && txt.length) {
    const spf = txt.filter(x => /v=spf1/i.test(x.data));
    const dmarc = txt.filter(x => /v=dmarc1/i.test(x.data));
    if (spf.length) out.push({ id: fid('recon'), tool: 'dns', severity: 'info', title: 'SPF record found', evidence: spf.map(x => x.data) });
    else out.push({ id: fid('recon'), tool: 'dns', severity: 'low', title: 'No SPF record — email spoofing possible for this domain', evidence: ['No v=spf1 TXT record'] });
    if (dmarc.length) out.push({ id: fid('recon'), tool: 'dns', severity: 'info', title: 'DMARC record found', evidence: dmarc.map(x => x.data) });
    else out.push({ id: fid('recon'), tool: 'dns', severity: 'low', title: 'No DMARC record — spoofed-mail delivery likely', evidence: ['No v=dmarc1 TXT record'] });
  }

  if (Array.isArray(crt) && crt.length) {
    const subs = [...new Set(crt.flatMap(c => String(c.name_value || '').split('\n').map(s => s.trim().replace(/^\*\./, ''))))].filter(s => s.endsWith(hostname) && s !== hostname).slice(0, 100);
    if (subs.length) out.push({ id: fid('recon'), tool: 'crt.sh', severity: 'info', title: `${subs.length} subdomains from certificate transparency logs`, evidence: subs });
  }
  return out;
}

async function moduleSubdomains(hostname) {
  const base = hostname.replace(/^www\./, '');
  const resolved = [];
  const uniq = [...new Set(SUBDOMAINS)].slice(0, 100);
  // DoH in batches of 10 — real DNS answers only
  for (let i = 0; i < uniq.length; i += 10) {
    const batch = uniq.slice(i, i + 10);
    const results = await Promise.all(batch.map(s => doh(`${s}.${base}`, 'A')));
    results.forEach((r, idx) => {
      if (r && r.length) resolved.push({ subdomain: `${batch[idx]}.${base}`, ips: r.map(x => x.data).slice(0, 2) });
    });
  }
  const findings = [];
  if (resolved.length) {
    findings.push({ id: fid('sub'), tool: 'dns-brute', severity: 'info', title: `${resolved.length} subdomains resolved (of ${uniq.length} probed)`, evidence: resolved });
  }
  return findings;
}

async function moduleDirs(url, isAdvanced) {
  const paths = isAdvanced ? DIR_PATHS : DIR_PATHS.filter(p => ['.env', '.git/HEAD', '.git/config', 'backup.zip', 'db.sql', 'phpinfo.php', 'wp-login.php', 'xmlrpc.php', 'actuator/health', 'swagger.json', 'robots.txt', 'admin/', '.htaccess', '.DS_Store', 'graphql', 'api/', '.htpasswd', 'server-status'].includes(p));
  // baseline for soft-404 detection
  const base404 = `${url}/${XSS_CANARY}-nf-${Math.random().toString(36).slice(2, 8)}`;
  let baseLen = -1, baseStatus = 0;
  try {
    const b = await timeoutFetch(base404, {}, 8000);
    baseStatus = b.status;
    const bt = await b.text().catch(() => '');
    baseLen = bt.length;
  } catch {}

  const found = [];
  const checked = [];
  const BATCH = 8;
  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.all(batch.map(async (p) => {
      try {
        const r = await timeoutFetch(`${url}/${p}`, {}, 7000);
        const body = r.status < 500 ? await r.text().catch(() => '') : '';
        return { p, status: r.status, len: body.length, body: body.slice(0, 4000) };
      } catch { return { p, status: 0, len: 0, body: '' }; }
    }));
    checked.push(...results.map(x => ({ path: x.p, status: x.status })));
    for (const x of results) {
      const isSoft404 = x.status === baseStatus && Math.abs(x.len - baseLen) < 32;
      if (x.status && x.status !== 404 && !isSoft404) {
        let sev = x.status < 300 ? 'medium' : x.status < 400 ? 'low' : 'info';
        // verify exposure by content signature
        if (x.p === '.env' && /={1,}\s*$/m.test(x.body) === false && !/[A-Z_]+=/.test(x.body)) sev = 'info';
        if (x.p.startsWith('.git') && !/ref: refs\//.test(x.body)) sev = 'info';
        if (/phpinfo|Configuration File|DATABASE_PASSWORD|APP_KEY|DB_PASSWORD/i.test(x.body)) sev = 'critical';
        found.push({ id: fid('dir'), tool: 'dirlist', severity: sev, title: `${x.p} → HTTP ${x.status}`, evidence: { url: `${url}/${x.p}`, status: x.status, length: x.len, snippet: x.body.replace(/\s+/g, ' ').slice(0, 300) } });
      }
    }
  }
  return { findings: found, checkedCount: checked.length };
}

async function moduleExposure(url) {
  const checks = [
    { p: '.env', sig: /[A-Z_]{3,}\s*=/, sev: 'critical', name: '.env file exposed' },
    { p: '.git/HEAD', sig: /ref: refs\//, sev: 'critical', name: 'Git repository exposed (.git/HEAD)' },
    { p: '.git/config', sig: /\[core\]/, sev: 'critical', name: 'Git config exposed' },
    { p: '.aws/credentials', sig: /aws_access_key_id/i, sev: 'critical', name: 'AWS credentials exposed' },
    { p: 'backup.sql', sig: /CREATE TABLE|INSERT INTO/i, sev: 'critical', name: 'Database dump exposed' },
    { p: '.htpasswd', sig: /:\$|:\$2y\$|:\$apr1\$/, sev: 'high', name: '.htpasswd exposed' },
  ];
  const out = [];
  for (const c of checks) {
    try {
      const r = await timeoutFetch(`${url}/${c.p}`, {}, 7000);
      if (r.status === 200) {
        const body = await r.text().catch(() => '');
        if (c.sig.test(body)) {
          out.push({ id: fid('exp'), tool: 'exposure', severity: c.sev, title: `${c.name} — verified by content`, evidence: { url: `${url}/${c.p}`, snippet: body.replace(/\s+/g, ' ').slice(0, 300) } });
        }
      }
    } catch {}
  }
  return out;
}

function moduleHeaders(h) {
  const out = [];
  const checks = [
    ['strict-transport-security', 'medium', 'HSTS missing — SSL-stripping possible', 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains'],
    ['content-security-policy', 'high', 'CSP missing — no defense-in-depth against XSS', 'Add a Content-Security-Policy header'],
    ['x-frame-options', 'medium', 'Clickjacking possible (no X-Frame-Options / frame-ancestors)', 'Add X-Frame-Options: DENY or CSP frame-ancestors'],
    ['x-content-type-options', 'low', 'MIME-sniffing possible', 'Add X-Content-Type-Options: nosniff'],
    ['referrer-policy', 'low', 'Referrer leakage possible', 'Add Referrer-Policy: strict-origin-when-cross-origin'],
    ['permissions-policy', 'info', 'No Permissions-Policy declared', 'Declare a Permissions-Policy'],
  ];
  for (const [name, sev, why, fix] of checks) {
    if (!h[name]) {
      out.push({ id: fid('hdr'), tool: 'headers', severity: sev, title: `Missing ${name}`, evidence: { problem: why, fix, responseHeaders: Object.keys(h).slice(0, 20) } });
    }
  }
  if (h['server']) out.push({ id: fid('hdr'), tool: 'headers', severity: 'info', title: `Server header discloses software: ${h['server']}`, evidence: { header: 'server', value: h['server'] } });
  if (h['x-powered-by']) out.push({ id: fid('hdr'), tool: 'headers', severity: 'low', title: `X-Powered-By discloses stack: ${h['x-powered-by']}`, evidence: { header: 'x-powered-by', value: h['x-powered-by'] } });
  const csp = h['content-security-policy'] || '';
  if (csp && /unsafe-inline|unsafe-eval|\*/.test(csp)) {
    out.push({ id: fid('hdr'), tool: 'headers', severity: 'medium', title: 'Weak CSP (unsafe-inline / unsafe-eval / wildcard source)', evidence: { csp: csp.slice(0, 400) } });
  }
  if (h['access-control-allow-origin'] === '*') {
    out.push({ id: fid('hdr'), tool: 'headers', severity: 'low', title: 'CORS allows all origins (ACAO: *)', evidence: { header: 'access-control-allow-origin', value: '*' } });
  }
  return out;
}

async function moduleCors(finalUrl) {
  const evil = 'https://evil-' + XSS_CANARY + '.example.com';
  try {
    const r = await timeoutFetch(finalUrl, { headers: { Origin: evil } }, 8000);
    const h = hdrs(r);
    const acao = h['access-control-allow-origin'];
    const acac = h['access-control-allow-credentials'];
    if (acao === evil || (acao === '*' && acac === 'true')) {
      return [{ id: fid('cors'), tool: 'cors', severity: acao === evil && acac === 'true' ? 'high' : 'low', title: `CORS reflects arbitrary Origin${acac === 'true' ? ' with credentials' : ''}`, evidence: { sentOrigin: evil, responseAllowOrigin: acao, allowCredentials: acac || '(absent)' } }];
    }
    return [{ id: fid('cors'), tool: 'cors', severity: 'info', title: 'CORS does not reflect arbitrary origins', evidence: { sentOrigin: evil, responseAllowOrigin: acao || '(absent)' } }];
  } catch (e) {
    return [{ id: fid('cors'), tool: 'cors', severity: 'info', title: 'CORS check skipped (request failed)', evidence: { error: e.message } }];
  }
}

function moduleTech(body, h) {
  const out = [];
  const haystack = (body || '').slice(0, 200000);
  for (const t of TECH_SIGNATURES) {
    let hit = false, detail = '';
    if (t.header) {
      const v = h[t.header];
      if (v && (t.name === 'Vercel' || t.m.test(v))) { hit = true; detail = `${t.header}: ${v}`; }
    } else if (t.m.test(haystack)) { hit = true; detail = (haystack.match(t.m) || [''])[0].slice(0, 60); }
    if (hit) out.push({ id: fid('tech'), tool: 'fingerprint', severity: 'info', title: `Technology detected: ${t.name}`, evidence: { match: detail } });
  }
  // version extraction
  for (const v of VERSION_MAP) {
    const m = (haystack.match(v.rx) || (h['server'] || '').match(v.rx) || (h['x-powered-by'] || '').match(v.rx));
    if (m) out.push({ id: fid('tech'), tool: 'fingerprint', severity: 'low', title: `${v.product} version disclosed: ${m[1]}`, evidence: { product: v.product, version: m[1], cpe: `cpe:2.3:a:${v.cpe}` } });
  }
  return out;
}

function moduleSecrets(body) {
  const out = [];
  const text = (body || '').slice(0, 300000);
  for (const p of API_KEY_PATTERNS) {
    const matches = text.match(p.rx);
    if (matches && matches.length) {
      out.push({ id: fid('sec'), tool: 'secrets', severity: p.name === 'Firebase' ? 'low' : 'high', title: `${p.name} pattern found in page source (${matches.length} match${matches.length > 1 ? 'es' : ''})`, evidence: matches.slice(0, 3).map(m => m.slice(0, 12) + '…' + m.slice(-4)) });
    }
  }
  const emails = [...new Set(text.match(EMAIL_RX) || [])].slice(0, 15);
  if (emails.length) out.push({ id: fid('sec'), tool: 'secrets', severity: 'info', title: `${emails.length} email address(es) in page source`, evidence: emails });
  const internal = [...new Set((text.match(/https?:\/\/[a-z0-9.\-]*(?:internal|intranet|local|staging|\.corp|\.lan)[a-z0-9.\-\/]*/gi) || []))].slice(0, 10);
  if (internal.length) out.push({ id: fid('sec'), tool: 'secrets', severity: 'low', title: 'Internal/staging URLs referenced in source', evidence: internal });
  return out;
}

async function moduleXss(url) {
  const out = [];
  try {
    const u = new URL(url);
    const params = [...u.searchParams.keys()].slice(0, 6);
    if (!params.length) {
      out.push({ id: fid('xss'), tool: 'xss', severity: 'info', title: 'No query parameters to test for reflected XSS', evidence: { tested: 'GET parameters only' } });
      return out;
    }
    for (const p of params) {
      const testUrl = new URL(url);
      testUrl.searchParams.set(p, XSS_CANARY);
      const r = await timeoutFetch(testUrl.toString(), {}, 8000);
      const body = await r.text().catch(() => '');
      if (body.includes(XSS_CANARY)) {
        const idx = body.indexOf(XSS_CANARY);
        const ctx = body.slice(Math.max(0, idx - 120), idx + 120);
        // determine reflection context
        const before = body.slice(0, idx).match(/<([a-zA-Z][a-zA-Z0-9]*)[^>]*$/);
        const inScript = /<script[\s>]/i.test(body.slice(Math.max(0, idx - 300), idx));
        const inAttr = before && !/>$/.test(before[0]);
        const sev = inScript ? 'high' : inAttr ? 'medium' : 'low';
        out.push({ id: fid('xss'), tool: 'xss', severity: sev, title: `Parameter "${p}" reflects unencoded in ${inScript ? 'script' : inAttr ? 'attribute' : 'body'} context`, evidence: { parameter: p, canary: XSS_CANARY, context: ctx.replace(/\s+/g, ' ').slice(0, 240) }, recommendation: inScript || inAttr ? 'Encode output per context; add CSP. Manual verification with payloads recommended.' : undefined });
      }
    }
    if (!out.length) out.push({ id: fid('xss'), tool: 'xss', severity: 'info', title: 'Parameters do not reflect canary value', evidence: { canary: XSS_CANARY } });
  } catch (e) {
    out.push({ id: fid('xss'), tool: 'xss', severity: 'info', title: `XSS check error: ${e.message}` });
  }
  return out;
}

async function moduleSqli(url) {
  const out = [];
  try {
    const u = new URL(url);
    const params = [...u.searchParams.keys()].slice(0, 4);
    if (!params.length) { return [{ id: fid('sqli'), tool: 'sqli', severity: 'info', title: 'No query parameters to test for SQL injection', evidence: {} }]; }
    let errHits = [];
    for (const p of params) {
      for (const payload of SQLI_PAYLOADS.slice(0, 4)) {
        const t = new URL(url);
        t.searchParams.set(p, payload);
        try {
          const r = await timeoutFetch(t.toString(), {}, 8000);
          const body = (await r.text().catch(() => '')).toLowerCase();
          const matched = SQL_ERRORS.filter(s => body.includes(s));
          if (matched.length) {
            errHits.push({ parameter: p, payload, signatures: matched.slice(0, 3) });
            break;
          }
        } catch {}
      }
    }
    if (errHits.length) {
      out.push({ id: fid('sqli'), tool: 'sqli', severity: 'high', title: `Database error signatures returned when probing parameter(s) ${[...new Set(errHits.map(h => h.parameter))].join(', ')}`, evidence: errHits, recommendation: 'Likely SQL injection sink. Confirm with sqlmap (authorized) before reporting.' });
    } else {
      out.push({ id: fid('sqli'), tool: 'sqli', severity: 'info', title: 'No SQL error signatures observed in probe responses', evidence: { payloads: SQLI_PAYLOADS.slice(0, 4).length } });
    }
  } catch (e) {
    out.push({ id: fid('sqli'), tool: 'sqli', severity: 'info', title: `SQLi check error: ${e.message}` });
  }
  return out;
}

async function moduleRedirect(url) {
  const out = [];
  const probe = 'https://evil-' + XSS_CANARY + '.example.com';
  try {
    const u = new URL(url);
    const params = [...u.searchParams.keys()].filter(p => REDIRECT_PARAMS.includes(p.toLowerCase())).slice(0, 5);
    if (!params.length) return [{ id: fid('red'), tool: 'redirect', severity: 'info', title: 'No redirect-style parameters present', evidence: {} }];
    for (const p of params) {
      const t = new URL(url);
      t.searchParams.set(p, probe);
      const r = await timeoutFetch(t.toString(), {}, 8000);
      const loc = r.headers.get('location');
      const meta = r.status >= 300 && r.status < 400 ? loc : (await r.text().catch(() => '')).match(/http-equiv=["']?refresh["']?[^>]*url=([^"'>\s]+)/i);
      const dest = Array.isArray(meta) ? meta[1] : meta;
      if ((dest || '').includes('evil-' + XSS_CANARY)) {
        out.push({ id: fid('red'), tool: 'redirect', severity: r.status >= 300 && r.status < 400 ? 'medium' : 'low', title: `Open redirect via parameter "${p}"`, evidence: { parameter: p, statusCode: r.status, location: String(dest).slice(0, 200) } });
      }
    }
    if (!out.length) out.push({ id: fid('red'), tool: 'redirect', severity: 'info', title: 'Redirect parameters do not reflect external target', evidence: {} });
  } catch (e) {
    out.push({ id: fid('red'), tool: 'redirect', severity: 'info', title: `Redirect check error: ${e.message}` });
  }
  return out;
}

async function moduleCves(techFindings) {
  const out = [];
  const cpeHits = techFindings.filter(t => t.evidence && t.evidence.cpe).slice(0, 3);
  for (const t of cpeHits) {
    try {
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(t.evidence.cpe + ':' + t.evidence.version + ':*:*:*:*:*:*:*:*')}&resultsPerPage=5`;
      const r = await timeoutFetch(url, {}, 12000);
      if (!r.ok) continue;
      const j = await r.json();
      const vulns = (j.result && j.result.CVE_Items) || [];
      for (const v of vulns.slice(0, 5)) {
        const cve = v.cve;
        const sev = (v.metrics && (v.metrics.cvssMetricV31?.[0]?.cvssData?.baseSeverity || v.metrics.cvssMetricV2?.[0]?.baseSeverity)) || 'unknown';
        out.push({ id: fid('cve'), tool: 'nvd', severity: typeof sev === 'string' ? sev.toLowerCase() : 'unknown', title: `${cve.id}: ${v.cve?.descriptions?.[0]?.value?.slice(0, 120) || 'CVE against ' + t.evidence.product}`, evidence: { product: t.evidence.product, version: t.evidence.version, published: cve.published || v.published, references: (v.cve?.references?.[0]?.url) || undefined } });
      }
      if (!vulns.length) out.push({ id: fid('cve'), tool: 'nvd', severity: 'info', title: `No NVD CVEs listed for ${t.evidence.product} ${t.evidence.version}`, evidence: { cpe: t.evidence.cpe } });
    } catch {}
  }
  return out;
}

async function modulePorts(hostname) {
  const out = [];
  const results = await Promise.all(HTTP_PORTS.map(async (port) => {
    const proto = port === 443 || port === 8443 ? 'https' : 'http';
    try {
      const r = await timeoutFetch(`${proto}://${hostname}:${port}/`, { redirect: 'manual' }, 4000);
      return { port, status: r.status, server: r.headers.get('server') || '' };
    } catch { return { port, status: 0 }; }
  }));
  const open = results.filter(r => r.status > 0);
  if (open.length) {
    out.push({ id: fid('port'), tool: 'http-probe', severity: 'info', title: `${open.length} HTTP port(s) responded: ${open.map(o => o.port).join(', ')}`, evidence: open.map(o => ({ port: o.port, httpStatus: o.status, server: o.server || undefined })) });
    const adminish = open.filter(o => [8080, 8443, 8000, 8888, 9000, 9090].includes(o.port));
    if (adminish.length) out.push({ id: fid('port'), tool: 'http-probe', severity: 'low', title: `Non-standard web port(s) exposed: ${adminish.map(o => o.port).join(', ')} — review what they serve`, evidence: adminish.map(o => ({ port: o.port, httpStatus: o.status, server: o.server || undefined })) });
  } else {
    out.push({ id: fid('port'), tool: 'http-probe', severity: 'info', title: `No HTTP response on ${HTTP_PORTS.length} common ports (from this network)`, evidence: { note: 'Vercel serverless cannot do raw TCP SYN scans; this is an HTTP-response check only' } });
  }
  return out;
}

// ---------------- runner ----------------
async function runScan(target, mode = 'basic', custom = null) {
  const isBasic = mode === 'basic';
  const isAdv = mode === 'advanced';
  const started = Date.now();
  const phases = [];
  const findings = [];
  const note = isAdv
    ? 'Advanced mode: active probes (XSS/SQLi/redirect) were sent. Findings are observations — verify before reporting.'
    : 'Basic mode: non-intrusive checks only.';

  async function track(name, fn) {
    const t0 = Date.now();
    try {
      const r = await fn();
      const list = Array.isArray(r) ? r : (r && Array.isArray(r.findings) ? r.foundings : []);
      if (Array.isArray(list)) findings.push(...list);
      phases.push({ phase: name, status: 'ok', ms: Date.now() - t0 });
    } catch (e) {
      phases.push({ phase: name, status: 'error', error: e.message, ms: Date.now() - t0 });
    }
  }

  let url = target.startsWith('http') ? target : `https://${target}`;
  let u = new URL(url);
  const hostname = u.hostname;

  // initial fetch + redirect chain (real)
  let res = null, body = '', redirectChain = [], finalUrl = url, httpStatus = 0;
  try {
    let current = url;
    for (let i = 0; i < 5; i++) {
      res = await timeoutFetch(current, { redirect: 'manual', headers: { 'user-agent': 'Mozilla/5.0 (compatible; BigBounty/1.0; security-scan)' } }, 12000);
      httpStatus = res.status;
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get('location');
        if (loc) { redirectChain.push({ from: current, to: new URL(loc, current).toString(), status: res.status }); current = new URL(loc, current).toString(); continue; }
      }
      break;
    }
    finalUrl = current;
    u = new URL(finalUrl);
    body = await res.text().catch(() => '');
  } catch (e) {
    return {
      target, finalTarget: url, mode, startedAt: nowIso(), completedAt: nowIso(),
      durationMs: Date.now() - started, httpStatus: 0, redirectChain,
      findings: [{ id: fid('err'), tool: 'fetch', severity: 'high', title: 'Target unreachable', evidence: { error: e.message } }],
      phases: [{ phase: 'fetch', status: 'error', error: e.message }], summary: { critical: 1 }, toolsUsed: ['fetch'], note,
    };
  }

  const h = hdrs(res);

  await track('recon', () => moduleRecon(hostname));
  if (isAdv) await track('subdomains', () => moduleSubdomains(hostname));

  const dirRes = await track('dirs', () => moduleDirs(finalUrl, isAdv));
  if (dirRes && dirRes.found && dirRes.found.length) {
    // exposure verified by content signature (runs when any sensitive path 200s)
    await track('exposure', () => moduleExposure(finalUrl));
  }

  await track('headers', () => moduleHeaders(h));
  await track('cors', () => moduleCors(finalUrl));
  const techF = await track('tech', () => moduleTech(body, h));
  await track('secrets', () => moduleSecrets(body));
  const dirUrls = ((dirRes && (dirRes.found || dirRes.findings)) || []).map(d => (d.url || d)).filter(x => typeof x === 'string').slice(0, 10);

  if (isAdv) {
    await track('xss', () => moduleXss(finalUrl));
    await track('sqli', () => moduleSqli(finalUrl));
    await track('redirect', () => moduleRedirect(finalUrl));
    await track('cves', () => moduleCves(techF || []));
    await track('attacks', async () => {
      const r = await runAttacks({ url: finalUrl, hostname, dirFindings: dirUrls, onPhase: null });
      return (r && r.findings) || [];
    });
  }

  if (BBKEY()) {
    await track('browser-bypass', async () => {
      const r = await runBrowserBot({ url: finalUrl, dirFindings: dirUrls });
      return (r && r.findings) || [];
    });
  }

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity] = (summary[f.severity] || 0) + 1;

  return {
    target, finalTarget: finalUrl, mode, startedAt: nowIso(), completedAt: nowIso(),
    durationMs: Date.now() - started, httpStatus, redirectChain,
    findings, phases, summary, toolsUsed: ['fetch', 'doh-cloudflare', 'crt.sh', 'rdap', 'nvd'].concat(isAdv ? ['http-probe', 'dns-brute', 'attack-engine'] : []).concat(process.env.BROWSERBASE_API_KEY && !isBasic ? ['browserbase-remote-browser'] : []),
    note,
  };
}

module.exports = { runScan };
