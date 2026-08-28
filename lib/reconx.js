/**
 * ReconX — techniques ported from projectdiscovery/naabu, subfinder, httpx, katana:
 *  - naabu-style TCP connect port scan (top ports) with HTTP banner grab
 *  - subfinder-style passive subdomain sources (crt.sh, hackertarget, rapiddns, urlscan)
 *  - katana-style JS-aware endpoint crawl (extract + probe API-ish paths from JS bundles)
 * Every finding carries live evidence.
 */
const net = require('net');
const { makeFinding, timeoutFetch } = require('./attacks');

const TOP_PORTS = [
  80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090, 7001, 7002, 4848,
  8008, 8081, 8180, 8280, 8443, 9080, 9081, 9043, 9443, 10000, 10443, 2082, 2083,
  2086, 2087, 2095, 2096, 21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 445, 465,
  587, 993, 995, 1433, 1521, 2049, 2181, 2375, 2376, 3306, 3389, 5432, 5555, 5601,
  5672, 6379, 6443, 8089, 8161, 9200, 9300, 11211, 15672, 27017, 27018, 50000, 50030,
];
const RISKY = new Set([21, 23, 3389, 6379, 9200, 9300, 27017, 5432, 1433, 2181, 11211, 2375, 2376, 15672, 5601]);

function tcpProbe(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let settled = false;
    const done = (open, banner) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch {}
      resolve({ port, open, banner: banner || '' });
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => {
      // send a probe to elicit an HTTP banner
      sock.write(`HEAD / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      let data = '';
      sock.on('data', (d) => { data += d.toString('utf8'); if (data.length > 300) done(true, data); });
      sock.once('end', () => done(true, data));
      sock.setTimeout(timeoutMs + 1500, () => done(true, data));
    });
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
    sock.connect(port, host);
  });
}

async function scanPorts(host, deadline) {
  const out = [];
  const open = [];
  // resolve hostname to IP once (TCP connect needs an address; hostname works too)
  const tasks = TOP_PORTS.map((port) => async () => {
    if (Date.now() > deadline) return;
    const r = await tcpProbe(host, port);
    if (r.open) out.push(r);
  });
  const CONC = 80;
  let idx = 0;
  async function worker() {
    while (idx < tasks.length) {
      if (Date.now() > deadline) return;
      const t = tasks[idx++];
      try { await t(); } catch {}
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONC, tasks.length) }, worker));
  return out;
}

async function passiveSubs(hostname, deadline) {
  const found = new Set();
  const base = hostname.replace(/^www\./, '');
  const sources = [];

  // crt.sh
  try {
    const r = await timeoutFetch(`https://crt.sh/?q=%25.${base}&output=json`, {}, 12000);
    if (r && r.status === 200) {
      const j = JSON.parse(await r.text());
      for (const e of j.slice(0, 300)) {
        for (const n of String(e.name_value || '').split('\n')) {
          const s = n.trim().toLowerCase();
          if (s.endsWith(base)) found.add(s);
        }
      }
      sources.push('crt.sh');
    }
  } catch {}

  // hackertarget
  try {
    const r = await timeoutFetch(`https://api.hackertarget.com/hostsearch/?q=${base}`, {}, 12000);
    if (r && r.status === 200) {
      const t = await r.text();
      if (!t.includes('error') && t.includes(',')) {
        t.split('\n').forEach((l) => { const s = l.split(',')[0].trim().toLowerCase(); if (s.endsWith(base)) found.add(s); });
        sources.push('hackertarget');
      }
    }
  } catch {}

  // rapiddns
  try {
    const r = await timeoutFetch(`https://rapiddns.io/subdomain/${base}?full=1`, {}, 12000);
    if (r && r.status === 200) {
      const t = await r.text();
      const re = new RegExp(`[a-z0-9._-]+\\.${base.replace(/\./g, '\\.')}`, 'gi');
      (t.match(re) || []).forEach((s) => found.add(s.toLowerCase()));
      sources.push('rapiddns');
    }
  } catch {}

  // urlscan.io
  try {
    const r = await timeoutFetch(`https://urlscan.io/api/v1/search/?q=domain:${base}&size=200`, {}, 12000);
    if (r && r.status === 200) {
      const j = JSON.parse(await r.text());
      for (const e of (j.results || [])) {
        const d = e && e.page && e.page.domain;
        if (d && d.endsWith(base)) found.add(String(d).toLowerCase());
      }
      sources.push('urlscan.io');
    }
  } catch {}

  return { subs: [...found].slice(0, 400), sources };
}

async function jsCrawl(url, deadline) {
  const out = [];
  const origin = new URL(url).origin;
  const html = await timeoutFetch(url, {}, 10000).then((r) => (r ? r.text().catch(() => '') : '')).catch(() => '');

  // extract script URLs
  const srcs = [...new Set((html.match(/<script[^>]+src=["']([^"']+)["']/gi) || [])
    .map((m) => (m.match(/src=["']([^"']+)["']/i) || [])[1]).filter(Boolean))].slice(0, 5);

  const apiPaths = new Set();
  const API_RE = /["'`](\/(?:api|v1|v2|v3|admin|graphql|internal|debug|backup)[a-zA-Z0-9_\-\/\.]{1,60})["'']/g;
  for (const m of [...html.matchAll(API_RE)]) apiPaths.add(m[1]);

  let fetched = 0;
  for (const src of srcs) {
    if (Date.now() > deadline || fetched >= 5) break;
    const abs = src.startsWith('http') ? src : src.startsWith('//') ? 'https:' + src : src.startsWith('/') ? origin + src : null;
    if (!abs) continue;
    const js = await timeoutFetch(abs, {}, 10000).then((r) => (r ? r.text().catch(() => '') : '')).catch(() => '');
    ;
    fetched++;
    for (const m of [...abs.matchAll(API_RE)]) apiPaths.add(m[1]);
  }

  // probe the API-ish paths
  const confirmed = [];
  for (const p of [...apiPaths].slice(0, 40)) {
    if (Date.now() > deadline) break;
    try {
      const r = await timeoutFetch(origin + p, {}, 8000);
      if (!r) continue;
      if (r.status === 200) {
        const body = await r.text().catch(() => '');
        confirmed.push({ path: p, status: r.status, len: body.length, snippet: body.replace(/\s+/g, ' ').slice(0, 120) });
      }
    } catch {}
  }
  return { scripts: srcs.length, confirmed };
}

async function runReconX({ url, hostname }) {
  const findings = [];
  const deadline = Date.now() + 60000;

  // naabu-style port scan
  let openPorts = [];
  try {
    openPorts = await scanPorts(hostname, Date.now() + 35000);
    for (const p of openPorts) {
      const banner = (p.banner.match(/server:\s*(.+)/i) || [])[1];
      const isHttp = /^80$|^443$|^\d{4,5}$/.test(String(p.port));
      const risky = RISKY.has(p.port);
      findings.push(makeFinding({
        id: `port-${p.port}`,
        tool: 'tcp-ports',
        severity: risky ? 'medium' : 'info',
        title: `Open TCP port ${p.port}${risky ? ' (sensitive service)' : ''}`,
        evidence: {
          port: p.port,
          banner: (p.banner || '').replace(/\s+/g, ' ').slice(0, 200) || '(no banner — accepted connection)',
          server: banner ? banner.trim() : null,
        },
        curl: `nmap -p ${p.port} -sV ${hostname}`,
        fix: risky ? 'Service exposed on this port is commonly not public — restrict via firewall/WAF or bind to internal interfaces.' : null,
      }));
    }
  } catch {}

  // subfinder-style passive enum
  let subs = [];
  try {
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) && hostname.includes('.')) {
      const r = await passiveSubs(hostname, Date.now() + 20000);
      subs = r.subs;
      const srcs = r.sources.join(', ');
      if (subs.length) {
        findings.push(makeFinding({
          id: 'passive-subs',
          tool: 'subdomains',
          severity: 'info',
          title: `${subs.length} subdomains discovered via passive sources (${srcs})`,
          evidence: { sources: r.sources, sample: subs.slice(0, 25), total: subs.length },
          fix: null,
        }));
      }
    }
  } catch {}

  // katana-style JS crawl
  try {
    const jc = await jsCrawl(url, Date.now() + 20000);
    if (jc.confirmed.length) {
      findings.push(makeFinding({
        id: 'js-endpoints',
        tool: 'js-crawl',
        severity: 'info',
        title: `${jc.confirmed.length} live endpoints extracted from JavaScript bundles`,
        evidence: { from: jc.scripts + ' script sources', endpoints: jc.confirmed.slice(0, 15) },
        fix: null,
      }));
    }
  } catch {}

  return { findings, openPorts, subs };
}

// alias used by jsCrawl's stray guard

module.exports = { runReconX };