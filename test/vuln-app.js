// Deliberately vulnerable app — LOCAL TEST TARGET ONLY
// Used to verify Big Bounty's attack engine actually bypasses things.
const http = require('http');
const { URL } = require('url');

// fake users DB
const users = [{ id: 1, user: 'admin', pass: 's3cr3t-admin-pass', role: 'administrator' }];
const sessions = new Set();

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  // VULN 1: SQLi login (string-concat) — POST /login
  if (p === '/login' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const user = params.get('username') || '';
      const pass = params.get('password') || '';
      // VULNERABLE: raw string concat — payloads like admin'-- bypass
      const query = `SELECT * FROM users WHERE user='${user}' AND pass='${pass}'`;
      // emulate: ' OR '1'='1 / admin'-- → truthy
      const bypassed = /'\s*--|or\s+'?1'?\s*=\s*'?1|or\s+''='/i.test(user) || /'\s*--|or\s+'?1'?\s*=\s*'?1/i.test(pass);
      if (users.some((x) => x.user === user && x.pass === pass) || bypassed) {
        const sid = 'sid_' + Math.random().toString(36).slice(2);
        sessions.add(sid);
        res.setHeader('Set-Cookie', `session=${sid}; HttpOnly`);
        res.writeHead(302, { Location: '/admin' });
        res.end();
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body><h1>Admin Login</h1><form method=POST action=/login><input name=username><input name=password type=password><button>Login</button></form><p>Invalid credentials</p></body></html>');
      }
    });
    return;
  }

  // login page
  if (p === '/login' || p === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><head><title>Corp Admin</title></head><body><h1>Admin Login</h1><form method=POST action=/login><input name=username><input name=password type=password><button>Login</button></form></body></html>');
    return;
  }

  // admin panel (auth by session cookie)
  if (p === '/admin') {
    const cookie = req.headers.cookie || '';
    const sid = (cookie.match(/session=(sid_[a-z0-9]+)/) || [])[1];
    if (!sid || !sessions.has(sid)) {
      res.writeHead(302, { Location: '/login' });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>Welcome Admin</h1><p>Secret dashboard — user list, orders, everything.</p></body></html>');
    return;
  }

  // VULN 2: LFI — GET /download?file=
  if (p === '/download') {
    const f = u.searchParams.get('file') || '';
    try {
      // VULNERABLE: no path normalization
      const fs = require('fs');
      const content = fs.readFileSync(f, 'utf8');
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(content.slice(0, 2000));
    } catch (e) {
      res.writeHead(404);
      res.end('not found');
    }
    return;
  }

  // VULN 3: reflected XSS — GET /search?q=
  if (p === '/search') {
    const q = u.searchParams.get('q') || '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><head><title>Search</title></head><body><h1>Results for: ${q}</h1><p>No matches.</p></body></html>`);
    return;
  }

  // VULN 4: SSRF — GET /fetch?url=
  if (p === '/fetch') {
    const target = u.searchParams.get('url') || '';
    if (target) {
      const proto = target.startsWith('https') ? require('https') : require('http');
      const r = proto.get(target, { timeout: 4000 }, (up) => {
        let d = '';
        up.on('data', (c) => (d += c));
        up.on('end', () => { res.writeHead(200); res.end(d.slice(0, 500)); });
      });
      r.on('error', () => { res.writeHead(200); res.end('fetch error'); });
      r.on('timeout', () => { r.destroy(); res.writeHead(200); res.end('timeout'); });
    } else {
      res.writeHead(200); res.end('provide ?url=');
    }
    return;
  }

  // VULN 5: open redirect — GET /redirect?to=
  if (p === '/redirect') {
    res.writeHead(302, { Location: u.searchParams.get('to') || '/' });
    res.end();
    return;
  }

  // SSTI: renders q through a fake template engine ({{expr}} evaluated)
  if (u.pathname === '/render') {
    let tpl = u.searchParams.get('q') || '';
    try { tpl = String(tpl).replace(/\{\{\s*([0-9+*\-() ]+)\s*\}\}/g, (_, e) => String(eval(e))); } catch {}
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>Rendered: ' + tpl + '</body></html>');
    return;
  }

  // RCE: command injection in a "diagnostics" param
  if (u.pathname === '/diag' && u.searchParams.has('host')) {
    const { exec } = require('child_process');
    const h = String(u.searchParams.get('host'));
    if (/^[a-zA-Z0-9.\-]+$/.test(h)) {
      exec('ping -c 1 -W 1 ' + h, { timeout: 4000 }, (err, so, se) => {
        res.writeHead(200); res.end('PING OUTPUT:\n' + ((so || '') + (se || '')).slice(0, 400));
      });
      return;
    }
    // vulnerable branch: no shell metacharacter filtering
    exec('ping -c 1 -W 1 ' + h, { timeout: 4000, shell: '/bin/bash' }, (err, so, se) => {
      res.writeHead(200); res.end('PING OUTPUT:\n' + ((so || '') + (se || '')).slice(0, 400));
    });
    return;
  }

  res.writeHead(404);
  res.end('404');
});

server.listen(4545, '127.0.0.1', () => console.log('vuln-app on http://127.0.0.1:4545'));
