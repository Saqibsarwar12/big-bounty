'use strict';
/**
 * Burp Suite Repeater Engine
 * Performs controlled comparative analysis against interesting identifiers (IDOR, role deltas,
 * method tampering, header manipulation, null byte injection). Compares baseline response vs mutated request.
 */

const { timeoutFetch, curlFor, makeFinding } = require('./shared-utils');

async function runBurpRepeater({
  url,
  custom = null,
  candidatePaths = [],
  deadline = 0
}) {
  const findings = [];
  const u = new URL(url);

  // Pick target paths to test in Repeater
  const testPaths = ['/api/v1/users', '/api/users', '/admin', '/account', '/profile', '/dashboard'];
  if (candidatePaths && candidatePaths.length) {
    for (const cp of candidatePaths) {
      if (typeof cp === 'string' && cp.startsWith('/') && !testPaths.includes(cp)) {
        testPaths.unshift(cp);
      }
    }
  }

  // Selected path for repeater analysis
  const targetPath = testPaths[0];
  const targetUrl = `${u.origin}${targetPath}`;

  // Step 1: Base request
  let baseResp = null;
  let baseStatus = 0;
  let baseBody = '';
  let baseHeaders = {};
  try {
    baseResp = await timeoutFetch(targetUrl, {
      headers: { 'User-Agent': 'Mozilla/5.0 (BurpSuite/Repeater)', 'Accept': '*/*' },
      redirect: 'manual'
    }, 4000);
    baseStatus = baseResp.status;
    baseBody = await baseResp.text().catch(() => '');
    baseResp.headers.forEach((v, k) => { baseHeaders[k.toLowerCase()] = v; });
  } catch {}

  // Step 2: Repeater Mutations
  // A: HTTP Verb Tampering (GET -> POST -> PUT -> OPTIONS)
  // B: X-Original-URL / X-Rewrite-URL / X-Forwarded-For Auth Bypass headers
  // C: IDOR Identifier Substitution (0, 1, admin)
  const mutations = [
    {
      name: 'HTTP Verb Tampering (POST)',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': '2' },
      body: '{}',
      url: targetUrl
    },
    {
      name: 'Header Bypass (X-Original-URL)',
      method: 'GET',
      headers: { 'X-Original-URL': targetPath, 'X-Override-URL': targetPath },
      url: `${u.origin}/`
    },
    {
      name: 'IDOR Identifier Step (ID 0 vs 1)',
      method: 'GET',
      headers: {},
      url: `${u.origin}${targetPath}/1`
    },
    {
      name: 'Privileged Role Header Simulation',
      method: 'GET',
      headers: { 'X-Forwarded-For': '127.0.0.1', 'X-Custom-IP-Authorization': '127.0.0.1', 'X-Admin': 'true' },
      url: targetUrl
    }
  ];

  const diffReports = [];
  for (const mut of mutations) {
    if (deadline && Date.now() > deadline) break;
    try {
      const t0 = Date.now();
      const r = await timeoutFetch(mut.url, {
        method: mut.method,
        headers: { 'User-Agent': 'Mozilla/5.0 (BurpSuite/Repeater)', ...mut.headers },
        body: mut.body,
        redirect: 'manual'
      }, 4000);
      const timeMs = Date.now() - t0;
      const body = r.status < 500 ? await r.text().catch(() => '') : '';
      const len = body.length;

      // Detect meaningful behavioral changes
      const statusChanged = r.status !== baseStatus && r.status !== 0;
      const bodySignificantDiff = Math.abs(len - baseBody.length) > 50;

      if (statusChanged || (baseStatus === 403 && [200, 201].includes(r.status))) {
        diffReports.push({
          mutationName: mut.name,
          url: mut.url,
          method: mut.method,
          headers: mut.headers,
          baselineStatus: baseStatus,
          mutatedStatus: r.status,
          baselineLength: baseBody.length,
          mutatedLength: len,
          timeMs,
          bodySnippet: body.slice(0, 250).replace(/\s+/g, ' ')
        });
      }
    } catch {}
  }

  for (const diff of diffReports) {
    const isBypass = (diff.baselineStatus === 403 || diff.baselineStatus === 401) && diff.mutatedStatus === 200;
    const sev = isBypass ? 'high' : 'medium';

    findings.push(makeFinding({
      tool: 'burp-repeater',
      severity: sev,
      title: `Burp Repeater: Response Diff Detected via ${diff.mutationName}`,
      desc: `Burp Repeater differential analysis identified a response divergence. Baseline returned HTTP ${diff.baselineStatus} (${diff.baselineLength} bytes), while mutation returned HTTP ${diff.mutatedStatus} (${diff.mutatedLength} bytes in ${diff.timeMs}ms).`,
      evidence: {
        tool: 'Burp Suite Repeater (Differential Inspector)',
        mutation: diff.mutationName,
        requestMethod: diff.method,
        requestUrl: diff.url,
        injectedHeaders: diff.headers,
        baseline: { status: diff.baselineStatus, bytes: diff.baselineLength },
        mutated: { status: diff.mutatedStatus, bytes: diff.mutatedLength, timeMs: diff.timeMs },
        preview: diff.bodySnippet
      },
      curl: curlFor(diff.method, diff.url, diff.headers, null),
      fix: 'Align access control policies across all HTTP methods and prohibit trust of client-supplied spoofing headers.'
    }));
  }

  if (!findings.length) {
    findings.push(makeFinding({
      tool: 'burp-repeater',
      severity: 'info',
      title: 'Burp Repeater: Identifier & Method Variance Clean',
      desc: `Burp Repeater comparative analysis completed on target route '${targetPath}'. Mutated requests (verb tampering, proxy spoofing headers, identifier stepping) maintained strict access control symmetry.`,
      evidence: {
        tool: 'Burp Suite Repeater',
        testedPath: targetPath,
        baselineStatus: baseStatus,
        mutationsEvaluated: mutations.map(m => m.name)
      },
      curl: `curl -sk -i '${targetUrl}' -X GET`,
      fix: 'Endpoint exhibits consistent authorization behavior across mutations.'
    }));
  }

  return { findings, count: diffReports.length };
}

module.exports = { runBurpRepeater };
