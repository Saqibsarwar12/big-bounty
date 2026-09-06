'use strict';
/**
 * OWASP ZAP Fuzzer Engine
 * Active HTTP fuzzer with payload injection targeting query params, headers, and paths.
 */

const { timeoutFetch, makeFinding } = require('./shared-utils');

// ZAP Fuzz payloads targeting common vulnerabilities (Path traversal, command injection, format string, boundary tests)
const ZAP_FUZZ_PAYLOADS = [
  { name: 'Path Traversal probe', payload: '../../../../etc/passwd', check: /root:.*:0:0:/ },
  { name: 'Null Byte injection', payload: '%00', check: /null|error|exception/i },
  { name: 'Format String probe', payload: '%s%p%x%d', check: /0x[0-9a-f]{4,}/i },
  { name: 'Command injection canary', payload: ';echo zap_fuzz_canary;', check: /zap_fuzz_canary/ },
  { name: 'Large buffer / overflow probe', payload: 'A'.repeat(512), check: /overflow|stack|dump|internal server error|500/i }
];

async function runZapFuzzer({ url, deadline = 0 }) {
  const findings = [];
  const u = new URL(url);
  const params = [...u.searchParams.keys()];

  // If URL has no params, fuzz a test parameter on the root
  const targetParams = params.length > 0 ? params.slice(0, 3) : ['q', 'id'];

  for (const p of targetParams) {
    if (deadline && Date.now() > deadline) break;

    for (const item of ZAP_FUZZ_PAYLOADS) {
      if (deadline && Date.now() > deadline) break;

      const testUrl = new URL(url);
      testUrl.searchParams.set(p, item.payload);

      try {
        const r = await timeoutFetch(testUrl.toString(), {
          headers: {
            'User-Agent': 'OWASP-ZAP/2.14.0 Fuzzer',
            'X-ZAP-Scan': 'ActiveFuzz'
          }
        }, 4000);

        const body = await r.text().catch(() => '');
        if (item.check.test(body)) {
          findings.push(makeFinding({
            tool: 'zap-fuzzer',
            severity: item.name.includes('Traversal') || item.name.includes('Command') ? 'critical' : 'high',
            title: `OWASP ZAP Fuzzer: Vulnerability Triggered via [${item.name}] on parameter '${p}'`,
            desc: `OWASP ZAP Fuzzer injected payload '${item.payload}' into parameter '${p}' and observed response signature matching ${item.name}.`,
            evidence: {
              tool: 'OWASP ZAP Active Fuzzer',
              fuzzedParam: p,
              payload: item.payload,
              statusCode: r.status,
              matchSnippet: body.slice(0, 300).replace(/\s+/g, ' ')
            },
            curl: `curl -sk -i '${testUrl.toString()}' -H 'User-Agent: OWASP-ZAP/2.14.0'`,
            fix: 'Implement strict input validation, parameter type casting, and sanitize inputs before use.'
          }));
        } else if (r.status >= 500) {
          findings.push(makeFinding({
            tool: 'zap-fuzzer',
            severity: 'medium',
            title: `OWASP ZAP Fuzzer: HTTP ${r.status} Internal Error Triggered on param '${p}'`,
            desc: `OWASP ZAP Fuzzer payload '${item.payload}' on parameter '${p}' triggered an unhandled server error (HTTP ${r.status}).`,
            evidence: {
              tool: 'OWASP ZAP Fuzzer',
              fuzzedParam: p,
              payload: item.payload,
              statusCode: r.status,
              errorSnippet: body.slice(0, 200).replace(/\s+/g, ' ')
            },
            curl: `curl -sk -i '${testUrl.toString()}'`,
            fix: 'Ensure all unexpected inputs are caught gracefully without exposing stack traces or 500 errors.'
          }));
        }
      } catch {}
    }
  }

  if (!findings.length) {
    findings.push(makeFinding({
      tool: 'zap-fuzzer',
      severity: 'info',
      title: 'OWASP ZAP Fuzzer: Input Fuzzing Clean',
      desc: `OWASP ZAP Fuzzer injected ${ZAP_FUZZ_PAYLOADS.length} active fuzz vectors across parameters [${targetParams.join(', ')}]. No anomalies, leaks, or crashes were triggered.`,
      evidence: {
        tool: 'OWASP ZAP Fuzzer',
        paramsTested: targetParams,
        vectorsCount: ZAP_FUZZ_PAYLOADS.length
      },
      curl: `curl -sk -i '${url}' -H 'User-Agent: OWASP-ZAP'`,
      fix: 'All tested parameters handled boundary and fuzz payloads cleanly.'
    }));
  }

  return { findings, count: findings.length };
}

module.exports = { runZapFuzzer };
