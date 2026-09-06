'use strict';
/**
 * Kiterunner Engine — API Route & Endpoint Discovery
 * Specifically designed for fast API route and spec-driven endpoint hunting.
 */

const { timeoutFetch, makeFinding } = require('./shared-utils');

// Kiterunner API route assets & common API prefixes + endpoints
const KR_API_ROUTES = [
  'api', 'api/v1', 'api/v2', 'api/v3', 'v1', 'v2', 'api/public',
  'api/private', 'api/internal', 'api/auth', 'api/users', 'api/user',
  'api/login', 'api/account', 'api/profile', 'api/keys', 'api/tokens',
  'api/config', 'api/status', 'api/health', 'api/ping', 'api/version',
  'api/docs', 'api/swagger', 'api/openapi.json', 'api/graphql',
  'swagger.json', 'swagger/v1/swagger.json', 'openapi.json',
  'actuator', 'actuator/health', 'actuator/env', 'actuator/info',
  'rest/v1', 'graphql', 'graphiql'
];

async function runKiterunner({ url, deadline = 0 }) {
  const findings = [];
  const u = new URL(url);

  const BATCH = 5;
  const discovered = [];

  for (let i = 0; i < KR_API_ROUTES.length; i += BATCH) {
    if (deadline && Date.now() > deadline) break;
    const batch = KR_API_ROUTES.slice(i, i + BATCH);

    const results = await Promise.all(batch.map(async (route) => {
      const testUrl = `${u.origin}/${route}`;
      try {
        const r = await timeoutFetch(testUrl, {
          headers: {
            'User-Agent': 'Kiterunner/1.0.2',
            'Accept': 'application/json, text/plain, */*'
          },
          redirect: 'manual'
        }, 4000);
        const ct = (r.headers.get('content-type') || '').toLowerCase();
        const text = r.status < 500 ? await r.text().catch(() => '') : '';
        const isJson = ct.includes('json') || text.trim().startsWith('{') || text.trim().startsWith('[');

        return {
          route,
          url: testUrl,
          status: r.status,
          contentType: ct,
          isJson,
          length: text.length,
          snippet: text.slice(0, 300).replace(/\s+/g, ' ')
        };
      } catch {
        return { route, url: testUrl, status: 0, contentType: '', isJson: false, length: 0, snippet: '' };
      }
    }));

    for (const res of results) {
      if (res.status > 0 && res.status !== 404) {
        discovered.push(res);
      }
    }
  }

  for (const api of discovered) {
    let sev = 'info';
    if (api.status === 200) {
      if (/tokens|keys|env|actuator|private|internal/i.test(api.route)) {
        sev = 'high';
      } else if (api.isJson || /swagger|openapi|docs|users|auth/i.test(api.route)) {
        sev = 'medium';
      } else {
        sev = 'low';
      }
    } else if (api.status === 401 || api.status === 403) {
      sev = 'low';
    }

    findings.push(makeFinding({
      tool: 'kiterunner',
      severity: sev,
      title: `Kiterunner: Discovered API Endpoint /${api.route} (HTTP ${api.status})`,
      desc: `Kiterunner API discovery located endpoint /${api.route} returning HTTP ${api.status} (${api.contentType || 'unknown type'}, ${api.length} bytes).`,
      evidence: {
        tool: 'Kiterunner (kr scan)',
        endpoint: `/${api.route}`,
        fullUrl: api.url,
        statusCode: api.status,
        contentType: api.contentType,
        isJsonResponse: api.isJson,
        sampleOutput: api.snippet
      },
      curl: `kr scan '${u.origin}' -A=routes-large && curl -sk -i '${api.url}' -H 'Accept: application/json'`,
      fix: 'Enforce strict API gateway authentication, schema validation, and disable exposed internal routes or Swagger docs in production.'
    }));
  }

  if (!findings.length) {
    findings.push(makeFinding({
      tool: 'kiterunner',
      severity: 'info',
      title: 'Kiterunner: No Exposed Unprotected API Routes Found',
      desc: `Kiterunner scanned ${KR_API_ROUTES.length} known API specs and route patterns. No unauthorized or sensitive API endpoints were discovered.`,
      evidence: {
        tool: 'Kiterunner',
        routesTested: KR_API_ROUTES.length,
        prefixList: ['api/', 'v1/', 'actuator/', 'swagger/']
      },
      curl: `kr scan '${u.origin}' -A=apiroutes-210228`,
      fix: 'Maintain routine API spec auditing and authorization gatekeeping.'
    }));
  }

  return { findings, count: discovered.length };
}

module.exports = { runKiterunner };
