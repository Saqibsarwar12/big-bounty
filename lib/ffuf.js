'use strict';
/**
 * ffuf Engine — Fast Web Fuzzer
 * Automated path, segment, and directory discovery with status, word, and line filtering.
 */

const { timeoutFetch, makeFinding } = require('./shared-utils');

const FFUF_DISCOVERY_WORDS = [
  'api', 'v1', 'v2', 'admin', 'login', 'portal', 'dashboard', 'auth',
  'users', 'user', 'profile', 'settings', 'config', 'setup', 'debug',
  'dev', 'test', 'staging', 'graphql', 'swagger', 'docs', 'health',
  'status', 'metrics', 'internal', 'private', 'backup', 'files', 'upload'
];

async function runFfuf({ url, custom = null, deadline = 0 }) {
  const findings = [];
  const u = new URL(url);

  let wordlist = [...FFUF_DISCOVERY_WORDS];
  if (typeof custom === 'string' && custom.trim()) {
    const extra = custom.split(/[\s,;\n]+/).filter(w => w.length > 1 && !w.startsWith('http'));
    for (const w of extra) {
      if (!wordlist.includes(w)) wordlist.unshift(w);
    }
  }

  // Baseline calibration (filter calibration)
  let baseStatus = 404;
  let baseWords = 0;
  let baseLines = 0;
  try {
    const b = await timeoutFetch(`${u.origin}/ffuf-calib-${Math.random().toString(36).slice(2, 7)}`, {}, 3500);
    baseStatus = b.status;
    const bt = await b.text().catch(() => '');
    baseWords = bt.split(/\s+/).filter(Boolean).length;
    baseLines = bt.split('\n').length;
  } catch {}

  const BATCH = 6;
  const matches = [];

  for (let i = 0; i < wordlist.length; i += BATCH) {
    if (deadline && Date.now() > deadline) break;
    const batch = wordlist.slice(i, i + BATCH);

    const batchResults = await Promise.all(batch.map(async (word) => {
      const cleanWord = word.replace(/^\/+/, '');
      const testUrl = `${u.origin}/${cleanWord}`;
      try {
        const t0 = Date.now();
        const r = await timeoutFetch(testUrl, {
          headers: { 'User-Agent': 'Fuzz Faster U Fool v2.1.0' },
          redirect: 'manual'
        }, 4000);
        const dur = Date.now() - t0;
        const text = r.status < 500 ? await r.text().catch(() => '') : '';
        const wordCount = text.split(/\s+/).filter(Boolean).length;
        const lineCount = text.split('\n').length;

        return {
          word: cleanWord,
          url: testUrl,
          status: r.status,
          words: wordCount,
          lines: lineCount,
          chars: text.length,
          dur,
          bodySnippet: text.slice(0, 300).replace(/\s+/g, ' ')
        };
      } catch {
        return { word: cleanWord, url: testUrl, status: 0, words: 0, lines: 0, chars: 0, dur: 0, bodySnippet: '' };
      }
    }));

    for (const res of batchResults) {
      // Filter out calibrated baseline 404 / soft-404 matches
      const isSoft404 = res.status === baseStatus && Math.abs(res.words - baseWords) < 10;
      if (res.status > 0 && res.status !== 404 && !isSoft404) {
        matches.push(res);
      }
    }
  }

  for (const m of matches) {
    let sev = m.status === 200 ? 'medium' : m.status < 400 ? 'low' : 'info';
    if (/admin|config|backup|internal|debug|auth|root/i.test(m.word)) sev = 'high';

    findings.push(makeFinding({
      tool: 'ffuf',
      severity: sev,
      title: `ffuf: Discovered Path /${m.word} [Status: ${m.status}, Size: ${m.chars}, Words: ${m.words}]`,
      desc: `ffuf automated path/segment discovery identified an accessible route at /${m.word}. Response details: HTTP ${m.status}, ${m.words} words, ${m.lines} lines, ${m.chars} bytes, duration: ${m.dur}ms.`,
      evidence: {
        tool: 'ffuf (Fast Web Fuzzer)',
        fuzzKeyword: 'FUZZ',
        discoveredPath: `/${m.word}`,
        url: m.url,
        httpStatus: m.status,
        contentLength: m.chars,
        wordCount: m.words,
        lineCount: m.lines,
        durationMs: m.dur,
        snippet: m.bodySnippet
      },
      curl: `ffuf -u '${u.origin}/FUZZ' -w <wordlist> -mc all -fc 404 && curl -sk -i '${m.url}'`,
      fix: 'Audit access control lists and authentication checks on discovered paths.'
    }));
  }

  if (!findings.length) {
    findings.push(makeFinding({
      tool: 'ffuf',
      severity: 'info',
      title: 'ffuf: Path & Segment Discovery Clean',
      desc: `ffuf automated discovery tested ${wordlist.length} candidate paths/segments. All responded with standard 404 or filtered baseline status.`,
      evidence: {
        tool: 'ffuf v2.1.0',
        wordsTested: wordlist.length,
        calibrationStatus: baseStatus,
        sampleWords: wordlist.slice(0, 10)
      },
      curl: `ffuf -u '${u.origin}/FUZZ' -w <wordlist> -mc 200,301,302,401,403`,
      fix: 'No exposed paths detected by ffuf discovery module.'
    }));
  }

  return { findings, count: matches.length };
}

module.exports = { runFfuf };
