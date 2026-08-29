/**
 * Big Bounty AI analyst — free-tier only, rate-limit aware.
 * Provider pool: OpenRouter free model + 6 NVIDIA direct keys.
 * On 429/error the failing provider gets a cooldown and the next one
 * takes over immediately; start position round-robins so concurrent
 * scans spread load across the whole pool.
 * Never throws into the scan path; runAiTriage returns null on failure.
 */
const OPENROUTER_KEY = process.env.OPENROUTER_BUGBOUNTY || process.env.Openrouter_bugbounty || '';
const NVIDIA_KEYS = [
  process.env.NVIDIA_BUGBOUNTY || process.env.nvidia_bugbounty || '',
  process.env.nvidia_bugbounty_2 || '',
  process.env.nvidia_bugbounty_3 || '',
  process.env.nvidia_bugbounty_4 || '',
  process.env.nvidia_bugbounty_5 || '',
  process.env.nvidia_bugbounty_6 || '',
].filter(Boolean);
const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const NVIDIA_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';
const MODEL = 'nvidia/nemotron-3-ultra-550b-a55b';

// cooldown[providerId] = ts until which that provider is skipped
const cooldown = new Map();
const RATE_LIMIT_COOLDOWN = 60000;  // 429 / quota — back off a full minute
const ERROR_COOLDOWN = 10000;       // transient error — short skip
let rrIndex = 0;                    // round-robin start position

function providers() {
  const list = [];
  if (OPENROUTER_KEY) list.push({ id: 'openrouter', url: OPENROUTER_URL, key: OPENROUTER_KEY, or: true });
  NVIDIA_KEYS.forEach((key, i) => list.push({ id: i === 0 ? 'nvidia' : 'nvidia' + (i + 1), url: NVIDIA_URL, key, or: false }));
  return list;
}

function aiConfigured() {
  return providers().length > 0;
}

function aiPoolSize() {
  return providers().length;
}

function cleanThink(text) {
  if (!text) return '';
  return String(text)
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .trim();
}

function extractJson(text) {
  const t = cleanThink(text);
  const fenced = t.match(/```(?:json)?\s*([\s\S]*?)```/);
  const raw = fenced ? fenced[1] : t;
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try { return JSON.parse(raw.slice(start, end + 1)); } catch { return null; }
}

async function callProvider(p, messages, maxTokens, timeoutMs) {
  const until = cooldown.get(p.id) || 0;
  if (Date.now() < until) return null;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(p.url, {
      method: 'POST',
      signal: ctrl.signal,
      headers: {
        'authorization': `Bearer ${p.key}`,
        'content-type': 'application/json',
        ...(p.or ? { 'http-referer': 'https://big-bounty.vercel.app', 'x-title': 'Big Bounty' } : {}),
      },
      body: JSON.stringify({
        model: p.or ? `${MODEL}:free` : MODEL,
        messages,
        temperature: 0.2,
        max_tokens: maxTokens,
      }),
    });
    if (res.status === 429 || res.status === 402 || res.status === 403) {
      cooldown.set(p.id, Date.now() + RATE_LIMIT_COOLDOWN);
      return null;
    }
    if (!res.ok) {
      cooldown.set(p.id, Date.now() + ERROR_COOLDOWN);
      return null;
    }
    const data = await res.json();
    const msg = data && data.choices && data.choices[0] && data.choices[0].message;
    const content = cleanThink(msg && (msg.content || ''));
    if (!content && msg && msg.reasoning_content) {
      // reasoning model ran out of tokens mid-think — unusable
      cooldown.set(p.id, Date.now() + 5000);
      return null;
    }
    if (!content) return null;
    return { content, provider: p.id };
  } catch {
    cooldown.set(p.id, Date.now() + ERROR_COOLDOWN);
    return null;
  } finally {
    clearTimeout(t);
  }
}

/**
 * Triage call with full-pool failover. Returns {content, provider} or null.
 */
async function aiChat(messages, { maxTokens = 2000, timeoutMs = 75000 } = {}) {
  const pool = providers();
  if (!pool.length) return null;
  const order = [];
  for (let i = 0; i < pool.length; i++) order.push(pool[(rrIndex + i) % pool.length]);
  rrIndex = (rrIndex + 1) % pool.length;
  for (const p of order) {
    const r = await callProvider(p, messages, maxTokens, timeoutMs);
    if (r) return r;
  }
  return null;
}

function compactFindings(findings) {
  return (findings || []).slice(0, 60).map(f => ({
    id: f.id, severity: f.severity, tool: f.tool, title: f.title,
    detail: String(f.detail || f.fix || '').slice(0, 160),
    evidence: JSON.stringify(f.evidence || {}).slice(0, 220),
  }));
}

async function runAiTriage({ target, mode, findings, summary }) {
  if (!aiConfigured()) return null;
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings || []) sev[f.severity] = (sev[f.severity] || 0) + 1;

  const messages = [
    {
      role: 'system',
      content:
`You are the AI analyst inside "Big Bounty", a security assessment tool used by a professional pentester reporting to CLIENTS who own the scanned targets.
You receive raw scan findings that were each confirmed with live HTTP/DNS evidence.
Respond with ONLY a valid JSON object, no prose outside JSON:
{
  "executiveSummary": "3-5 sentences for a non-technical site owner: overall risk in plain language",
  "riskVerdict": "one of: CRITICAL RISK | HIGH RISK | MODERATE RISK | LOW RISK | MINIMAL",
  "riskReason": "1-2 sentences justifying the verdict",
  "attackNarrative": "how a real attacker would chain these exact findings, step by step, concrete",
  "remediation": [{"priority": 1, "title": "...", "howto": "concrete fix steps, 1-2 sentences"}],
  "fpSuspects": ["finding ids that look like possible false positives, with reason embedded like 'f3: reason'"],
  "nextAttacks": ["2-4 specific manual tests a pentester should run next that this scanner did not cover"]
}`
    },
    {
      role: 'user',
      content: `Target: ${target}\nScan mode: ${mode}\nSeverity counts: ${JSON.stringify(sev)}\nFindings (id | severity | tool | title | evidence):\n${compactFindings(findings).map(f => `${f.id} | ${f.severity} | ${f.tool} | ${f.title} | ${f.evidence}`).join('\n')}\n\nProduce the JSON verdict now. Be specific to THESE findings, not generic advice.`
    },
  ];

  const r = await aiChat(messages, { maxTokens: 2400, timeoutMs: 90000 });
  if (!r) return null;
  const parsed = extractJson(r.content);
  if (!parsed || !parsed.executiveSummary) return null;
  parsed.aiProvider = r.provider;
  parsed.aiModel = MODEL;
  return parsed;
}

module.exports = { aiChat, runAiTriage, aiConfigured, aiPoolSize, cleanThink };