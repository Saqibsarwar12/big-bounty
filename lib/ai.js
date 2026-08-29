/**
 * Big Bounty AI analyst — free-tier only, rate-limit aware.
 * Chain: OpenRouter free model -> NVIDIA direct. Max 2 calls/scan.
 * Never throws into the scan path; runAiTriage returns null on failure.
 */
const OPENROUTER_KEY = process.env.OPENROUTER_BUGBOUNTY || process.env.Openrouter_bugbounty || '';
const NVIDIA_KEY = process.env.NVIDIA_BUGBOUNTY || process.env.nvidia_bugbounty || '';
const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const NVIDIA_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';
const MODEL = 'nvidia/nemotron-3-ultra-550b-a55b';

// last-failure timestamps so a rate-limited provider is skipped for 60s
const cooldown = { openrouter: 0, nvidia: 0 };
const COOLDOWN_MS = 60000;

function aiConfigured() {
  return Boolean(OPENROUTER_KEY || NVIDIA_KEY);
}

function cleanThink(text) {
  if (!text) return '';
  return String(text)
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/^\s*think[\s\S]*?\/think\s*/i, '')
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

async function callProvider(kind, messages, maxTokens, timeoutMs) {
  const isOR = kind === 'openrouter';
  const key = isOR ? OPENROUTER_KEY : NVIDIA_KEY;
  if (!key || Date.now() < cooldown[kind]) return null;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(isOR ? OPENROUTER_URL : NVIDIA_URL, {
      method: 'POST',
      signal: ctrl.signal,
      headers: {
        'authorization': `Bearer ${key}`,
        'content-type': 'application/json',
        ...(isOR ? { 'http-referer': 'https://big-bounty.vercel.app', 'x-title': 'Big Bounty' } : {}),
      },
      body: JSON.stringify({
        model: isOR ? `${MODEL}:free` : MODEL,
        messages,
        temperature: 0.2,
        max_tokens: maxTokens,
      }),
    });
    if (res.status === 429 || res.status === 402 || res.status === 403) {
      cooldown[kind] = Date.now() + COOLDOWN_MS;
      return null;
    }
    if (!res.ok) {
      cooldown[kind] = Date.now() + 10000;
      return null;
    }
    const data = await res.json();
    const msg = data && data.choices && data.choices[0] && data.choices[0].message;
    let content = cleanThink(msg && (msg.content || ''));
    if (!content && msg && msg.reasoning_content) {
      // reasoning model ran out of tokens mid-think — unusable
      cooldown[kind] = Date.now() + 5000;
      return null;
    }
    if (!content) return null;
    return { content, provider: isOR ? 'openrouter' : 'nvidia' };
  } catch {
    cooldown[kind] = Date.now() + 10000;
    return null;
  } finally {
    clearTimeout(t);
  }
}

/**
 * Single triage call with provider failover. Returns {content, provider} or null.
 */
async function aiChat(messages, { maxTokens = 2000, timeoutMs = 75000 } = {}) {
  const order = Date.now() % 2 === 0 ? ['openrouter', 'nvidia'] : ['nvidia', 'openrouter'];
  for (const kind of order) {
    const r = await callProvider(kind, messages, maxTokens, timeoutMs);
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

module.exports = { aiChat, runAiTriage, aiConfigured, cleanThink };
