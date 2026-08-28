"use client";
import { useState } from "react";

const MODES = [
  { id: "basic", label: "Basic", desc: "Recon, dirs, headers, CORS, tech, secrets", accent: "#22c55e" },
  { id: "advanced", label: "Advanced", desc: "Everything + XSS, SQLi, redirect, ports, subdomain brute, CVEs", accent: "#ef4444" },
  { id: "custom", label: "Custom", desc: "Advanced + your own paths/instructions", accent: "#a855f7" },
];

const SEV_COLORS = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280" };

export default function BigBounty() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("basic");
  const [custom, setCustom] = useState("");
  const [status, setStatus] = useState("idle"); // idle | scanning | done | error
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [open, setOpen] = useState({}); // finding id -> bool

  async function run() {
    if (!target.trim()) { setError("Enter a target URL"); return; }
    if (mode === "custom" && !custom.trim()) { setError("Custom mode needs instructions"); return; }
    setStatus("scanning"); setError(""); setResult(null); setOpen({});
    const started = Date.now();
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ target: target.trim(), mode, ...(mode === "custom" ? { custom } : {}) }),
        signal: AbortSignal.timeout(280000),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      setResult(data);
      setStatus("done");
    } catch (e) {
      setError(e.name === "AbortError" ? "Scan timed out (4.5 min limit). Try basic mode or a faster target." : (e.message || "Scan failed"));
      setStatus("error");
    }
  }

  const ph = result ? Object.fromEntries(result.phases.map((p) => [p.phase, p])) : {};
  const bySev = result ? Object.fromEntries(result.findings.reduce((acc, f) => { const m = acc.find((x) => x[0] === f.severity); if (m) m[1]++; else acc.push([f.severity, 1]); return acc; }, [])) : {};

  return (
    <div style={{ minHeight: "100vh", background: "#0a0e14", color: "#e6e6e6", fontFamily: "ui-monospace, 'Cascadia Code', Menlo, monospace", padding: 24 }}>
      <div style={{ maxWidth: 980, margin: "0 auto" }}>
        <header style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 4 }}>
          <span style={{ fontSize: 28 }}>⚔️</span>
          <h1 style={{ fontSize: 24, margin: 0, letterSpacing: 1 }}>BIG BOUNTY</h1>
          <span style={{ fontSize: 11, background: "#161b22", border: "1px solid #30363d", padding: "2px 8px", borderRadius: 10, color: "#8b949e" }}>v3.0 · real evidence only</span>
          <span style={{ fontSize: 11, background: "#161b22", border: "1px solid #1f6feb", padding: "2px 8px", borderRadius: 10, color: "#58a6ff" }}>🌐 browser attacks enabled</span>
        </header>
        <p style={{ color: "#8b949e", fontSize: 13, margin: "0 0 20px" }}>
          Every finding is backed by a live HTTP / DNS / RDAP request — raw evidence included. Advanced mode adds real bypass attempts (SQLi login bypass, LFI, SSRF, subdomain takeover) plus an AI-driven remote browser (Browserbase) that hunts for auth bypasses and DOM XSS like a human tester. Use only on targets you're authorized to test.
        </p>

        <div style={{ background: "#0d1117", border: "1px solid #30363d", borderRadius: 8, padding: 16 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <input
              value={target} onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && status !== "scanning" && run()}
              placeholder="https://target.example.com" disabled={status === "scanning"}
              style={{ flex: 1, background: "#010409", border: "1px solid #30363d", borderRadius: 6, padding: "10px 12px", color: "#e6e6e6", fontSize: 14, outline: "none" }}
            />
            <button onClick={run} disabled={status === "scanning"}
              style={{ background: status === "scanning" ? "#21262d" : "#238636", border: "1px solid rgba(240,246,252,.1)", borderRadius: 6, padding: "10px 20px", color: "#fff", fontWeight: 700, cursor: status === "scanning" ? "wait" : "pointer", whiteSpace: "nowrap" }}>
              {status === "scanning" ? "SCANNING…" : "RUN SCAN"}
            </button>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {MODES.map((m) => (
              <button key={m.id} onClick={() => setMode(m.id)} disabled={status === "scanning"}
                style={{ background: mode === m.id ? "#161b22" : "transparent", border: `1px solid ${mode === m.id ? m.accent : "#30363d"}`, borderRadius: 6, padding: "6px 12px", color: mode === m.id ? "#fff" : "#8b949e", cursor: "pointer", fontSize: 13 }}>
                <b style={{ color: mode === m.id ? m.accent : undefined }}>{m.label}</b> — {m.desc}
              </button>
            ))}
          </div>

          {mode === "custom" && (
            <textarea value={custom} onChange={(e) => setCustom(e.target.value)} disabled={status === "scanning"}
              placeholder="e.g. check /admin /backup.zip /api/v1/users — plus any custom instructions for the scanner"
              rows={2}
              style={{ width: "100%", marginTop: 10, background: "#010409", border: "1px solid #30363d", borderRadius: 6, padding: 10, color: "#e6e6e6", fontSize: 13, fontFamily: "inherit", outline: "none", boxSizing: "border-box" }} />
          )}
        </div>

        {status === "scanning" && (
          <div style={{ marginTop: 16, padding: 16, border: "1px solid #30363d", borderRadius: 8, color: "#8b949e", fontSize: 13 }}>
            <span className="pulse" style={{ color: "#f0883e" }}>●</span> Firing live requests at <b style={{ color: "#e6e6e6" }}>{target}</b> — recon, dir brute force, vuln probes{mode !== "basic" && <> + real <b style={{ color: "#f85149" }}>bypass attacks</b> &amp; remote-browser hunt</>}. This is real network traffic — advanced scans take 1–4 min.
          </div>
        )}

        {status === "error" && (
          <div style={{ marginTop: 16, padding: 16, border: "1px solid #f85149", borderRadius: 8, color: "#f85149", fontSize: 13 }}>
            ✗ {error}
          </div>
        )}

        {result && (
          <div style={{ marginTop: 16 }}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontSize: 13, color: "#8b949e" }}>
                <b style={{ color: "#e6e6e6" }}>{result.finalTarget}</b> · HTTP {result.httpStatus} · {(result.durationMs / 1000).toFixed(1)}s · {result.findings.length} findings
              </span>
              {["critical", "high", "medium", "low", "info"].map((s) => bySev[s] ? (
                <span key={s} style={{ fontSize: 11, background: "#161b22", border: `1px solid ${SEV_COLORS[s]}`, color: SEV_COLORS[s], padding: "2px 8px", borderRadius: 10 }}>{s}: {bySev[s]}</span>
              ) : null)}
            </div>

            <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginBottom: 12 }}>
              {result.phases.map((p) => (
                <span key={p.phase} title={p.status === "ok" ? p.ms + "ms" : (p.error || "")}
                  style={{ fontSize: 11, padding: "2px 8px", borderRadius: 4, background: "#010409", border: `1px solid ${p.status === "ok" ? "#238636" : p.status === "empty" ? "#30363d" : "#f85149"}`, color: p.status === "ok" ? "#3fb950" : p.status === "empty" ? "#484f58" : "#f85149" }}>
                  {p.phase} {p.status === "ok" ? "✓" : p.status === "empty" ? "·" : "✗"}
                </span>
              ))}
            </div>

            {result.findings.map((f) => (
              <div key={f.id} style={{ background: "#0d1117", border: "1px solid #30363d", borderLeft: `3px solid ${SEV_COLORS[f.severity]}`, borderRadius: 6, marginBottom: 8, overflow: "hidden" }}>
                <div onClick={() => setOpen((o) => ({ ...o, [f.id]: !o[f.id] }))} style={{ padding: "10px 14px", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                  <div style={{ fontSize: 13 }}>
                    <b style={{ color: SEV_COLORS[f.severity] }}>{f.severity.toUpperCase()}</b>
                    <span style={{ color: "#8b949e", margin: "0 6px" }}>[{f.tool}]</span>
                    {f.title}
                    <span style={{ color: "#484f58", fontSize: 12, marginLeft: 6 }}>{f.detail}</span>
                  </div>
                  <span style={{ color: "#484f58", fontSize: 11, whiteSpace: "nowrap" }}>{open[f.id] ? "▾" : "▸"}</span>
                </div>
                {open[f.id] && (
                  <div style={{ padding: "0 14px 12px", fontSize: 12 }}>
                    {f.desc && <div style={{ color: "#8b949e", marginBottom: 8 }}>{f.desc}</div>}
                    {f.poc && f.poc.steps && (
                      <div style={{ marginBottom: 8 }}>
                        <div style={{ color: "#f0883e", marginBottom: 4, fontWeight: 700 }}>HOW IT WAS BYPASSED (share with your client):</div>
                        <ol style={{ margin: "0 0 8px 18px", padding: 0, color: "#e6e6e6", lineHeight: 1.7 }}>
                          {(f.poc.steps || []).map((s, i) => <li key={i}>{s}</li>)}
                        </ol>
                        {f.poc.curl && (
                          <div>
                            <div style={{ color: "#8b949e", marginBottom: 4 }}>Reproduce with curl:</div>
                            <pre style={{ background: "#010409", border: "1px solid #21262d", borderRadius: 6, padding: 10, overflowX: "auto", margin: "0 0 8px", color: "#7ee787", fontSize: 11.5, whiteSpace: "pre-wrap" }}>{f.poc.curl}</pre>
                          </div>
                        )}
                      </div>
                    )}
                    <pre style={{ background: "#010409", border: "1px solid #21262d", borderRadius: 6, padding: 10, overflowX: "auto", margin: 0, color: "#a5d6ff", fontSize: 11.5, lineHeight: 1.5 }}>
                      {typeof f.evidence === 'object' ? JSON.stringify(f.evidence, null, 2) : String(f.evidence)}
                    </pre>
                    {f.screenshot && (
                      <details style={{ marginTop: 8 }}>
                        <summary style={{ color: "#8b949e", cursor: "pointer" }}>📸 Browser proof screenshot</summary>
                        <img src={`data:image/png;base64,${f.screenshot}`} alt="proof" style={{ maxWidth: "100%", border: "1px solid #30363d", borderRadius: 6, marginTop: 6 }} />
                      </details>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      <style jsx global>{`
        @keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: .3 } }
        .pulse { animation: pulse 1.2s infinite }
      `}</style>
    </div>
  );
}