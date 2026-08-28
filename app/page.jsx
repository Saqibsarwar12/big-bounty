"use client";
import { useState } from "react";

const MODES = [
  { id: "basic", label: "Basic", desc: "Recon, dirs, headers, CORS, tech, secrets — non-intrusive" },
  { id: "advanced", label: "Advanced", desc: "Everything + XSS, SQLi, redirect, CVEs, real bypass attacks (auth bypass, LFI, SSRF, takeover) with PoC", hot: true },
  { id: "custom", label: "Custom", desc: "Advanced + your own paths / instructions" },
];

const SEV_COLOR = { critical: "#ff2b4e", high: "#ff7a1a", medium: "#eab308", low: "#38bdf8", info: "#8b8b8b" };

export default function Home() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("basic");
  const [instructions, setInstructions] = useState("");
  const [status, setStatus] = useState("idle");
  const [livePhases, setLivePhases] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  async function downloadReport(fmt) {
    if (!result) return;
    setDownloading(true);
    try {
      const res = await fetch("/api/report?format=" + fmt, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: fmt === "json" ? "application/json" : "*/*" },
        body: JSON.stringify(result),
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const ext = fmt === "pdf" ? "pdf" : fmt;
      const mime = fmt === "pdf" ? "application/pdf" : fmt === "md" ? "text/markdown" : fmt === "html" ? "text/html" : "application/json";
      const blob = fmt === "json" ? new Blob([JSON.stringify(result, null, 2)], { type: mime }) : await res.blob();
      const host = (result.finalTarget || result.target || "scan").replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]/gi, "");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "bigbounty-" + host + "-" + new Date().toISOString().slice(0, 10) + "." + ext;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      setError("Report download failed: " + (e && e.message ? e.message : String(e)));
    } finally {
      setDownloading(false);
    }
  }

  async function run() {
    if (!target.trim()) { setError("Enter a target URL"); return; }
    if (mode === "custom" && !instructions.trim()) { setError("Custom mode needs instructions"); return; }
    setStatus("scanning"); setError(""); setResult(null); setLivePhases([]);
    const t0 = Date.now();
    const tick = setInterval(() => setElapsed(Math.round((Date.now() - t0) / 1000)), 1000);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), mode, ...(mode === "custom" ? { instructions } : {}) }),
        signal: AbortSignal.timeout(290000),
      });

      if (!res.ok || !res.body) {
        let msg = `HTTP ${res.status}`;
        try {
          const txt = await res.text();
          try {
            const j = JSON.parse(txt);
            msg = typeof j.error === "string" ? j.error : (j.error?.message || j.message || txt.slice(0, 160));
          } catch { msg = txt.slice(0, 160) || `HTTP ${res.status}`; }
        } catch {}
        throw new Error(msg);
      }

      // NDJSON stream: phase events live, final {type:'done'} carries the full result
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      let done = false;
      while (!done) {
        const { value, done: rdDone } = await reader.read();
        if (rdDone) break;
        buf += dec.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 1);
          if (!line) continue;
          let ev;
          try { ev = JSON.parse(line); } catch { continue; }
          if (ev.type === "phase") {
            setLivePhases((prev) => {
              const others = prev.filter((p) => p.phase !== ev.phase);
              return [...others, ev];
            });
          } else if (ev.type === "done") {
            setResult(ev.result); setStatus("done"); done = true;
          } else if (ev.type === "error") {
            throw new Error(ev.error);
          }
        }
      }
      if (!result && !done) setError("Scan stream ended early — try again");
    } catch (e) {
      const msg = e && e.name === "AbortError"
        ? "Scan timed out (server limit ~5 min). Try Basic mode, or a faster target."
        : (e && e.message ? e.message : "Scan failed — check the target URL and try Basic mode");
      setError(String(msg)); setStatus("error");
    } finally {
      clearInterval(tick);
    }
  }

  const phases = livePhases.length ? livePhases : (result ? result.phases : []);
  const sevCounts = (list) => {
    const c = {};
    for (const f of list || []) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0a0e14", color: "#d7dce3", fontFamily: "ui-monospace, Menlo, monospace", padding: 24 }}>
      <div style={{ maxWidth: 860, margin: "0 auto" }}>
        <header style={{ marginBottom: 28 }}>
          <h1 style={{ fontSize: 30, margin: 0, color: "#ff2b4e", letterSpacing: 2 }}>⚔ BIG BOUNTY</h1>
          <p style={{ color: "#7d8590", fontSize: 13, margin: "8px 0 0" }}>
            Real-evidence security scanner — every finding ships the raw HTTP/DNS evidence + a PoC curl command.
            Advanced mode fires real bypass attempts (SQLi login bypass, LFI, SSRF, takeover) plus a remote
            browser that hunts auth bypasses &amp; DOM XSS. Only scan targets you are authorized to test.
          </p>
        </header>

        <section style={{ border: "1px solid #1f2733", borderRadius: 10, padding: 18, background: "#0d1219" }}>
          <label style={{ display: "block", fontSize: 12, color: "#7d8590", marginBottom: 6 }}>TARGET</label>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input
              value={target} onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && status !== "scanning" && run()}
              placeholder="https://client-site.com"
              style={{ flex: 1, minWidth: 240, background: "#0a0e14", border: "1px solid #2a3441", borderRadius: 8, padding: "10px 12px", color: "#d7dce3", fontSize: 14 }}
            />
            <button onClick={run} disabled={status === "scanning"}
              style={{ background: status === "scanning" ? "#1f2733" : "#16a34a", color: "#fff", border: 0, borderRadius: 8, padding: "10px 22px", fontSize: 14, fontWeight: 700, cursor: status === "scanning" ? "wait" : "pointer" }}>
              {status === "scanning" ? `SCANNING… ${elapsed}s` : "RUN SCAN"}
            </button>
          </div>

          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            {MODES.map((m) => (
              <button key={m.id} onClick={() => setMode(m.id)}
                style={{
                  background: mode === m.id ? (m.hot ? "rgba(255,43,78,.12)" : "rgba(22,163,74,.12)") : "transparent",
                  border: `1px solid ${mode === m.id ? (m.hot ? "#ff2b4e" : "#16a34a") : "#2a3441"}`,
                  color: mode === m.id ? (m.hot ? "#ff2b4e" : "#16a34a") : "#7d8590",
                  borderRadius: 8, padding: "8px 14px", fontSize: 12, cursor: "pointer", textAlign: "left",
                }}>
                <b>{m.label}</b> — {m.desc}
              </button>
            ))}
          </div>

          {mode === "custom" && (
            <textarea value={instructions} onChange={(e) => setInstructions(e.target.value)}
              placeholder={"e.g. focus on /api/v1, test the session cookie, try bypassing the login at /auth/login"}
              rows={3} style={{ width: "100%", marginTop: 10, background: "#0a0e14", border: "1px solid #2a3441", borderRadius: 8, padding: 10, color: "#d7dce3", fontSize: 13 }} />
          )}
        </section>

        {error && (
          <div style={{ marginTop: 16, border: "1px solid #ff2b4e", borderRadius: 8, padding: 14, color: "#ff2b4e", fontSize: 13, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
            ✗ {error}
          </div>
        )}

        {status === "scanning" && (
          <div style={{ marginTop: 16, border: "1px solid #1f2733", borderRadius: 8, padding: 14 }}>
            <div style={{ fontSize: 12, color: "#7d8590", marginBottom: 8 }}>LIVE — phases as they complete ({elapsed}s elapsed)</div>
            {livePhases.map((p) => (
              <div key={p.phase} style={{ display: "flex", gap: 10, fontSize: 12, padding: "3px 0", color: p.status === "ok" ? "#16a34a" : p.status === "error" ? "#ff7a1a" : "#7d8590" }}>
                <span>{p.status === "running" ? "◌" : p.status === "ok" ? "✓" : "✗"}</span>
                <span style={{ width: 160 }}>{p.phase}</span>
                <span style={{ color: "#7d8590" }}>{p.status === "ok" ? `${p.ms}ms${p.hits != null ? ` · ${p.hits} hits` : ""}` : p.status === "running" ? "running…" : p.error || p.status}</span>
              </div>
            ))}
          </div>
        )}

        {result && (
          <section style={{ marginTop: 18 }}>
            <div style={{ border: "1px solid #1f2733", borderRadius: 10, padding: 16, background: "#0d1219" }}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 14, alignItems: "baseline", fontSize: 13 }}>
                <b style={{ color: "#16a34a" }}>{result.finalTarget}</b>
                <span style={{ color: "#7d8590" }}>HTTP {result.httpStatus} · {result.durationMs / 1000 | 0}s · mode {result.mode}</span>
              </div>
              {result.summary && (
                <div style={{ display: "flex", gap: 14, marginTop: 10, fontSize: 13 }}>
                  {["critical", "high", "medium", "low", "info"].map((s) => (
                    <span key={s} style={{ color: SEV_COLOR[s] }}>{s}: {result.summary[s] || 0}</span>
                  ))}
                  <div style={{ display: "flex", gap: 8, width: "100%", marginTop: 4, flexWrap: "wrap" }}>
                    {[["pdf", "PDF Report"], ["md", "Markdown"], ["html", "HTML"], ["json", "JSON"]].map(([fmt, label]) => (
                      <button key={fmt} onClick={() => downloadReport(fmt)} disabled={downloading}
                        style={{ background: "#111a26", color: "#58a6ff", border: "1px solid #1f6feb", borderRadius: 6, padding: "6px 12px", cursor: downloading ? "wait" : "pointer", fontSize: 12 }}>
                        ⬇ {label}
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 12 }}>
                {(result.phases || []).map((p) => (
                  <span key={p.phase} title={p.status === "ok" ? p.ms + "ms" : (p.error || p.status)}
                    style={{ fontSize: 11, padding: "3px 8px", borderRadius: 6, border: `1px solid ${p.status === "ok" ? "#16341f" : p.status === "skipped" ? "#2a3441" : "#4a1a12"}`, color: p.status === "ok" ? "#16a34a" : p.status === "skipped" ? "#7d8590" : "#ff7a1a" }}>
                    {p.phase} {p.status === "ok" ? "✓" : p.status === "skipped" ? "·" : "✗"}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ marginTop: 14, display: "flex", flexDirection: "column", gap: 10 }}>
              {result.findings.length === 0 && <div style={{ color: "#7d8590", fontSize: 13 }}>No findings — target looks clean for the checks run in {result.mode} mode.</div>}
              {result.findings.map((f) => (
                <div key={f.id} style={{ border: `1px solid ${SEV_COLOR[f.severity] || "#2a3441"}55`, borderLeft: `3px solid ${SEV_COLOR[f.severity] || "#2a3441"}`, borderRadius: 8, padding: 12, background: "#0d1219" }}>
                  <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                    <span style={{ fontSize: 10, fontWeight: 800, letterSpacing: 1, color: SEV_COLOR[f.severity], border: `1px solid ${SEV_COLOR[f.severity]}`, padding: "1px 7px", borderRadius: 5 }}>{f.severity.toUpperCase()}</span>
                    <b style={{ fontSize: 14 }}>{f.title}</b>
                    <span style={{ fontSize: 11, color: "#7d8590" }}>[{f.tool}]</span>
                  </div>
                  {f.desc && <p style={{ fontSize: 12, color: "#9aa4af", margin: "6px 0 0" }}>{f.desc}</p>}
                  <details style={{ marginTop: 8 }}>
                    <summary style={{ fontSize: 11, color: "#38bdf8", cursor: "pointer" }}>EVIDENCE / PROOF</summary>
                    <pre style={{ background: "#0a0e14", border: "1px solid #1f2733", borderRadius: 6, padding: 10, fontSize: 11, overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "#c9d1d9" }}>
{typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence, null, 2)}
                    </pre>
                  </details>
                  {f.poc && f.poc.curl && (
                    <details style={{ marginTop: 6 }} open>
                      <summary style={{ fontSize: 11, color: "#ff7a1a", cursor: "pointer" }}>REPRODUCE (curl)</summary>
                      <pre style={{ background: "#0a0e14", border: "1px solid #4a1a12", borderRadius: 6, padding: 10, fontSize: 11, overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "#ffb46e" }}>{f.poc.curl}</pre>
                      {f.poc.notes && <div style={{ fontSize: 11, color: "#9aa4af", marginTop: 6 }}>↳ {f.poc.notes}</div>}
                    </details>
                  )}
                  {f.fix && <div style={{ marginTop: 8, fontSize: 12, color: "#9aa4af" }}><b style={{ color: "#16a34a" }}>FIX:</b> {f.fix}</div>}
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}