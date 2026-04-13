import { useCallback, useEffect, useRef, useState } from "react";
import axios from "axios";
import { Skull, StopCircle, Zap, Crosshair, RefreshCw } from "lucide-react";

const SERVER = import.meta.env.VITE_SERVER_URL
  ? `${import.meta.env.VITE_SERVER_URL}/api/test`
  : "http://localhost:5000/api/test";

const ATTACK_CONFIGS = {
  syn_flood: {
    label:    "SYN Flood",
    icon:     "⚡",
    color:    "#f87171",
    colorDim: "#2a0f0f",
    border:   "#5a1a1a",
    interval: 30,
    duration: 8000,
    pktSize:  60,
    desc:     "Kichik TCP SYN paketlar (60B), tez yuborish — SYN flood pattern",
    metrics:  "~33 req/s · 60B/pkt · 8s",
    expectedBlock: "SYN",
    mechanism: "pkt≤100B + req/s≥20 → is_syn=true → pkts_per_req=25 → flow_pkts_s≈825 → Model: SYN",
  },
  udp_flood: {
    label:    "UDP Flood",
    icon:     "🌊",
    color:    "#fb923c",
    colorDim: "#2a1a08",
    border:   "#5a3a10",
    interval: 40,
    duration: 8000,
    pktSize:  1400,
    desc:     "Katta UDP paketlar (1400B) bilan flood — UDP flood pattern",
    metrics:  "~25 req/s · 1400B/pkt · 8s",
    expectedBlock: "UDP",
    mechanism: "pkt≥800B + req/s≥15 → is_udp=true → pkts_per_req=24 → flow_pkts_s≈600 → Model: UDP",
  },
  dns_amp: {
    label:    "DNS Amp",
    icon:     "📡",
    color:    "#818cf8",
    colorDim: "#10102a",
    border:   "#2a2a5a",
    interval: 40,
    duration: 8000,
    pktSize:  120,
    desc:     "DNS amplification — o'rta hajmli paketlar (120B) pattern",
    metrics:  "~25 req/s · 120B/pkt · 8s",
    expectedBlock: "DNS",
    mechanism: "60≤pkt≤250B + req/s≥15 → is_dns=true → pkts_per_req=20 → flow_pkts_s≈500 → Model: DNS",
  },
  portscan: {
    label:    "Port Scan",
    icon:     "🔍",
    color:    "#facc15",
    colorDim: "#1a1a08",
    border:   "#4a4a10",
    interval: 5,
    duration: 8000,
    pktSize:  44,
    desc:     "Kichik SYN paketlar (44B), juda tez — portlarni skanerlash",
    metrics:  "~200 req/s · 44B/pkt · 8s",
    expectedBlock: "PORTSCAN",
    mechanism: "pkt≤80B + req/s≥10 → is_portscan=true → flow_pkts_s≈50,000 → Model: PORTSCAN",
  },
  normal_test: {
    label:    "Normal Test",
    icon:     "✅",
    color:    "#4ade80",
    colorDim: "#081a0a",
    border:   "#1a4020",
    interval: 500,
    duration: 10000,
    pktSize:  800,
    desc:     "Sekin, normal HTTP so'rovlar — BENIGN bo'lishi kerak",
    metrics:  "~2 req/s · 800B/pkt · 10s",
    expectedBlock: null,
    mechanism: "req/s=2, pkt=800B → hech qanday attack pattern mos kelmaydi → pkts_per_req=1 → flow_pkts_s≈2 → Model: BENIGN",
  },
};

export default function Attacker() {
  const intervalRef = useRef(null);
  const timeoutRef  = useRef(null);
  const elapsedRef  = useRef(null);
  const logEndRef   = useRef(null);

  const [running,    setRunning]    = useState(false);
  const [attackType, setAttackType] = useState("syn_flood");
  const [sent,       setSent]       = useState(0);
  const [blocked,    setBlocked]    = useState(0);
  const [logs,       setLogs]       = useState([]);
  const [elapsed,    setElapsed]    = useState(0);

  const cfg = ATTACK_CONFIGS[attackType];

  const addLog = useCallback((text, type = "info") => {
    setLogs((prev) =>
      [{ text, type, time: new Date().toLocaleTimeString("uz") }, ...prev].slice(0, 100)
    );
  }, []);

  const stop = useCallback(() => {
    clearInterval(intervalRef.current);
    clearTimeout(timeoutRef.current);
    clearInterval(elapsedRef.current);
    intervalRef.current = null;
    timeoutRef.current  = null;
    elapsedRef.current  = null;
    setRunning(false);
    setElapsed(0);
    addLog("Hujum to'xtatildi.", "warn");
  }, [addLog]);

  const start = useCallback(() => {
    if (intervalRef.current) stop();

    const activeCfg = ATTACK_CONFIGS[attackType];

    setRunning(true);
    setSent(0);
    setBlocked(0);
    setLogs([]);
    setElapsed(0);

    addLog(`${activeCfg.icon} ${activeCfg.label} boshlandi`, "info");
    addLog(`Interval: ${activeCfg.interval}ms · Paket: ${activeCfg.pktSize}B · Davom: ${activeCfg.duration / 1000}s`, "info");

    if (activeCfg.expectedBlock) {
      addLog(`Kutilgan natija: "${activeCfg.expectedBlock}" deb bloklash`, "warn");
    } else {
      addLog("Kutilgan natija: Bloklanmasligi kerak (BENIGN)", "success");
    }

    let inFlight = 0;
    const MAX_INFLIGHT = attackType === "portscan" ? 30 : 8;

    elapsedRef.current = setInterval(() => setElapsed((p) => +(p + 0.1).toFixed(1)), 100);

    intervalRef.current = setInterval(async () => {
      if (inFlight >= MAX_INFLIGHT) return;
      inFlight++;
      try {
        await axios.post(
          SERVER,
          { payload: "X".repeat(activeCfg.pktSize) },
          { headers: { "Content-Type": "application/json" }, timeout: 3000 },
        );
        setSent((p) => p + 1);

        if (attackType === "normal_test") {
          addLog(`→ Normal so'rov o'tdi (${activeCfg.pktSize}B) — BENIGN ✓`, "success");
        } else if (attackType === "portscan") {
          addLog(`→ SYN scan paket yuborildi (${activeCfg.pktSize}B)`, "info");
        } else {
          addLog(`→ So'rov yuborildi (${activeCfg.pktSize}B)`, "info");
        }
      } catch (err) {
        const code    = err.response?.status;
        const errMsg  = err.response?.data?.error ?? "Hujum aniqlandi";

        if (code === 403) {
          setBlocked((p) => p + 1);
          addLog(`BLOKLANDI · HTTP 403 · ${errMsg}`, "error");
        } else if (code) {
          // TUZATISH: normal_test bloklansa ham ko'rsatiladi
          if (attackType === "normal_test") {
            setBlocked((p) => p + 1);
            addLog(`KUTILMAGAN BLOKLASH! HTTP ${code} — false positive!`, "error");
          } else {
            addLog(`HTTP ${code} xatosi`, "warn");
          }
        } else if (err.code === "ECONNABORTED") {
          addLog("Timeout — server javob bermadi", "warn");
        } else {
          addLog(`Tarmoq xatosi: ${err.message.slice(0, 60)}`, "warn");
        }
      } finally {
        inFlight--;
      }
    }, activeCfg.interval);

    timeoutRef.current = setTimeout(() => {
      stop();
      addLog("Test yakunlandi.", "success");
    }, activeCfg.duration);
  }, [attackType, stop, addLog]);

  useEffect(() => () => {
    clearInterval(intervalRef.current);
    clearTimeout(timeoutRef.current);
    clearInterval(elapsedRef.current);
  }, []);

  const total     = sent + blocked;
  const blockRate = total > 0 ? Math.round((blocked / total) * 100) : 0;
  const duration  = ATTACK_CONFIGS[attackType].duration / 1000;
  const progress  = running ? Math.min((elapsed / duration) * 100, 100) : 0;

  const configs3 = Object.entries(ATTACK_CONFIGS).slice(0, 3);
  const configs2 = Object.entries(ATTACK_CONFIGS).slice(3);

  return (
    <div style={{ maxWidth: 760, fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>

      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
          <div style={{
            width: 36, height: 36, background: "#1a0808",
            border: "1px solid #5a1a1a", borderRadius: 8,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            <Skull size={16} color="#f87171" />
          </div>
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 700, color: "#f0eeff", margin: 0, letterSpacing: "0.04em" }}>
              ATTACKER LAB
            </h1>
            <p style={{ fontSize: 10, color: "#3a3a5a", margin: 0, letterSpacing: "0.08em" }}>
              ML MODEL SINOV MUHITI — v5 TO'LIQ TUZATILGAN
            </p>
          </div>
        </div>
      </div>

      {/* Attack type selector */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 9, color: "#2a2a4a", letterSpacing: "0.12em", fontWeight: 600, marginBottom: 10 }}>
          HUJUM TURINI TANLANG
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, marginBottom: 8 }}>
          {configs3.map(([key, c]) => {
            const isActive = attackType === key;
            return (
              <button
                key={key}
                onClick={() => !running && setAttackType(key)}
                disabled={running}
                style={{
                  padding: 14, borderRadius: 8,
                  border: `1px solid ${isActive ? c.border : "#1e1e2e"}`,
                  background: isActive ? c.colorDim : "#0d0d14",
                  cursor: running ? "not-allowed" : "pointer",
                  opacity: running && !isActive ? 0.4 : 1,
                  textAlign: "left", transition: "all 0.15s", outline: "none",
                }}
              >
                <div style={{ fontSize: 18, marginBottom: 6 }}>{c.icon}</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: isActive ? c.color : "#4a4a6a", letterSpacing: "0.05em", marginBottom: 4 }}>
                  {c.label}
                </div>
                <div style={{ fontSize: 9, color: "#3a3a5a", lineHeight: 1.5, marginBottom: 4 }}>{c.desc}</div>
                <div style={{ fontSize: 9, color: isActive ? c.color : "#2a2a4a", letterSpacing: "0.04em", fontWeight: 600 }}>
                  {c.metrics}
                </div>
                {c.expectedBlock ? (
                  <div style={{ fontSize: 9, color: "#f87171", marginTop: 4 }}>→ Kutilgan: {c.expectedBlock} blok</div>
                ) : (
                  <div style={{ fontSize: 9, color: "#4ade80", marginTop: 4 }}>→ Kutilgan: BENIGN (o'tsin)</div>
                )}
              </button>
            );
          })}
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8 }}>
          {configs2.map(([key, c]) => {
            const isActive = attackType === key;
            return (
              <button
                key={key}
                onClick={() => !running && setAttackType(key)}
                disabled={running}
                style={{
                  padding: 14, borderRadius: 8,
                  border: `1px solid ${isActive ? c.border : "#1e1e2e"}`,
                  background: isActive ? c.colorDim : "#0d0d14",
                  cursor: running ? "not-allowed" : "pointer",
                  opacity: running && !isActive ? 0.4 : 1,
                  textAlign: "left", transition: "all 0.15s", outline: "none",
                }}
              >
                <div style={{ fontSize: 18, marginBottom: 6 }}>{c.icon}</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: isActive ? c.color : "#4a4a6a", letterSpacing: "0.05em", marginBottom: 4 }}>
                  {c.label}
                </div>
                <div style={{ fontSize: 9, color: "#3a3a5a", lineHeight: 1.5, marginBottom: 4 }}>{c.desc}</div>
                <div style={{ fontSize: 9, color: isActive ? c.color : "#2a2a4a", letterSpacing: "0.04em", fontWeight: 600 }}>
                  {c.metrics}
                </div>
                {c.expectedBlock ? (
                  <div style={{ fontSize: 9, color: "#f87171", marginTop: 4 }}>→ Kutilgan: {c.expectedBlock} blok</div>
                ) : (
                  <div style={{ fontSize: 9, color: "#4ade80", marginTop: 4 }}>→ Kutilgan: BENIGN (o'tsin)</div>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Progress bar */}
      {running && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ fontSize: 10, color: "#3a3a5a" }}>PROGRESS</span>
            <span style={{ fontSize: 10, color: cfg.color }}>{Math.round(elapsed)}s / {duration}s</span>
          </div>
          <div style={{ height: 3, background: "#1e1e2e", borderRadius: 2, overflow: "hidden" }}>
            <div style={{
              width: `${progress}%`, height: "100%",
              background: cfg.color, borderRadius: 2,
              transition: "width 0.1s linear",
            }} />
          </div>
        </div>
      )}

      {/* Control buttons */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        <button
          onClick={start}
          disabled={running}
          style={{
            display: "flex", alignItems: "center", gap: 8,
            background: running ? "#1a1a2a" : cfg.colorDim,
            border: `1px solid ${running ? "#2a2a4a" : cfg.border}`,
            color: running ? "#4a4a6a" : cfg.color,
            padding: "11px 20px", borderRadius: 8,
            fontSize: 11, fontWeight: 700,
            cursor: running ? "not-allowed" : "pointer",
            letterSpacing: "0.06em", flex: 1, justifyContent: "center",
            transition: "all 0.15s", outline: "none",
          }}
        >
          {attackType === "portscan" ? <Crosshair size={14} /> : <Zap size={14} />}
          {running ? `${cfg.label.toUpperCase()} DAVOM ETMOQDA...` : `${cfg.label.toUpperCase()} BOSHLASH`}
        </button>

        {running && (
          <button
            onClick={stop}
            style={{
              display: "flex", alignItems: "center", gap: 8,
              background: "#1a1a2a", border: "1px solid #3a3a5a",
              color: "#9090c0", padding: "11px 16px", borderRadius: 8,
              fontSize: 11, fontWeight: 700, cursor: "pointer",
              letterSpacing: "0.06em", outline: "none",
            }}
          >
            <StopCircle size={14} />
            TO'XTATISH
          </button>
        )}

        {!running && (sent > 0 || blocked > 0) && (
          <button
            onClick={() => { setSent(0); setBlocked(0); setLogs([]); }}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              background: "#0d0d14", border: "1px solid #1e1e2e",
              color: "#3a3a5a", padding: "11px 14px", borderRadius: 8,
              fontSize: 11, cursor: "pointer", outline: "none",
            }}
          >
            <RefreshCw size={13} />
          </button>
        )}
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 16 }}>
        {[
          { label: "YUBORILGAN", value: total,      color: "#818cf8" },
          { label: "BLOKLANGAN", value: blocked,    color: "#f87171" },
          { label: "O'TGAN",     value: sent,       color: "#4ade80" },
          { label: "BLOK %",     value: `${blockRate}%`, color: blockRate > 50 ? "#f87171" : blockRate > 0 ? "#fb923c" : "#3a3a5a" },
        ].map(({ label, value, color }) => (
          <div key={label} style={{
            background: "#0d0d14", border: "1px solid #1e1e2e",
            borderRadius: 8, padding: "12px 14px", textAlign: "center",
          }}>
            <div style={{ fontSize: 9, color: "#2a2a4a", letterSpacing: "0.1em", marginBottom: 6, fontWeight: 600 }}>
              {label}
            </div>
            <div style={{ fontSize: 22, fontWeight: 700, color }}>{value}</div>
          </div>
        ))}
      </div>

      {/* Terminal log */}
      <div style={{ background: "#060609", border: "1px solid #1e1e2e", borderRadius: 8, overflow: "hidden" }}>
        <div style={{
          padding: "10px 14px", background: "#0d0d14",
          borderBottom: "1px solid #1e1e2e",
          display: "flex", alignItems: "center", justifyContent: "space-between",
        }}>
          <div style={{ display: "flex", gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#3a1515" }} />
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#2a2a10" }} />
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#0a2a0a" }} />
          </div>
          <span style={{ fontSize: 9, color: "#2a2a4a", letterSpacing: "0.1em" }}>
            {cfg.icon} {cfg.label.toLowerCase()}.log
          </span>
          {running && (
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{
                width: 6, height: 6, borderRadius: "50%",
                background: "#4ade80", boxShadow: "0 0 6px #4ade80",
                animation: "pulse 1s infinite",
              }} />
              <span style={{ fontSize: 9, color: "#4ade80", letterSpacing: "0.08em" }}>LIVE</span>
            </div>
          )}
        </div>

        <div style={{
          padding: "12px 14px", maxHeight: 280,
          overflowY: "auto", display: "flex",
          flexDirection: "column", gap: 3,
        }}>
          <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}`}</style>
          {logs.length === 0 ? (
            <span style={{ fontSize: 11, color: "#2a2a4a" }}>
              $ hujum turini tanlang va boshlash tugmasini bosing...
            </span>
          ) : (
            logs.map((l, i) => (
              <div key={i} style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
                <span style={{ fontSize: 10, color: "#2a2a4a", flexShrink: 0 }}>{l.time}</span>
                <span style={{
                  fontSize: 10, fontFamily: "monospace",
                  color: l.type === "error"   ? "#f87171"
                       : l.type === "success" ? "#4ade80"
                       : l.type === "warn"    ? "#facc15"
                       : "#5a5a8a",
                  lineHeight: 1.5,
                }}>
                  {l.type === "error"   ? "[BLOCKED] "
                 : l.type === "success" ? "[OK]      "
                 : l.type === "warn"    ? "[WARN]    "
                 : "[INFO]    "}
                  {l.text}
                </span>
              </div>
            ))
          )}
          <div ref={logEndRef} />
        </div>
      </div>

      {/* Info box */}
      <div style={{
        marginTop: 14, padding: "12px 14px",
        background: "#0d0d14", border: "1px solid #1e1e2e", borderRadius: 8,
      }}>
        <div style={{ fontSize: 10, color: cfg.color, fontWeight: 700, letterSpacing: "0.06em", marginBottom: 6 }}>
          {cfg.icon} {cfg.label.toUpperCase()} — ANIQLASH MEXANIZMI
        </div>
        <p style={{ fontSize: 10, color: "#4a4a6a", lineHeight: 1.7, margin: 0 }}>
          {cfg.mechanism}
        </p>
      </div>
    </div>
  );
}