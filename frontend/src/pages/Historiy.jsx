import { useCallback, useEffect, useState } from "react";
import axios from "axios";
import { RefreshCcw, ShieldAlert, ShieldCheck, Search, Filter, Download } from "lucide-react";

const SERVER = import.meta.env.VITE_SERVER_URL || "http://localhost:5000";

const TYPE_COLORS = {
  BENIGN:   { text: "#4ade80", bg: "#0a1f10", border: "#1a4020" },
  DNS:      { text: "#818cf8", bg: "#10102a", border: "#20205a" },
  NTP:      { text: "#a78bfa", bg: "#14102a", border: "#2a1f5a" },
  SYN:      { text: "#f87171", bg: "#2a0808", border: "#5a1515" },
  UDP:      { text: "#fb923c", bg: "#2a1208", border: "#5a2a10" },
  LDAP:     { text: "#c084fc", bg: "#160d2a", border: "#2d1a5a" },
  PORTSCAN: { text: "#facc15", bg: "#1a1a05", border: "#3a3a10" },
};
const getTypeStyle = (t) => TYPE_COLORS[t] || { text: "#9090c0", bg: "#10101a", border: "#20203a" };

export default function History() {
  const [logs,       setLogs]       = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState(null);
  const [search,     setSearch]     = useState("");
  const [filterType, setFilterType] = useState("ALL");
  const [filterStat, setFilterStat] = useState("ALL");

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get(`${SERVER}/api/logs?limit=200`);
      setLogs(res.data);
    } catch (err) {
      setError(err.response?.data?.error || "Serverga ulanib bo'lmadi.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const attacks = logs.filter((l) => l.status === "ATTACK").length;
  const types   = ["ALL", ...new Set(logs.map((l) => l.attack_type))];

  const filtered = logs.filter((l) => {
    const matchSearch = l.ip.includes(search) || l.attack_type.includes(search.toUpperCase());
    const matchType   = filterType === "ALL" || l.attack_type === filterType;
    const matchStat   = filterStat === "ALL" || l.status === filterStat;
    return matchSearch && matchType && matchStat;
  });

  const exportCSV = () => {
    const header = "ID,IP,Hujum turi,Req/s,Holat,Vaqt";
    const rows = logs.map((l) =>
      `${l.id},"${l.ip}",${l.attack_type},${l.req},${l.status},${l.time}`
    );
    const blob = new Blob([[header, ...rows].join("\n")], { type: "text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url;
    a.download = `ids_logs_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>
      <style>{`
        input::placeholder { color: #2a2a4a; }
        select option { background: #0d0d14; color: #e8e6f0; }
        @keyframes spin { from { transform: rotate(0deg) } to { transform: rotate(360deg) } }
      `}</style>

      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "flex-start", marginBottom: 24,
      }}>
        <div>
          <h1 style={{ fontSize: 18, fontWeight: 700, color: "#f0eeff", margin: 0, letterSpacing: "0.04em" }}>
            HUJUMLAR JURNALI
          </h1>
          {!loading && !error && (
            <p style={{ fontSize: 10, color: "#3a3a5a", margin: "4px 0 0", letterSpacing: "0.06em" }}>
              JAMI {logs.length} · HUJUM{" "}
              <span style={{ color: "#f87171" }}>{attacks}</span> ·{" "}
              NORMAL <span style={{ color: "#4ade80" }}>{logs.length - attacks}</span>
            </p>
          )}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={exportCSV}
            disabled={logs.length === 0}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              background: "#0d0d14", border: "1px solid #1e1e2e",
              color: logs.length === 0 ? "#2a2a4a" : "#4a4a6a",
              padding: "8px 12px", borderRadius: 6,
              fontSize: 10, cursor: logs.length === 0 ? "not-allowed" : "pointer",
              letterSpacing: "0.06em", fontWeight: 600, outline: "none",
            }}
          >
            <Download size={11} />
            CSV
          </button>
          <button
            onClick={fetchLogs}
            disabled={loading}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              background: "#0d0d14", border: "1px solid #1e1e2e",
              color: loading ? "#2a2a4a" : "#818cf8",
              padding: "8px 14px", borderRadius: 6,
              fontSize: 10, cursor: loading ? "not-allowed" : "pointer",
              letterSpacing: "0.06em", fontWeight: 600, outline: "none",
            }}
          >
            <RefreshCcw
              size={11}
              style={{ animation: loading ? "spin 1s linear infinite" : "none" }}
            />
            YANGILASH
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          marginBottom: 16, padding: "12px 14px",
          background: "#1a0808", border: "1px solid #5a1515",
          color: "#f87171", borderRadius: 8, fontSize: 11,
        }}>
          ⚠ {error}
        </div>
      )}

      {/* Filters */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ position: "relative", flex: 1, minWidth: 160 }}>
          <Search size={11} color="#2a2a4a" style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }} />
          <input
            type="text"
            placeholder="IP yoki tur qidiring..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: "100%", background: "#0d0d14",
              border: "1px solid #1e1e2e", color: "#c0c0e0",
              padding: "8px 12px 8px 28px", borderRadius: 6,
              fontSize: 11, outline: "none", boxSizing: "border-box",
              fontFamily: "inherit",
            }}
          />
        </div>

        <div style={{ position: "relative" }}>
          <Filter size={10} color="#2a2a4a" style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }} />
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            style={{
              background: "#0d0d14", border: "1px solid #1e1e2e",
              color: "#c0c0e0", padding: "8px 12px 8px 26px",
              borderRadius: 6, fontSize: 10, outline: "none",
              cursor: "pointer", fontFamily: "inherit", letterSpacing: "0.04em",
            }}
          >
            {types.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        {["ALL", "ATTACK", "NORMAL"].map((s) => (
          <button
            key={s}
            onClick={() => setFilterStat(s)}
            style={{
              padding: "7px 12px", borderRadius: 6,
              border: `1px solid ${filterStat === s
                ? s === "ATTACK" ? "#5a1515" : s === "NORMAL" ? "#1a4020" : "#3a3a6a"
                : "#1e1e2e"}`,
              background: filterStat === s
                ? s === "ATTACK" ? "#1a0808" : s === "NORMAL" ? "#081a0a" : "#12122a"
                : "#0d0d14",
              color: filterStat === s
                ? s === "ATTACK" ? "#f87171" : s === "NORMAL" ? "#4ade80" : "#818cf8"
                : "#3a3a5a",
              fontSize: 9, fontWeight: 700, cursor: "pointer",
              letterSpacing: "0.08em", outline: "none", fontFamily: "inherit",
            }}
          >
            {s}
          </button>
        ))}

        <span style={{ fontSize: 10, color: "#2a2a4a", marginLeft: "auto" }}>
          {filtered.length} ta
        </span>
      </div>

      {/* Table */}
      <div style={{
        background: "#0d0d14", border: "1px solid #1e1e2e",
        borderRadius: 10, overflow: "hidden",
      }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "50px 1fr 110px 70px 80px 80px",
          gap: 8, padding: "10px 16px",
          borderBottom: "1px solid #1e1e2e", background: "#0a0a12",
        }}>
          {["ID", "IP MANZIL", "HUJUM TURI", "REQ/S", "HOLAT", "VAQT"].map((h) => (
            <span key={h} style={{ fontSize: 9, color: "#2a2a4a", letterSpacing: "0.12em", fontWeight: 600 }}>
              {h}
            </span>
          ))}
        </div>

        {loading ? (
          <div style={{ padding: "40px 0", textAlign: "center", fontSize: 11, color: "#2a2a4a" }}>
            yuklanmoqda...
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: "40px 0", textAlign: "center", fontSize: 11, color: "#2a2a4a" }}>
            {logs.length === 0 ? "hozircha yozuv yo'q" : "filtr natija bermadi"}
          </div>
        ) : (
          filtered.map((l) => {
            const ts = getTypeStyle(l.attack_type);
            return (
              <div
                key={l.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "50px 1fr 110px 70px 80px 80px",
                  gap: 8, padding: "10px 16px",
                  borderBottom: "1px solid #0e0e1a",
                  alignItems: "center", cursor: "default",
                  transition: "background 0.1s",
                }}
                onMouseEnter={(e) => e.currentTarget.style.background = "#10101a"}
                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
              >
                <span style={{ fontSize: 10, color: "#2a2a4a" }}>#{l.id}</span>

                <span style={{
                  fontSize: 11, color: "#7070a0", fontFamily: "monospace",
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>
                  {l.ip}
                </span>

                <span style={{
                  fontSize: 9, fontWeight: 700,
                  background: ts.bg, border: `1px solid ${ts.border}`,
                  color: ts.text, padding: "3px 8px", borderRadius: 4,
                  letterSpacing: "0.05em", display: "inline-block", textAlign: "center",
                }}>
                  {l.attack_type}
                </span>

                <span style={{ fontSize: 11, color: "#4a4a6a", textAlign: "right" }}>
                  {l.req}
                </span>

                <div>
                  {l.status === "ATTACK" ? (
                    <span style={{
                      display: "inline-flex", alignItems: "center", gap: 4,
                      background: "#1a0505", border: "1px solid #4a1010",
                      color: "#f87171", padding: "3px 8px", borderRadius: 4,
                      fontSize: 9, fontWeight: 700, letterSpacing: "0.05em",
                    }}>
                      <ShieldAlert size={8} /> ATTACK
                    </span>
                  ) : (
                    <span style={{
                      display: "inline-flex", alignItems: "center", gap: 4,
                      background: "#051a08", border: "1px solid #104a18",
                      color: "#4ade80", padding: "3px 8px", borderRadius: 4,
                      fontSize: 9, fontWeight: 700, letterSpacing: "0.05em",
                    }}>
                      <ShieldCheck size={8} /> OK
                    </span>
                  )}
                </div>

                <span style={{
                  fontSize: 10, color: "#2a2a4a",
                  textAlign: "right", fontFamily: "monospace",
                }}>
                  {l.time}
                </span>
              </div>
            );
          })
        )}
      </div>

      {filtered.length > 0 && (
        <div style={{
          marginTop: 8, fontSize: 10, color: "#2a2a4a",
          textAlign: "center", letterSpacing: "0.06em",
        }}>
          {filtered.length} ta yozuv ko'rsatilmoqda
        </div>
      )}
    </div>
  );
}