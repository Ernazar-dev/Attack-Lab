import { useEffect, useState, useRef } from "react";
import axios from "axios";
import {
  ShieldAlert, ShieldCheck, Activity, Zap,
  TrendingUp, BarChart2, Clock,
} from "lucide-react";
import { useSocket } from "../components/Layout";

const SERVER = import.meta.env.VITE_SERVER_URL || "http://localhost:5000";

const ATTACK_COLORS = {
  BENIGN:   { bg: "#0f2a1a", border: "#1a4a2a", text: "#4ade80", dot: "#4ade80" },
  DNS:      { bg: "#1a1a2a", border: "#2a2a5a", text: "#818cf8", dot: "#818cf8" },
  NTP:      { bg: "#1a1a2a", border: "#2a2a5a", text: "#a78bfa", dot: "#a78bfa" },
  SYN:      { bg: "#2a0f0f", border: "#5a1a1a", text: "#f87171", dot: "#f87171" },
  UDP:      { bg: "#2a1a0f", border: "#5a3a1a", text: "#fb923c", dot: "#fb923c" },
  LDAP:     { bg: "#1a1a2a", border: "#3a2a5a", text: "#c084fc", dot: "#c084fc" },
  PORTSCAN: { bg: "#2a2a0f", border: "#5a5a1a", text: "#facc15", dot: "#facc15" },
};

const getColor = (type) => ATTACK_COLORS[type] || ATTACK_COLORS.DNS;

function MiniBar({ value, max, color }) {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{
        flex: 1, height: 4, background: "#1e1e2e",
        borderRadius: 2, overflow: "hidden",
      }}>
        <div style={{
          width: `${pct}%`, height: "100%",
          background: color, borderRadius: 2,
          transition: "width 0.4s ease",
        }} />
      </div>
      <span style={{
        fontSize: 11, color, minWidth: 28,
        textAlign: "right", fontWeight: 600,
      }}>{value}</span>
    </div>
  );
}

function StatCard({ label, value, sub, icon: Icon, color, pulse }) {
  return (
    <div style={{
      background: "#0d0d14", border: "1px solid #1e1e2e",
      borderRadius: 10, padding: "18px 20px",
      position: "relative", overflow: "hidden",
    }}>
      <div style={{
        position: "absolute", top: 0, right: 0,
        width: 80, height: 80,
        background: `radial-gradient(circle at top right, ${color}15, transparent 70%)`,
        pointerEvents: "none",
      }} />
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "flex-start", marginBottom: 10,
      }}>
        <span style={{ fontSize: 10, color: "#3a3a5a", letterSpacing: "0.1em", fontWeight: 600 }}>
          {label}
        </span>
        <div style={{
          width: 28, height: 28, borderRadius: 6,
          background: `${color}18`, border: `1px solid ${color}30`,
          display: "flex", alignItems: "center", justifyContent: "center",
        }}>
          <Icon size={13} color={color} />
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
        <span style={{ fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>{value}</span>
        {pulse && (
          <span style={{
            width: 6, height: 6, borderRadius: "50%",
            background: color, boxShadow: `0 0 8px ${color}`,
            animation: "pulse 1.5s infinite", flexShrink: 0,
          }} />
        )}
      </div>
      {sub && <div style={{ fontSize: 10, color: "#3a3a5a", marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

function EventRow({ log: entry, animate }) {
  const c = getColor(entry.attack_type);
  return (
    <div style={{
      display: "grid",
      gridTemplateColumns: "80px 1fr 100px 60px 80px",
      gap: 12, padding: "10px 16px",
      borderBottom: "1px solid #12121c",
      alignItems: "center",
      background: animate ? "#16121e" : "transparent",
      transition: "background 0.5s ease",
      fontSize: 11,
    }}>
      <span style={{ color: "#3a3a5a", fontFamily: "monospace" }}>{entry.time}</span>
      <span style={{
        color: "#9090c0", fontFamily: "monospace",
        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
      }}>
        {entry.ip}
      </span>
      <span style={{
        background: c.bg, border: `1px solid ${c.border}`,
        color: c.text, padding: "2px 8px", borderRadius: 4,
        fontSize: 10, fontWeight: 600, textAlign: "center", letterSpacing: "0.05em",
      }}>
        {entry.attack_type}
      </span>
      <span style={{ color: "#5a5a8a", textAlign: "right" }}>{entry.req}/s</span>
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        {entry.status === "ATTACK" ? (
          <span style={{
            display: "flex", alignItems: "center", gap: 4,
            background: "#2a0808", border: "1px solid #5a1515",
            color: "#f87171", padding: "2px 8px", borderRadius: 4,
            fontSize: 10, fontWeight: 600,
          }}>
            <ShieldAlert size={9} /> ATTACK
          </span>
        ) : (
          <span style={{
            display: "flex", alignItems: "center", gap: 4,
            background: "#0a1f10", border: "1px solid #1a4020",
            color: "#4ade80", padding: "2px 8px", borderRadius: 4,
            fontSize: 10, fontWeight: 600,
          }}>
            <ShieldCheck size={9} /> OK
          </span>
        )}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [logs,  setLogs]  = useState([]);
  const [newId, setNewId] = useState(null);

  // Context dan WebSocket ma'lumotlari — yangi ulanish ochilmaydi
  const { connected, liveEvents } = useSocket();

  const fetchAll = async () => {
    try {
      const [s, l] = await Promise.all([
        axios.get(`${SERVER}/api/stats`),
        axios.get(`${SERVER}/api/logs`),
      ]);
      setStats(s.data);
      setLogs(l.data);
    } catch (err) {
      console.warn("API xato:", err.message);
    }
  };

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 10_000);
    return () => clearInterval(interval);
  }, []);

  // Yangi event kelganda animate qilish
  useEffect(() => {
    if (liveEvents.length > 0) {
      const latest = liveEvents[0];
      setNewId(latest._id);
      setTimeout(() => setNewId(null), 800);
    }
  }, [liveEvents]);

  const byType     = stats?.by_type || {};
  const maxAttack  = Math.max(...Object.values(byType), 1);
  const attackRate = stats?.attack_rate ?? 0;

  return (
    <div>
      <style>{`
        @keyframes pulse { 0%,100% { opacity:1 } 50% { opacity:0.3 } }
      `}</style>

      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between",
        alignItems: "flex-start", marginBottom: 28,
      }}>
        <div>
          <h1 style={{
            fontSize: 22, fontWeight: 700, color: "#f0eeff",
            margin: 0, letterSpacing: "0.04em",
          }}>
            THREAT MONITOR
          </h1>
          <p style={{ fontSize: 11, color: "#3a3a5a", margin: "4px 0 0", letterSpacing: "0.06em" }}>
            REAL-TIME NETWORK INTRUSION DETECTION
          </p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{
            width: 6, height: 6, borderRadius: "50%",
            background: connected ? "#4ade80" : "#f87171",
            boxShadow: connected ? "0 0 8px #4ade80" : "0 0 8px #f87171",
            animation: "pulse 2s infinite",
          }} />
          <span style={{
            fontSize: 10,
            color: connected ? "#4ade80" : "#f87171",
            letterSpacing: "0.08em",
          }}>
            {connected ? "LIVE" : "OFFLINE"}
          </span>
        </div>
      </div>

      {/* Stats grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
        <StatCard label="TOTAL FLOWS"  value={stats?.total   ?? "—"} sub="Jami tahlil qilingan"  icon={Activity}    color="#818cf8" pulse={connected} />
        <StatCard label="ATTACKS"      value={stats?.attacks ?? "—"} sub="Bloklangan hujumlar"   icon={ShieldAlert} color="#f87171" />
        <StatCard label="NORMAL"       value={stats?.normal  ?? "—"} sub="O'tkazib yuborilgan"   icon={ShieldCheck} color="#4ade80" />
        <StatCard
          label="ATTACK RATE"
          value={`${attackRate}%`}
          sub="Hujum ulushi"
          icon={TrendingUp}
          color={attackRate > 50 ? "#f87171" : attackRate > 20 ? "#fb923c" : "#4ade80"}
        />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>

        {/* Attack breakdown */}
        <div style={{
          background: "#0d0d14", border: "1px solid #1e1e2e",
          borderRadius: 10, padding: "18px 20px",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 16 }}>
            <BarChart2 size={13} color="#818cf8" />
            <span style={{ fontSize: 10, color: "#3a3a5a", letterSpacing: "0.1em", fontWeight: 600 }}>
              ATTACK BREAKDOWN
            </span>
          </div>
          {Object.keys(byType).length === 0 ? (
            <div style={{ fontSize: 11, color: "#2a2a4a", textAlign: "center", padding: "20px 0" }}>
              Hujum yozuvlari yo'q
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {Object.entries(byType)
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) => (
                  <div key={type}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                      <span style={{
                        fontSize: 10, color: getColor(type).text,
                        letterSpacing: "0.06em", fontWeight: 600,
                      }}>{type}</span>
                    </div>
                    <MiniBar value={count} max={maxAttack} color={getColor(type).dot} />
                  </div>
                ))}
            </div>
          )}
        </div>

        {/* Live feed — context dan keladi */}
        <div style={{
          background: "#0d0d14", border: "1px solid #1e1e2e",
          borderRadius: 10, overflow: "hidden",
        }}>
          <div style={{
            padding: "14px 16px", borderBottom: "1px solid #1e1e2e",
            display: "flex", alignItems: "center", justifyContent: "space-between",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Zap size={13} color="#facc15" />
              <span style={{ fontSize: 10, color: "#3a3a5a", letterSpacing: "0.1em", fontWeight: 600 }}>
                LIVE EVENTS
              </span>
            </div>
            <span style={{ fontSize: 10, color: "#2a2a4a" }}>{liveEvents.length} ta</span>
          </div>
          <div style={{ maxHeight: 220, overflowY: "auto" }}>
            {liveEvents.length === 0 ? (
              <div style={{ fontSize: 11, color: "#2a2a4a", textAlign: "center", padding: "30px 0" }}>
                WebSocket kutilmoqda...
              </div>
            ) : (
              liveEvents.map((e) => (
                <EventRow key={e._id} log={e} animate={e._id === newId} />
              ))
            )}
          </div>
        </div>
      </div>

      {/* Recent logs table */}
      <div style={{
        background: "#0d0d14", border: "1px solid #1e1e2e",
        borderRadius: 10, overflow: "hidden",
      }}>
        <div style={{
          padding: "14px 16px", borderBottom: "1px solid #1e1e2e",
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <Clock size={13} color="#818cf8" />
          <span style={{ fontSize: 10, color: "#3a3a5a", letterSpacing: "0.1em", fontWeight: 600 }}>
            SO'NGGI YOZUVLAR
          </span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <div style={{
            display: "grid",
            gridTemplateColumns: "80px 1fr 100px 60px 80px",
            gap: 12, padding: "8px 16px 6px",
            borderBottom: "1px solid #12121c",
          }}>
            {["VAQT", "IP MANZIL", "HUJUM TURI", "REQ/S", "HOLAT"].map((h) => (
              <span key={h} style={{
                fontSize: 9, color: "#2a2a4a",
                letterSpacing: "0.1em", fontWeight: 600,
              }}>{h}</span>
            ))}
          </div>
          {logs.slice(0, 12).map((l) => (
            <EventRow key={l.id} log={l} animate={false} />
          ))}
          {logs.length === 0 && (
            <div style={{ fontSize: 11, color: "#2a2a4a", textAlign: "center", padding: "24px 0" }}>
              Yozuvlar yo'q
            </div>
          )}
        </div>
      </div>
    </div>
  );
}