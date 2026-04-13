import { NavLink, Outlet } from "react-router-dom";
import { Activity, Skull, ScrollText, Shield, Wifi } from "lucide-react";
import { useEffect, useState, createContext, useContext } from "react";
import { io } from "socket.io-client";

// WebSocket context — barcha komponentlar bu orqali foydalanadi
// Oldin: Dashboard.jsx va Layout.jsx da alohida io() chaqirilardi = 2 ta parallel ulanish
// Endi: faqat shu yerda 1 ta ulanish, context orqali tarqatiladi
export const SocketContext = createContext({
  connected: false,
  lastAlert: null,
});

export function useSocket() {
  return useContext(SocketContext);
}

const SERVER_URL = import.meta.env.VITE_SERVER_URL || "http://localhost:5000";

const links = [
  { to: "/dashboard", label: "Dashboard",  icon: Activity  },
  { to: "/attacker",  label: "Attacker",   icon: Skull     },
  { to: "/history",   label: "Tarix",      icon: ScrollText },
];

export default function Layout() {
  const [connected, setConnected] = useState(false);
  const [lastAlert, setLastAlert] = useState(null);
  // Dashboard uchun live events ham shu yerda saqlanadi
  const [liveEvents, setLiveEvents] = useState([]);

  useEffect(() => {
    const socket = io(SERVER_URL, {
      transports: ["websocket"],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
    });

    socket.on("connect",    () => setConnected(true));
    socket.on("disconnect", () => setConnected(false));
    socket.on("connect_error", (err) => {
      console.warn("Socket ulanish xatosi:", err.message);
      setConnected(false);
    });
    socket.on("new_alert", (data) => {
      const event = { ...data, _id: Date.now() + Math.random() };
      if (data.status === "ATTACK") {
        setLastAlert(data);
      }
      setLiveEvents((prev) => [event, ...prev].slice(0, 50));
    });

    return () => socket.disconnect();
  }, []);

  return (
    <SocketContext.Provider value={{ connected, lastAlert, liveEvents }}>
      <div style={{
        display: "flex",
        minHeight: "100vh",
        background: "#0a0a0f",
        color: "#e8e6f0",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      }}>

        {/* Sidebar */}
        <aside style={{
          width: 220,
          background: "#0d0d14",
          borderRight: "1px solid #1e1e2e",
          display: "flex",
          flexDirection: "column",
          position: "fixed",
          top: 0, left: 0, bottom: 0,
          zIndex: 50,
        }}>
          {/* Logo */}
          <div style={{
            padding: "20px 20px 16px",
            borderBottom: "1px solid #1e1e2e",
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}>
            <div style={{
              width: 32, height: 32,
              background: "linear-gradient(135deg, #3b82f6, #8b5cf6)",
              borderRadius: 8,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <Shield size={16} color="#fff" />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: 13, letterSpacing: "0.08em", color: "#f0eeff" }}>
                IDS / IPS
              </div>
              <div style={{ fontSize: 10, color: "#4a4a6a", letterSpacing: "0.05em" }}>
                ML DETECTION v5
              </div>
            </div>
          </div>

          {/* Connection status */}
          <div style={{
            margin: "12px 12px 0",
            padding: "8px 12px",
            borderRadius: 6,
            background: connected ? "#0f1f14" : "#1a0f0f",
            border: `1px solid ${connected ? "#1a3a20" : "#3a1a1a"}`,
            display: "flex", alignItems: "center", gap: 8,
          }}>
            <span style={{
              width: 7, height: 7, borderRadius: "50%",
              background: connected ? "#4ade80" : "#f87171",
              boxShadow: connected ? "0 0 8px #4ade80" : "0 0 8px #f87171",
              flexShrink: 0,
            }} />
            <span style={{
              fontSize: 10,
              color: connected ? "#4ade80" : "#f87171",
              letterSpacing: "0.05em",
            }}>
              {connected ? "CONNECTED" : "OFFLINE"}
            </span>
            <Wifi size={11} color={connected ? "#4ade80" : "#f87171"} style={{ marginLeft: "auto" }} />
          </div>

          {/* Nav */}
          <nav style={{ flex: 1, padding: "16px 12px" }}>
            <div style={{
              fontSize: 9, color: "#2a2a4a",
              letterSpacing: "0.12em", padding: "0 8px 8px", fontWeight: 600,
            }}>
              NAVIGATION
            </div>
            {links.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                style={({ isActive }) => ({
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "9px 12px",
                  borderRadius: 6,
                  fontSize: 12,
                  fontWeight: isActive ? 600 : 400,
                  color: isActive ? "#a78bfa" : "#5a5a8a",
                  background: isActive ? "#16122a" : "transparent",
                  border: isActive ? "1px solid #2d2060" : "1px solid transparent",
                  textDecoration: "none",
                  transition: "all 0.15s",
                  marginBottom: 2,
                  letterSpacing: "0.04em",
                })}
              >
                <Icon size={14} />
                {label.toUpperCase()}
              </NavLink>
            ))}
          </nav>

          {/* Last attack alert */}
          {lastAlert && (
            <div style={{
              margin: 12,
              padding: "10px 12px",
              background: "#1a0808",
              border: "1px solid #3a1010",
              borderRadius: 6,
            }}>
              <div style={{ fontSize: 9, color: "#f87171", letterSpacing: "0.1em", marginBottom: 4 }}>
                LAST ATTACK
              </div>
              <div style={{ fontSize: 11, color: "#fca5a5", fontWeight: 600 }}>
                {lastAlert.attack_type}
              </div>
              <div style={{ fontSize: 10, color: "#5a2a2a", marginTop: 2 }}>
                {lastAlert.ip} · {lastAlert.time}
              </div>
            </div>
          )}

          {/* Footer */}
          <div style={{ padding: "12px 20px", borderTop: "1px solid #1e1e2e" }}>
            <p style={{ fontSize: 9, color: "#2a2a4a", letterSpacing: "0.08em", margin: 0 }}>
              XGBoost · CICIDS2017 · Flask
            </p>
          </div>
        </aside>

        {/* Main content */}
        <main style={{
          flex: 1,
          marginLeft: 220,
          padding: "32px 36px",
          maxWidth: "calc(100vw - 220px)",
        }}>
          <Outlet />
        </main>
      </div>
    </SocketContext.Provider>
  );
}