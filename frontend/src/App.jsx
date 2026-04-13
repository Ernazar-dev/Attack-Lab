import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout    from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Attacker  from "./pages/Attacker";
import History   from "./pages/Historiy";   // TUZATISH: "Historiy" → "History"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="attacker"  element={<Attacker />} />
          <Route path="history"   element={<History />} />
          <Route path="*"         element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}