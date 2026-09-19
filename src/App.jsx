import { useEffect } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import NewScan from "./pages/NewScan";
import ScanProgress from "./pages/ScanProgress";
import Reports from "./pages/Reports";
import SecurityReport from "./pages/SecurityReport";
import VulnerabilityDetail from "./pages/VulnerabilityDetail";
import ScanHistory from "./pages/ScanHistory";
import Settings from "./pages/Settings";
import { checkHealth } from "./services/api";

export default function App() {
  useEffect(() => {
    checkHealth()
      .then((data) => {
        console.log("[VibeGuard API Health Check]", data);
      })
      .catch((err) => {
        console.error("[VibeGuard API Health Check Failed]", err);
      });
  }, []);
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<NewScan />} />
          <Route path="/scan/progress" element={<ScanProgress />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/reports/:id" element={<SecurityReport />} />
          <Route path="/reports/:id/findings/:findingId" element={<VulnerabilityDetail />} />
          <Route path="/history" element={<ScanHistory />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
