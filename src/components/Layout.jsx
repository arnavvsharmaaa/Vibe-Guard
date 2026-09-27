import { useState } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

// Set VITE_PUBLIC_DEMO=true when building the public demo deployment.
const PUBLIC_DEMO = import.meta.env.VITE_PUBLIC_DEMO === "true";

export default function Layout() {
  const [open, setOpen] = useState(false);

  return (
    <div className="app-shell">
      <Sidebar open={open} onNavigate={() => setOpen(false)} />
      <div className="main-column">
        <Topbar onMenu={() => setOpen((value) => !value)} />
        <main className="content">
          {PUBLIC_DEMO ? (
            <div className="notice" role="note" style={{ marginBottom: "1.25rem" }}>
              Public demo: scans and reports are visible to other visitors and are not kept permanently. Please
              don&apos;t upload private, proprietary or sensitive code.
            </div>
          ) : null}
          <Outlet />
        </main>
      </div>
    </div>
  );
}
