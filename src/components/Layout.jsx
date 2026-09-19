import { useState } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

export default function Layout() {
  const [open, setOpen] = useState(false);

  return (
    <div className="app-shell">
      <Sidebar open={open} onNavigate={() => setOpen(false)} />
      <div className="main-column">
        <Topbar onMenu={() => setOpen((value) => !value)} />
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
