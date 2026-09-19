import { NavLink } from "react-router-dom";
import Icon from "./Icon";

const links = [
  { to: "/", label: "Dashboard", icon: "space_dashboard", end: true },
  { to: "/scan", label: "New Scan", icon: "shield_with_heart" },
  { to: "/reports", label: "Reports", icon: "assignment" },
  { to: "/history", label: "Scan History", icon: "history" },
  { to: "/settings", label: "Settings", icon: "settings" },
];

export default function Sidebar({ open, onNavigate }) {
  return (
    <aside className={`sidebar ${open ? "open" : ""}`}>
      <div className="sidebar-brand">
        <div className="brand-mark">VG</div>
        <div className="brand-text">
          <span className="brand-name">Vibe Guard</span>
          <span className="brand-sub">AI Code Security</span>
        </div>
      </div>
      <nav className="sidebar-nav">
        <div className="nav-group">Workspace</div>
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.end}
            className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
            onClick={onNavigate}
          >
            <Icon name={link.icon} />
            {link.label}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div className="engine-row">
          <span className="sidebar-meta">Review 1 Prototype</span>
          <span className="status-dot" />
        </div>
        <div className="muted" style={{ marginBottom: 8 }}>
          Demo AI Model · static mock scan
        </div>
        <div className="sidebar-meta">Version 0.1</div>
      </div>
    </aside>
  );
}
