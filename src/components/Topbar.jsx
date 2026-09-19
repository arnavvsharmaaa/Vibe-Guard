import { Link } from "react-router-dom";
import Icon from "./Icon";
import { currentUser, workspace } from "../data/mockData";

export default function Topbar({ title, onMenu }) {
  return (
    <header className="topbar">
      <div className="topbar-left">
        <button className="icon-btn mobile-toggle" type="button" onClick={onMenu} aria-label="Open navigation">
          <Icon name="menu" />
        </button>
        <div className="repo-chip">
          <Icon name="folder_code" />
          {workspace.org} / {workspace.project}
        </div>
        <div className="watch-chip">
          <span className="status-dot" />
          Static analysis ready · Review 1
        </div>
      </div>
      <div className="topbar-right">
        <label className="search-field">
          <Icon name="search" />
          <input placeholder="Search findings, files, CWEs..." />
          <kbd className="kbd">⌘K</kbd>
        </label>
        <Link className="btn btn-primary" to="/scan">
          <Icon name="add" />
          New Scan
        </Link>
        <button className="icon-btn" type="button" aria-label="Notifications">
          <Icon name="notifications" />
          <span className="ping" />
        </button>
        <div className="user-block">
          <div className="avatar">{currentUser.initials}</div>
          <div className="user-copy">
            <div className="user-name">{currentUser.name}</div>
            <div className="user-role">{currentUser.role}</div>
          </div>
        </div>
      </div>
    </header>
  );
}
