import { Link } from "react-router-dom";
import StatCard from "../components/StatCard";
import SecurityScore from "../components/SecurityScore";
import SeverityBadge from "../components/SeverityBadge";
import { dashboardSummary } from "../data/mockData";

const SEVERITY_COLORS = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

export default function Dashboard() {
  const { score, scoreLabel, total, severity, categories, recentScan } = dashboardSummary;
  const maxCategory = Math.max(...Object.values(categories), 1);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-subtitle">AI-powered security analysis for your application code.</p>
        </div>
        <Link className="btn btn-primary" to="/scan">
          + New Scan
        </Link>
      </div>

      <div className="grid-stats">
        <StatCard label="Security Score" value={`${score}/100`} meta={scoreLabel} />
        <StatCard label="Total Vulnerabilities" value={total} meta="Latest completed scan" />
        <StatCard label="High Severity" value={severity.high} tone="var(--high-fg)" meta="Requires prompt remediation" />
        <StatCard label="Medium Severity" value={severity.medium} tone="var(--medium-fg)" meta="Schedule fixes this sprint" />
        <StatCard label="Low Severity" value={severity.low} tone="var(--low-fg)" meta="Harden remaining issues" />
      </div>

      <div className="grid-2">
        <section className="card card-pad">
          <h2 className="section-title">Vulnerability Distribution</h2>
          {["critical", "high", "medium", "low"].map((key) => (
            <div className="dist-row" key={key}>
              <span className="dist-label">{key}</span>
              <div className="dist-track">
                <div
                  className="dist-fill"
                  style={{
                    width: `${((severity[key] || 0) / total) * 100}%`,
                    background: SEVERITY_COLORS[key],
                  }}
                />
              </div>
              <span className="dist-count">{severity[key] || 0}</span>
            </div>
          ))}
        </section>

        <section className="card card-pad">
          <h2 className="section-title">Vulnerability Categories</h2>
          <div className="category-list">
            {Object.entries(categories).map(([name, count]) => (
              <div className="category-item" key={name}>
                <span>{name}</span>
                <span className="mono">{count}</span>
                <div className="dist-track" style={{ maxWidth: 120 }}>
                  <div
                    className="dist-fill"
                    style={{ width: `${(count / maxCategory) * 100}%`, background: "var(--primary)" }}
                  />
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="card card-pad" style={{ marginTop: 12 }}>
        <h2 className="section-title">Recent Scan</h2>
        <div className="recent-scan">
          <SecurityScore score={recentScan.score} label={scoreLabel} />
          <div style={{ flex: 1 }}>
            <div className="row">
              <strong>{recentScan.project}</strong>
              <SeverityBadge status={recentScan.status} />
            </div>
            <p className="muted" style={{ margin: "8px 0 0" }}>
              {recentScan.score}/100 · {recentScan.findings} vulnerabilities
            </p>
          </div>
          <Link className="btn btn-primary" to={`/reports/${recentScan.reportId}`}>
            View Report
          </Link>
        </div>
      </section>
    </div>
  );
}
