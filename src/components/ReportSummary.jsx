import SecurityScore from "./SecurityScore";
import SeverityBadge from "./SeverityBadge";

const SEVERITY_COLORS = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

export default function ReportSummary({ report }) {
  const severity = report.severity;
  const total = report.findings || 1;

  return (
    <section className="card card-pad">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <div>
          <div className="stat-label">Security Report</div>
          <h2 style={{ margin: "4px 0 8px", fontSize: 24 }}>{report.project}</h2>
          <div className="row">
            <SeverityBadge status={report.status} />
            <span className="muted">{report.datetime || report.date}</span>
            <span className="dim">· {report.engine}</span>
          </div>
        </div>
        <SecurityScore score={report.score} label={report.scoreLabel} />
      </div>
      <p className="muted" style={{ marginTop: 16 }}>
        {report.findings} vulnerabilities detected
      </p>
      <div style={{ marginTop: 12 }}>
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
      </div>
    </section>
  );
}
