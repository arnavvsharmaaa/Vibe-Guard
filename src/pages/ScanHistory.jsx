import { useNavigate } from "react-router-dom";
import SeverityBadge from "../components/SeverityBadge";
import useApiResource from "../hooks/useApiResource";
import { describeError, listReports, listScans } from "../services/api";
import { mapReportSummary, mapScan } from "../services/mappers";

async function loadHistory(signal) {
  const [scans, reports] = await Promise.all([listScans(signal), listReports(signal)]);
  const byId = new Map(reports.reports.map((report) => [report.scan_id, mapReportSummary(report)]));
  return scans.scans.map((scan) => ({ ...mapScan(scan), report: byId.get(scan.scan_id) || null }));
}

export default function ScanHistory() {
  const navigate = useNavigate();
  const { data, error, loading } = useApiResource(loadHistory, []);
  const scanHistory = data || [];

  let message = null;
  if (loading) message = "Loading scan history...";
  else if (error) message = describeError(error);
  else if (!scanHistory.length) message = "No scans yet. Run a new scan to start your history.";

  function open(item) {
    navigate(item.report ? `/reports/${item.id}` : `/scan/progress?scan=${encodeURIComponent(item.id)}`);
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Scan History</h1>
          <p className="page-subtitle">Select a previous scan to open its security report.</p>
        </div>
      </div>

      <div className="card">
        <div className="history-item dim" style={{ cursor: "default" }}>
          <span>Project</span>
          <span>Date / time</span>
          <span>Score</span>
          <span>Findings</span>
          <span>Highest severity</span>
          <span>Status</span>
        </div>
        {message ? <div className="empty-state">{message}</div> : null}
        {scanHistory.map((item) => (
          <button className="history-item" type="button" key={item.id} onClick={() => open(item)}>
            <strong>{item.project}</strong>
            <span className="muted">{item.datetime}</span>
            <span className="mono">{item.report ? `${item.report.score}/100` : "—"}</span>
            <span>{item.report ? item.report.findings : "—"}</span>
            {item.report?.highestSeverity ? (
              <SeverityBadge severity={item.report.highestSeverity} />
            ) : (
              <span className="dim">—</span>
            )}
            <SeverityBadge status={item.status} />
          </button>
        ))}
      </div>
    </div>
  );
}
