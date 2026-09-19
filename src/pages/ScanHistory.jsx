import { useNavigate } from "react-router-dom";
import SeverityBadge from "../components/SeverityBadge";
import { scanHistory } from "../data/mockData";

export default function ScanHistory() {
  const navigate = useNavigate();

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
        {scanHistory.map((item) => (
          <button
            className="history-item"
            type="button"
            key={item.id}
            onClick={() => navigate(`/reports/${item.reportId}`)}
          >
            <strong>{item.project}</strong>
            <span className="muted">{item.datetime}</span>
            <span className="mono">{item.score}/100</span>
            <span>{item.findings}</span>
            <SeverityBadge severity={item.highestSeverity} />
            <SeverityBadge status={item.status} />
          </button>
        ))}
      </div>
    </div>
  );
}
