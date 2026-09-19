import { Link } from "react-router-dom";
import SeverityBadge from "../components/SeverityBadge";
import { reports } from "../data/mockData";

export default function Reports() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">Completed security reports from recent prototype scans.</p>
        </div>
      </div>

      <div className="card" style={{ overflowX: "auto" }}>
        <table className="table">
          <thead>
            <tr>
              <th>Project</th>
              <th>Date</th>
              <th>Score</th>
              <th>Vulnerabilities</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((report) => (
              <tr key={report.id}>
                <td>{report.project}</td>
                <td className="muted">{report.date}</td>
                <td className="mono">{report.score}/100</td>
                <td>{report.findings}</td>
                <td>
                  <SeverityBadge status={report.status} />
                </td>
                <td>
                  <Link className="btn btn-secondary" to={`/reports/${report.id}`}>
                    View Report
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
