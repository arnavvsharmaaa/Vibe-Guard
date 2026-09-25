import { Link } from "react-router-dom";
import SeverityBadge from "../components/SeverityBadge";
import useApiResource from "../hooks/useApiResource";
import { describeError, listReports } from "../services/api";
import { mapReportSummary } from "../services/mappers";

export default function Reports() {
  const { data, error, loading } = useApiResource((signal) => listReports(signal), []);
  const reports = (data?.reports || []).map(mapReportSummary);

  let message = null;
  if (loading) message = "Loading reports...";
  else if (error) message = describeError(error);
  else if (!reports.length) message = "No completed reports yet. Run a new scan to generate one.";

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle">Completed security reports from recent prototype scans.</p>
        </div>
      </div>

      {message ? (
        <div className="card empty-state">{message}</div>
      ) : (
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
      )}
    </div>
  );
}
