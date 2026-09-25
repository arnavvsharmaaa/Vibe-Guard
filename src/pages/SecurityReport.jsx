import { Link, useParams } from "react-router-dom";
import ReportSummary from "../components/ReportSummary";
import VulnerabilityList from "../components/VulnerabilityList";
import useApiResource from "../hooks/useApiResource";
import { describeError, getReport, getReportFindings } from "../services/api";
import { mapReportDetail } from "../services/mappers";

function ReportError({ error, id }) {
  if (error.status === 409) {
    return (
      <div className="card empty-state">
        <p>{error.detail}.</p>
        <Link className="btn btn-secondary" to={`/scan/progress?scan=${encodeURIComponent(id)}`}>
          View scan progress
        </Link>
      </div>
    );
  }
  const notFound = error.status === 400 || error.status === 404;
  return (
    <div className="card empty-state">
      <p>{notFound ? "Report not found." : describeError(error)}</p>
      <Link className="btn btn-secondary" to="/reports">
        All reports
      </Link>
    </div>
  );
}

export default function SecurityReport() {
  const { id } = useParams();
  const { data: report, error, loading } = useApiResource(
    async (signal) => {
      const [detail, findings] = await Promise.all([getReport(id, signal), getReportFindings(id, signal)]);
      return mapReportDetail(detail, findings.findings);
    },
    [id]
  );

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Report</h1>
          <p className="page-subtitle">
            {report
              ? `Scan completed for ${report.project}. Review findings, then open a finding for the full AI remediation path.`
              : "Review findings, then open a finding for the full AI remediation path."}
          </p>
        </div>
        <Link className="btn btn-secondary" to="/reports">
          All reports
        </Link>
      </div>
      {loading ? <div className="card empty-state">Loading report...</div> : null}
      {error ? <ReportError error={error} id={id} /> : null}
      {report ? (
        <>
          <ReportSummary report={report} />
          <section>
            <h2 className="section-title">Findings</h2>
            <VulnerabilityList findings={report.vulnerabilities} reportId={report.id} />
          </section>
        </>
      ) : null}
    </div>
  );
}
