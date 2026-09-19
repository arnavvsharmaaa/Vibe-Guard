import { Link, useParams } from "react-router-dom";
import ReportSummary from "../components/ReportSummary";
import VulnerabilityList from "../components/VulnerabilityList";
import { getReportById } from "../data/mockData";

export default function SecurityReport() {
  const { id } = useParams();
  const report = getReportById(id);

  return (
    <div className="stack">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Report</h1>
          <p className="page-subtitle">
            Scan completed for {report.project}. Review findings, then open SQL Injection for the full AI remediation path.
          </p>
        </div>
        <Link className="btn btn-secondary" to="/reports">
          All reports
        </Link>
      </div>
      <ReportSummary report={report} />
      <section>
        <h2 className="section-title">Findings</h2>
        <VulnerabilityList findings={report.vulnerabilities} reportId={report.id} />
      </section>
    </div>
  );
}
