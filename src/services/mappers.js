// Map backend report API responses (snake_case, uppercase severities) to the UI data model.

const SEVERITIES = ["critical", "high", "medium", "low"];

const LANGUAGES = {
  py: "python",
  js: "javascript",
  jsx: "javascript",
  ts: "javascript",
  tsx: "javascript",
  mjs: "javascript",
  cjs: "javascript",
};

function titleCase(value) {
  if (!value) return null;
  const text = String(value).toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function formatDate(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return { date: "", datetime: "" };
  const day = date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  const year = date.getFullYear();
  const time = date.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
  return { date: day, datetime: `${day}, ${year} · ${time}` };
}

function languageFor(file) {
  const ext = String(file || "").split(".").pop().toLowerCase();
  return LANGUAGES[ext] || "text";
}

function engineFor(ai) {
  if (ai && (ai.status === "completed" || ai.status === "partial")) return `Static rules + ${ai.model}`;
  if (ai && ai.status === "failed") return "Static rules (AI analysis failed)";
  return "Static rules";
}

export function mapReportSummary(report) {
  const counts = report.severity_counts || {};
  return {
    id: report.scan_id,
    project: report.project_name,
    ...formatDate(report.created_at),
    score: report.security_score,
    scoreLabel: report.score_label,
    status: titleCase(report.status),
    findings: report.finding_count,
    highestSeverity: titleCase(report.highest_severity),
    filesAnalyzed: report.file_count,
    severity: Object.fromEntries(SEVERITIES.map((key) => [key, counts[key.toUpperCase()] || 0])),
    categories: report.category_counts || {},
  };
}

export function mapReportDetail(report, findings) {
  return {
    ...mapReportSummary(report),
    engine: engineFor(report.ai),
    vulnerabilities: findings.map(mapFinding),
  };
}

export function mapFinding(finding) {
  const endLine = finding.end_line && finding.end_line >= finding.line ? finding.end_line : finding.line;
  const highlightLines = [];
  for (let n = finding.line; n <= endLine; n += 1) highlightLines.push(n);
  return {
    id: finding.finding_id,
    type: finding.type,
    severity: titleCase(finding.severity),
    file: finding.file,
    line: finding.line,
    endLine,
    cwe: finding.cwe || "No CWE",
    scanner: finding.message,
    code: finding.code ?? "",
    startLine: finding.line,
    highlightLines,
    language: languageFor(finding.file),
    aiStatus: finding.ai_status,
  };
}

export function mapFindingDetail(finding) {
  const ai = finding.ai_analysis;
  const aiAvailable = ai?.status === "completed";
  const fallback = `AI analysis not available for this finding (${ai?.status || "not run"}).`;
  return {
    ...mapFinding(finding),
    aiAvailable,
    explanation: (aiAvailable && ai.explanation) || fallback,
    impact: (aiAvailable && ai.impact) || fallback,
    recommendation: (aiAvailable && ai.recommendation) || fallback,
    fixedCode: (aiAvailable && ai.fixed_code) || "",
    fixedHighlightLines: [],
    remediationSteps: (aiAvailable && Array.isArray(ai.remediation_steps) && ai.remediation_steps) || [],
  };
}

export function mapScan(scan) {
  return {
    id: scan.scan_id,
    project: scan.project_name,
    status: titleCase(scan.status),
    ...formatDate(scan.created_at),
    score: scan.security_score,
    error: scan.error,
  };
}
