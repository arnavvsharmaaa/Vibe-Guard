import { useEffect, useState } from "react";
import { Link, useLocation, useSearchParams } from "react-router-dom";
import ScanPipeline from "../components/ScanPipeline";
import ProgressIndicator from "../components/ProgressIndicator";
import { scanStages } from "../data/mockData";
import { ApiError, describeError, getScan, getScanStatus } from "../services/api";

const POLL_INTERVAL_MS = 1500;
const MAX_CONSECUTIVE_ERRORS = 5;

// Backend statuses mapped onto the pipeline stages; "analyzing" covers normalization, scoring and AI.
const STAGE_INDEX = { uploaded: 1, queued: 1, scanning: 1, analyzing: 3, completed: scanStages.length };

export default function ScanProgress() {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const scanId = searchParams.get("scan");
  const [projectName, setProjectName] = useState(location.state?.projectName || "");
  const [status, setStatus] = useState(null);
  const [stageStatus, setStageStatus] = useState(null);
  const [failure, setFailure] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!scanId) return undefined;
    const controller = new AbortController();
    const { signal } = controller;
    let timer = null;
    let consecutiveErrors = 0;

    setStatus(null);
    setStageStatus(null);
    setFailure(null);
    setError(null);

    async function loadFailure() {
      try {
        const scan = await getScan(scanId, signal);
        if (!signal.aborted) setFailure(scan.error || "The scan failed.");
      } catch {
        if (!signal.aborted) setFailure("The scan failed.");
      }
    }

    async function poll() {
      try {
        const result = await getScanStatus(scanId, signal);
        if (signal.aborted) return;
        consecutiveErrors = 0;
        setStatus(result.status);
        if (result.status !== "failed") setStageStatus(result.status);
        if (result.status === "failed") {
          loadFailure();
          return;
        }
        if (result.status === "completed") return;
      } catch (err) {
        if (signal.aborted) return;
        if (err instanceof ApiError && (err.status === 400 || err.status === 404)) {
          setError("Scan not found.");
          return;
        }
        consecutiveErrors += 1;
        if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
          setError(describeError(err));
          return;
        }
      }
      timer = setTimeout(poll, POLL_INTERVAL_MS);
    }

    getScan(scanId, signal)
      .then((scan) => {
        if (!signal.aborted) setProjectName(scan.project_name);
      })
      .catch(() => {});
    poll();

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [scanId]);

  if (!scanId) {
    return (
      <div>
        <div className="page-header">
          <div>
            <h1 className="page-title">Scan Progress</h1>
            <p className="page-subtitle">No scan in progress.</p>
          </div>
        </div>
        <div className="card empty-state">
          <p>Start a new scan to follow its progress here.</p>
          <Link className="btn btn-primary" to="/scan">
            Start a new scan
          </Link>
        </div>
      </div>
    );
  }

  const complete = status === "completed";
  const failed = status === "failed";
  // A failed scan keeps the pipeline at the last stage it reached.
  const stageIndex = STAGE_INDEX[stageStatus] ?? 0;
  const activeStage = scanStages[Math.min(stageIndex, scanStages.length - 1)];
  const percent = complete ? 100 : Math.round(((stageIndex + 1) / scanStages.length) * 86);

  let label = activeStage.message;
  if (complete) label = "Security report ready";
  else if (failed) label = "Scan failed";
  else if (error) label = "Unable to track scan";
  else if (!status) label = "Checking scan status...";

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Analyzing {projectName || "project"}</h1>
          <p className="page-subtitle">Running security checks and preparing AI recommendations...</p>
        </div>
      </div>

      <div className="grid-2">
        <section className="card card-pad">
          <ScanPipeline stages={scanStages} currentIndex={stageIndex} />
        </section>
        <section className="card card-pad stack">
          <ProgressIndicator value={percent} label={label} />
          <p className="muted">No uploaded source is executed.</p>
          {failed ? (
            <>
              <div className="notice" role="alert" style={{ color: "var(--high-fg)" }}>
                {failure || "The scan failed."}
              </div>
              <Link className="btn btn-primary" to="/scan">
                Start a new scan
              </Link>
            </>
          ) : error ? (
            <>
              <div className="notice" role="alert" style={{ color: "var(--high-fg)" }}>
                {error}
              </div>
              <Link className="btn btn-secondary" to="/history">
                Scan history
              </Link>
            </>
          ) : complete ? (
            <Link className="btn btn-primary" to={`/reports/${encodeURIComponent(scanId)}`}>
              View Security Report
            </Link>
          ) : (
            <button className="btn btn-secondary" type="button" disabled>
              Generating report...
            </button>
          )}
        </section>
      </div>
    </div>
  );
}
