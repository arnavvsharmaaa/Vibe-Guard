import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import ScanPipeline from "../components/ScanPipeline";
import ProgressIndicator from "../components/ProgressIndicator";
import { primaryReport, scanStages } from "../data/mockData";

export default function ScanProgress() {
  const location = useLocation();
  const projectName = location.state?.projectName || "AI-Web-App";
  const [stageIndex, setStageIndex] = useState(0);
  const [complete, setComplete] = useState(false);

  useEffect(() => {
    if (complete) return undefined;
    const timer = setInterval(() => {
      setStageIndex((current) => {
        if (current >= scanStages.length - 1) {
          setComplete(true);
          return current;
        }
        return current + 1;
      });
    }, 900);
    return () => clearInterval(timer);
  }, [complete]);

  const percent = complete ? 100 : Math.round(((stageIndex + 1) / scanStages.length) * 86);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Analyzing {projectName}</h1>
          <p className="page-subtitle">Running security checks and preparing AI recommendations...</p>
        </div>
      </div>

      <div className="grid-2">
        <section className="card card-pad">
          <ScanPipeline stages={scanStages} currentIndex={complete ? scanStages.length : stageIndex} />
        </section>
        <section className="card card-pad stack">
          <ProgressIndicator
            value={percent}
            label={complete ? "Security report ready" : scanStages[stageIndex].message}
          />
          <p className="muted">
            Prototype scan uses centralized mock findings. No uploaded source is executed.
          </p>
          {complete ? (
            <Link className="btn btn-primary" to={`/reports/${primaryReport.id}`}>
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
