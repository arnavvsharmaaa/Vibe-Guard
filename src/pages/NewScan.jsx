import { useState } from "react";
import { useNavigate } from "react-router-dom";
import UploadZone from "../components/UploadZone";
import { mockUpload } from "../data/mockData";

export default function NewScan() {
  const navigate = useNavigate();
  const [file, setFile] = useState(null);
  const [projectName, setProjectName] = useState("AI-Web-App");
  const [securityRules, setSecurityRules] = useState(true);
  const [aiAnalysis, setAiAnalysis] = useState(true);

  function startScan() {
    if (!file) setFile(mockUpload);
    navigate("/scan/progress", { state: { projectName: projectName || "AI-Web-App" } });
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Start a Security Scan</h1>
          <p className="page-subtitle">
            Upload your source code and identify security vulnerabilities before deployment.
          </p>
        </div>
      </div>

      <div className="stack" style={{ maxWidth: 760 }}>
        <UploadZone file={file} onSelect={setFile} />

        <div>
          <label className="form-label" htmlFor="project-name">
            Project Name
          </label>
          <input
            id="project-name"
            className="input"
            value={projectName}
            onChange={(event) => setProjectName(event.target.value)}
          />
        </div>

        <div className="stack">
          <div className="option-row">
            <div>
              <div style={{ fontWeight: 600 }}>Security Rules</div>
              <div className="muted">Static checks for injection, secrets, and unsafe APIs.</div>
            </div>
            <button
              className={`toggle ${securityRules ? "" : "off"}`}
              type="button"
              aria-pressed={securityRules}
              onClick={() => setSecurityRules((value) => !value)}
            />
          </div>
          <div className="option-row">
            <div>
              <div style={{ fontWeight: 600 }}>AI Contextual Analysis</div>
              <div className="muted">Explain findings and generate secure replacements.</div>
            </div>
            <button
              className={`toggle ${aiAnalysis ? "" : "off"}`}
              type="button"
              aria-pressed={aiAnalysis}
              onClick={() => setAiAnalysis((value) => !value)}
            />
          </div>
        </div>

        <div className="notice">
          Your source code is analyzed statically and is not executed during scanning.
        </div>

        <div>
          <button className="btn btn-primary" type="button" onClick={startScan} disabled={!file && !projectName}>
            Start Security Scan
          </button>
        </div>
      </div>
    </div>
  );
}
