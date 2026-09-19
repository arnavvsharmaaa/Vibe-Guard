import { useState } from "react";

function ToggleRow({ title, description, on, onToggle }) {
  return (
    <div className="option-row">
      <div>
        <div style={{ fontWeight: 600 }}>{title}</div>
        <div className="muted">{description}</div>
      </div>
      <button className={`toggle ${on ? "" : "off"}`} type="button" aria-pressed={on} onClick={onToggle} />
    </div>
  );
}

export default function Settings() {
  const [staticAnalysis, setStaticAnalysis] = useState(true);
  const [securityRules, setSecurityRules] = useState(true);
  const [aiAnalysis, setAiAnalysis] = useState(true);
  const [model] = useState("Demo AI Model");
  const [theme] = useState("Dark");

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">UI-only controls for the Review 1 prototype.</p>
        </div>
      </div>

      <div className="stack" style={{ maxWidth: 720 }}>
        <section className="card card-pad settings-section">
          <h2 className="section-title">Scanner Settings</h2>
          <div className="stack">
            <ToggleRow
              title="Static analysis enabled"
              description="Evaluate source patterns without executing uploaded code."
              on={staticAnalysis}
              onToggle={() => setStaticAnalysis((value) => !value)}
            />
            <ToggleRow
              title="Security rules enabled"
              description="Include injection, secret, and path-safety rules in mock scans."
              on={securityRules}
              onToggle={() => setSecurityRules((value) => !value)}
            />
          </div>
        </section>

        <section className="card card-pad settings-section">
          <h2 className="section-title">AI Analysis</h2>
          <div className="stack">
            <ToggleRow
              title="AI analysis enabled"
              description="Attach explanations, impact, and suggested secure code to findings."
              on={aiAnalysis}
              onToggle={() => setAiAnalysis((value) => !value)}
            />
            <div>
              <label className="form-label" htmlFor="model">
                Model
              </label>
              <select id="model" className="select" value={model} disabled>
                <option>{model}</option>
              </select>
            </div>
          </div>
        </section>

        <section className="card card-pad settings-section">
          <h2 className="section-title">Appearance</h2>
          <div>
            <label className="form-label" htmlFor="theme">
              Theme
            </label>
            <select id="theme" className="select" value={theme} disabled>
              <option>{theme}</option>
            </select>
          </div>
        </section>
      </div>
    </div>
  );
}
