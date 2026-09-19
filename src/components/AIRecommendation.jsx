import Icon from "./Icon";

export default function AIRecommendation({ finding }) {
  return (
    <section className="card card-pad">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
        <h2 className="section-title" style={{ margin: 0 }}>
          AI Security Recommendation
        </h2>
        <span className="badge info">AI-assisted remediation</span>
      </div>
      <div className="ai-flow">
        <div className="ai-step">
          <h3>Scanner Finding</h3>
          <p style={{ margin: 0 }}>{finding.scanner}</p>
          <p className="dim" style={{ margin: "8px 0 0" }}>
            {finding.cwe} · {finding.type}
          </p>
        </div>
        <div className="ai-arrow">↓ Relevant Code Context</div>
        <div className="ai-step">
          <h3>Relevant Code Context</h3>
          <p className="path" style={{ margin: 0 }}>
            {finding.file} : Line {finding.line}
          </p>
        </div>
        <div className="ai-arrow">↓ AI Analysis</div>
        <div className="ai-step">
          <h3>AI Analysis</h3>
          <p style={{ margin: 0 }}>{finding.explanation}</p>
        </div>
        <div className="ai-arrow">↓ Secure Recommendation</div>
        <div className="ai-step">
          <h3>Secure Recommendation</h3>
          <p style={{ margin: 0 }}>{finding.recommendation}</p>
        </div>
        <div className="ai-arrow">↓ Corrected Code</div>
        <div className="ai-step">
          <h3>Corrected Code</h3>
          <p className="muted" style={{ margin: 0 }}>
            Replace string concatenation and untrusted interpolation with a parameterized, validated implementation. The suggested fix is shown in the code viewer.
          </p>
        </div>
      </div>
      <div className="row muted" style={{ marginTop: 12 }}>
        <Icon name="psychology" />
        Structured finding — not a chat transcript.
      </div>
    </section>
  );
}
