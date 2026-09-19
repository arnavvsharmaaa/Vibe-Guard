import { useState } from "react";
import CodeViewer from "./CodeViewer";

export default function CodeComparison({ finding }) {
  const [tab, setTab] = useState("vulnerable");
  const isFix = tab === "fix";

  return (
    <div>
      <div className="code-tabs" style={{ marginBottom: 8 }}>
        <button className={`code-tab ${!isFix ? "active" : ""}`} onClick={() => setTab("vulnerable")} type="button">
          Vulnerable Code
        </button>
        <button className={`code-tab ${isFix ? "active" : ""}`} onClick={() => setTab("fix")} type="button">
          Suggested Fix
        </button>
      </div>
      <CodeViewer
        filename={finding.file}
        code={isFix ? finding.fixedCode : finding.code}
        startLine={finding.startLine}
        highlightLines={isFix ? finding.fixedHighlightLines : finding.highlightLines}
        language={finding.language}
        mode={isFix ? "fixed" : "vulnerable"}
      />
    </div>
  );
}
