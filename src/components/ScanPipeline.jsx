import Icon from "./Icon";

export default function ScanPipeline({ stages, currentIndex }) {
  return (
    <div className="pipeline">
      {stages.map((stage, index) => {
        const done = index < currentIndex;
        const active = index === currentIndex;
        const state = done ? "done" : active ? "active" : "";
        return (
          <div className="pipeline-step" key={stage.id}>
            <div className="rail">
              <div className={`step-dot ${state}`}>
                {done ? <Icon name="check" /> : index + 1}
              </div>
              {index < stages.length - 1 ? <div className="rail-line" /> : null}
            </div>
            <div className="step-body">
              <div style={{ fontWeight: 600 }}>
                {done ? `${stage.title} ✓` : stage.title}
              </div>
              <div className="muted">
                {done ? "Complete" : active ? stage.message : "Waiting"}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
