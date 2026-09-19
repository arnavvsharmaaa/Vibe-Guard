export default function StatCard({ label, value, suffix, meta, tone }) {
  return (
    <article className="card card-pad">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={tone ? { color: tone } : undefined}>
        {value}
        {suffix ? (
          <span style={{ fontSize: 15, fontWeight: 500, color: "var(--text-tertiary)", marginLeft: 6 }}>
            {suffix}
          </span>
        ) : null}
      </div>
      {meta ? <div className="stat-meta">{meta}</div> : null}
    </article>
  );
}
