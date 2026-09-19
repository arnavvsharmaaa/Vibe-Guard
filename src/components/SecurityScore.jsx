export default function SecurityScore({ score, size = 88, label = "Good" }) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const tone = score >= 85 ? "var(--pass-fg)" : score >= 70 ? "var(--accent-cyan)" : "var(--high-fg)";

  return (
    <div className="score-wrap">
      <svg className="score-ring" width={size} height={size} viewBox="0 0 88 88" aria-hidden="true">
        <circle cx="44" cy="44" r={radius} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          stroke={tone}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 44 44)"
        />
        <text x="44" y="48" textAnchor="middle" fill="var(--text-primary)" fontSize="18" fontWeight="700" fontFamily="Geist, sans-serif">
          {score}
        </text>
      </svg>
      <div>
        <div className="stat-label">Security Score</div>
        <div style={{ fontSize: 24, fontWeight: 600, letterSpacing: "-0.02em" }}>{score}/100</div>
        <div className="muted">{label}</div>
      </div>
    </div>
  );
}
