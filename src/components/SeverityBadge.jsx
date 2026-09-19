export default function SeverityBadge({ severity, status }) {
  const value = (status || severity || "").toLowerCase();
  const label = status || severity;
  return (
    <span className={`badge ${value}`}>
      <span className="dot" />
      {label}
    </span>
  );
}
