export function DecisionBadge({ decision }) {
  const cls = { ALLOW: "badge-allow", DENY: "badge-deny", MFA_REQUIRED: "badge-mfa", BLOCK: "badge-block" }[decision] || "";
  return <span className={`badge ${cls}`}>{decision}</span>;
}

export function SeverityBadge({ severity }) {
  return <span className={`badge badge-${severity.toLowerCase()}`}>{severity}</span>;
}

export function StatusBadge({ status }) {
  return <span className={`badge badge-${status.toLowerCase()}`}>{status}</span>;
}

export function RiskMeter({ score }) {
  if (score === null || score === undefined) return <span className="muted">n/a</span>;
  let color = "var(--ok)";
  if (score >= 81) color = "var(--critical)";
  else if (score >= 61) color = "var(--high)";
  else if (score >= 31) color = "var(--warn)";
  return (
    <span className="risk-meter" style={{ color }}>
      {score}/100
    </span>
  );
}
