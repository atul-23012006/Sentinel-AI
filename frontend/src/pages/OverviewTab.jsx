import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth.jsx";
import { RiskMeter, SeverityBadge } from "../components/Badges.jsx";

export default function OverviewTab() {
  const { user, isAdmin } = useAuth();
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!isAdmin) return;
    Promise.all([api.auditSummary(), api.listAlerts({ status: "OPEN", limit: 6 })])
      .then(([s, a]) => {
        setSummary(s);
        setAlerts(a);
      })
      .catch((err) => setError(err.detail || "Failed to load summary"));
  }, [isAdmin]);

  if (!isAdmin) {
    return (
      <div>
        <div className="page-header">
          <h2>Hi, {user?.username}</h2>
          <p>Here's how access works for your account.</p>
        </div>
        <div className="card-grid">
          <InfoCard label="Role" value={user?.role} />
          <InfoCard label="Department" value={user?.department} />
          <InfoCard label="Clearance" value={user?.clearance_level} />
          <InfoCard label="Device" value={user?.device_trust} />
        </div>
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Requesting access</h3>
          <p className="muted" style={{ fontSize: 13.5, marginBottom: 16 }}>
            Every request is evaluated by the hybrid policy engine (RBAC + MAC + ABAC + TBAC + OBAC) and scored by the
            behavioral risk engine. Unusual activity may ask you to re-verify with a one-time code.
          </p>
          <Link to="/dashboard/resources">
            <button className="primary">Browse resources</button>
          </Link>
        </div>
      </div>
    );
  }

  if (error) return <div className="error-box">{error}</div>;
  if (!summary) return <p className="muted">Loading…</p>;

  return (
    <div>
      <div className="page-header">
        <h2>Security overview</h2>
        <p>Access decisions and open incidents across the organisation.</p>
      </div>

      {summary.pending_users_count > 0 && (
        <div className="notice notice-warn">
          <strong>{summary.pending_users_count}</strong>
          new account{summary.pending_users_count === 1 ? "" : "s"} awaiting approval —
          <Link to="/dashboard/admin">review now</Link>
        </div>
      )}

      <div className="card-grid">
        <Stat label="Total events" value={summary.total_events} color="#a8a29e" />
        <Stat label="Last 24 hours" value={summary.events_last_24h} color="#6366f1" />
        <Stat label="Allowed" value={summary.allow_count} color="var(--ok)" />
        <Stat label="Denied" value={summary.deny_count} color="var(--critical)" />
        <Stat
          label="Step-up required"
          value={summary.mfa_required_count + summary.email_verification_count}
          color="var(--warn)"
        />
        <Stat label="Blocked" value={summary.block_count} color="var(--high)" />
      </div>

      <div className="section-row">
        <h3 style={{ margin: 0 }}>Open alerts</h3>
        <Link to="/dashboard/alerts" className="muted">
          View all {summary.open_alerts_count} →
        </Link>
      </div>
      <div className="card">
        {alerts.length === 0 ? (
          <div className="empty">No open alerts — all quiet.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Alert</th>
                <th>Risk</th>
                <th>Severity</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.alert_id}>
                  <td>
                    <span className="muted">#{a.alert_id}</span>&nbsp; {a.alert_type.replaceAll("_", " ").toLowerCase()}
                  </td>
                  <td>
                    <RiskMeter score={a.risk_score} />
                  </td>
                  <td>
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="muted">{new Date(a.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div className="card stat-card">
      <div className="stat-label">
        <span className="stat-dot" style={{ background: color }} />
        {label}
      </div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

function InfoCard({ label, value }) {
  return (
    <div className="card stat-card">
      <div className="stat-label">{label}</div>
      <div style={{ fontSize: 16, fontWeight: 600, marginTop: 8 }}>{value || "—"}</div>
    </div>
  );
}
