import { useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../auth.jsx";

export default function OverviewTab() {
  const { isAdmin } = useAuth();
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!isAdmin) return;
    Promise.all([api.auditSummary(), api.listAlerts({ status: "OPEN", limit: 5 })])
      .then(([s, a]) => {
        setSummary(s);
        setAlerts(a);
      })
      .catch((err) => setError(err.detail || "Failed to load summary"));
  }, [isAdmin]);

  if (!isAdmin) {
    return (
      <div className="card">
        <p>
          Welcome. Use <strong>Resources &amp; Access</strong> to request access to a resource - every request is
          evaluated by the hybrid policy engine (RBAC + MAC + ABAC + TBAC) and scored by the behavioral risk engine.
        </p>
      </div>
    );
  }

  if (error) return <div className="error-box">{error}</div>;
  if (!summary) return <p className="muted">Loading...</p>;

  return (
    <div>
      <h2>Security Overview</h2>
      <div className="card-grid">
        <Stat label="Total events" value={summary.total_events} />
        <Stat label="Allowed" value={summary.allow_count} />
        <Stat label="Denied" value={summary.deny_count} />
        <Stat label="MFA required" value={summary.mfa_required_count} />
        <Stat label="Blocked" value={summary.block_count} />
        <Stat label="Events (24h)" value={summary.events_last_24h} />
      </div>

      <div className="section-row">
        <h3 style={{ margin: 0 }}>Open security alerts</h3>
      </div>
      <div className="card">
        {alerts.length === 0 ? (
          <p className="muted">No open alerts.</p>
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
                  <td>#{a.alert_id} {a.alert_type}</td>
                  <td>{a.risk_score}</td>
                  <td>{a.severity}</td>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="card stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}
