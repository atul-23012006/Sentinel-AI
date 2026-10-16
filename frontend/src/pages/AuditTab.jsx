import { useEffect, useState } from "react";
import { DecisionBadge, RiskMeter } from "../components/Badges.jsx";
import { api } from "../api";

export default function AuditTab() {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({ action: "", final_decision: "" });

  function refresh() {
    api
      .auditEvents({ action: filters.action || undefined, final_decision: filters.final_decision || undefined, limit: 100 })
      .then(setEvents)
      .catch((err) => setError(err.detail || "Failed to load audit events"));
  }

  useEffect(refresh, [filters]);

  return (
    <div>
      <div className="page-header">
        <h2>Audit log</h2>
        <p>Every login, access request and verification — passed or failed.</p>
      </div>
      {error && <div className="error-box">{error}</div>}

      <form className="inline" style={{ marginBottom: 16 }} onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label>Action</label>
          <select value={filters.action} onChange={(e) => setFilters({ ...filters, action: e.target.value })}>
            <option value="">All</option>
            <option value="LOGIN">LOGIN</option>
            <option value="READ">READ</option>
            <option value="DOWNLOAD">DOWNLOAD</option>
            <option value="WRITE">WRITE</option>
            <option value="DELETE">DELETE</option>
            <option value="MFA_VERIFY">MFA_VERIFY</option>
          </select>
        </div>
        <div className="field">
          <label>Decision</label>
          <select
            value={filters.final_decision}
            onChange={(e) => setFilters({ ...filters, final_decision: e.target.value })}
          >
            <option value="">All</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">DENY</option>
            <option value="MFA_REQUIRED">MFA_REQUIRED</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>
      </form>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>User</th>
              <th>Resource</th>
              <th>Action</th>
              <th>Decision</th>
              <th>Risk</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.event_id}>
                <td>{new Date(e.timestamp).toLocaleString()}</td>
                <td>{e.user_id ?? <span className="muted">unknown</span>}</td>
                <td>{e.resource_id ?? <span className="muted">-</span>}</td>
                <td>{e.action}</td>
                <td>
                  <DecisionBadge decision={e.final_decision} />
                </td>
                <td>
                  <RiskMeter score={e.risk_score} />
                </td>
                <td className="muted" style={{ maxWidth: 320 }}>
                  {e.reason}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {events.length === 0 && <p className="muted">No events match this filter.</p>}
      </div>
    </div>
  );
}
