import { useEffect, useState } from "react";
import { RiskMeter, SeverityBadge, StatusBadge } from "../components/Badges.jsx";
import { api } from "../api";

export default function AlertsTab() {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [explainModal, setExplainModal] = useState(null); // { alert, loading, explanation, source }

  function refresh() {
    api
      .listAlerts({ status: statusFilter || undefined, limit: 100 })
      .then(setAlerts)
      .catch((err) => setError(err.detail || "Failed to load alerts"));
  }

  useEffect(refresh, [statusFilter]);

  async function updateStatus(alertId, status) {
    await api.updateAlert(alertId, status);
    refresh();
  }

  async function openExplain(alert) {
    setExplainModal({ alert, loading: true, explanation: null, source: null });
    try {
      const res = await api.explainAlert(alert.alert_id);
      setExplainModal({ alert, loading: false, explanation: res.explanation, source: res.source });
    } catch (err) {
      setExplainModal({ alert, loading: false, explanation: err.detail || "Failed to generate explanation", source: null });
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2>Security alerts</h2>
        <p>
          Raised automatically when behavioral risk crosses a threshold. "Explain" asks the AI analyst for a
          plain-language summary — advisory only, it never changes an access decision.
        </p>
      </div>
      {error && <div className="error-box">{error}</div>}

      <div className="field" style={{ marginBottom: 14, maxWidth: 220 }}>
        <label>Status</label>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">All</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="RESOLVED">Resolved</option>
        </select>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Alert</th>
              <th>Risk</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.alert_id}>
                <td>
                  #{a.alert_id} <span className="muted">{a.alert_type}</span>
                  <div className="muted" style={{ maxWidth: 320 }}>{a.description}</div>
                </td>
                <td>
                  <RiskMeter score={a.risk_score} />
                </td>
                <td>
                  <SeverityBadge severity={a.severity} />
                </td>
                <td>
                  <StatusBadge status={a.status} />
                </td>
                <td>{new Date(a.created_at).toLocaleString()}</td>
                <td>
                  <div style={{ display: "flex", gap: 6 }}>
                    <button className="secondary" onClick={() => openExplain(a)}>
                      Explain
                    </button>
                    {a.status !== "ACKNOWLEDGED" && (
                      <button className="secondary" onClick={() => updateStatus(a.alert_id, "ACKNOWLEDGED")}>
                        Ack
                      </button>
                    )}
                    {a.status !== "RESOLVED" && (
                      <button className="danger" onClick={() => updateStatus(a.alert_id, "RESOLVED")}>
                        Resolve
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length === 0 && <p className="muted">No alerts.</p>}
      </div>

      {explainModal && (
        <div className="modal-backdrop" onClick={() => setExplainModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="section-row">
              <h3 style={{ margin: 0 }}>AI Security Analyst - Alert #{explainModal.alert.alert_id}</h3>
              <button className="secondary" onClick={() => setExplainModal(null)}>
                Close
              </button>
            </div>
            {explainModal.loading ? (
              <p className="muted">Generating explanation...</p>
            ) : (
              <>
                <p className="muted">Source: {explainModal.source || "unknown"}</p>
                <pre>{explainModal.explanation}</pre>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
