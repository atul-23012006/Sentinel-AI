import { useEffect, useState } from "react";
import { DecisionBadge, RiskMeter } from "../components/Badges.jsx";
import { api } from "../api";
import { useAuth } from "../auth.jsx";

const CLASSIFICATIONS = ["PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"];

export default function ResourcesTab() {
  const { isAdmin } = useAuth();
  const [resources, setResources] = useState([]);
  const [error, setError] = useState(null);
  const [activeResourceId, setActiveResourceId] = useState(null);

  const [newResource, setNewResource] = useState({
    resource_name: "",
    classification: "CONFIDENTIAL",
    department: "Finance",
    required_role: "",
  });

  function refresh() {
    api.listResources().then(setResources).catch((err) => setError(err.detail));
  }

  useEffect(refresh, []);

  async function handleCreateResource(e) {
    e.preventDefault();
    setError(null);
    try {
      await api.createResource({
        ...newResource,
        required_role: newResource.required_role || null,
      });
      setNewResource({ resource_name: "", classification: "CONFIDENTIAL", department: "Finance", required_role: "" });
      refresh();
    } catch (err) {
      setError(err.detail || "Failed to create resource");
    }
  }

  return (
    <div>
      <h2>Resources &amp; Access Simulator</h2>
      {error && <div className="error-box">{error}</div>}

      {isAdmin && (
        <div className="card" style={{ marginBottom: 20 }}>
          <h3 style={{ marginTop: 0 }}>Register a resource</h3>
          <form className="inline" onSubmit={handleCreateResource}>
            <div className="field">
              <label>Name</label>
              <input
                value={newResource.resource_name}
                onChange={(e) => setNewResource({ ...newResource, resource_name: e.target.value })}
                required
              />
            </div>
            <div className="field">
              <label>Classification</label>
              <select
                value={newResource.classification}
                onChange={(e) => setNewResource({ ...newResource, classification: e.target.value })}
              >
                {CLASSIFICATIONS.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Department</label>
              <input
                value={newResource.department}
                onChange={(e) => setNewResource({ ...newResource, department: e.target.value })}
                required
              />
            </div>
            <div className="field">
              <label>Required role (optional)</label>
              <input
                value={newResource.required_role}
                onChange={(e) => setNewResource({ ...newResource, required_role: e.target.value })}
                placeholder="e.g. HR Employee"
              />
            </div>
            <button className="primary" type="submit">
              Create
            </button>
          </form>
        </div>
      )}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Resource</th>
              <th>Classification</th>
              <th>Department</th>
              <th>Required role</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {resources.map((r) => (
              <ResourceRow
                key={r.resource_id}
                resource={r}
                expanded={activeResourceId === r.resource_id}
                onToggle={() => setActiveResourceId(activeResourceId === r.resource_id ? null : r.resource_id)}
                onChanged={refresh}
              />
            ))}
          </tbody>
        </table>
        {resources.length === 0 && <p className="muted">No resources yet.</p>}
      </div>
    </div>
  );
}

function ResourceRow({ resource, expanded, onToggle, onChanged }) {
  const { isAdmin } = useAuth();
  const [editing, setEditing] = useState(false);

  async function handleDelete() {
    await api.deleteResource(resource.resource_id);
    onChanged();
  }

  if (editing) {
    return (
      <ResourceEditRow
        resource={resource}
        onCancel={() => setEditing(false)}
        onSaved={() => {
          setEditing(false);
          onChanged();
        }}
      />
    );
  }

  return (
    <>
      <tr>
        <td>{resource.resource_name}</td>
        <td>{resource.classification}</td>
        <td>{resource.department}</td>
        <td>{resource.required_role || <span className="muted">none</span>}</td>
        <td style={{ display: "flex", gap: 6 }}>
          <button className="secondary" onClick={onToggle}>
            {expanded ? "Close" : "Request access"}
          </button>
          {isAdmin && (
            <>
              <button className="secondary" onClick={() => setEditing(true)}>
                Edit
              </button>
              <button className="danger" onClick={handleDelete}>
                Delete
              </button>
            </>
          )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5}>
            <AccessPanel resource={resource} />
            <OperationRulesPanel resource={resource} />
            <GrantsPanel resource={resource} />
          </td>
        </tr>
      )}
    </>
  );
}

function ResourceEditRow({ resource, onCancel, onSaved }) {
  const [form, setForm] = useState({
    resource_name: resource.resource_name,
    classification: resource.classification,
    department: resource.department,
    required_role: resource.required_role || "",
  });
  const [error, setError] = useState(null);

  async function handleSave() {
    setError(null);
    try {
      await api.updateResource(resource.resource_id, {
        resource_name: form.resource_name,
        classification: form.classification,
        department: form.department,
        required_role: form.required_role || null,
        clear_required_role: form.required_role === "",
      });
      onSaved();
    } catch (err) {
      setError(err.detail || "Failed to update resource");
    }
  }

  return (
    <tr>
      <td colSpan={5}>
        {error && <div className="error-box">{error}</div>}
        <form className="inline" onSubmit={(e) => e.preventDefault()}>
          <div className="field">
            <label>Name</label>
            <input value={form.resource_name} onChange={(e) => setForm({ ...form, resource_name: e.target.value })} />
          </div>
          <div className="field">
            <label>Classification</label>
            <select value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}>
              {CLASSIFICATIONS.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label>Department</label>
            <input value={form.department} onChange={(e) => setForm({ ...form, department: e.target.value })} />
          </div>
          <div className="field">
            <label>Required role (blank = none)</label>
            <input value={form.required_role} onChange={(e) => setForm({ ...form, required_role: e.target.value })} />
          </div>
          <button className="primary" onClick={handleSave}>
            Save
          </button>
          <button className="secondary" onClick={onCancel}>
            Cancel
          </button>
        </form>
      </td>
    </tr>
  );
}

function GrantsPanel({ resource }) {
  const { isAdmin } = useAuth();
  const [grants, setGrants] = useState([]);
  const [error, setError] = useState(null);
  const [newGrant, setNewGrant] = useState({ user_id: "", action: "", reason: "" });

  function refresh() {
    api
      .listGrants(resource.resource_id)
      .then(setGrants)
      .catch((err) => setError(err.detail));
  }

  useEffect(() => {
    if (isAdmin) refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin, resource.resource_id]);

  if (!isAdmin) return null;

  async function handleAdd(e) {
    e.preventDefault();
    setError(null);
    try {
      await api.createGrant(resource.resource_id, {
        user_id: Number(newGrant.user_id),
        action: newGrant.action || null,
        reason: newGrant.reason || null,
      });
      setNewGrant({ user_id: "", action: "", reason: "" });
      refresh();
    } catch (err) {
      setError(err.detail || "Failed to create grant");
    }
  }

  async function handleRevoke(grantId) {
    await api.deleteGrant(resource.resource_id, grantId);
    refresh();
  }

  return (
    <div className="card" style={{ marginTop: 12, background: "#0e1626" }}>
      <strong>Explicit access grants</strong>
      <p className="muted">
        Bypasses RBAC/MAC/ABAC/TBAC/OBAC for one specific user on this resource (e.g. a temporary exception) - it
        does NOT bypass the risk engine, so a granted user acting suspiciously can still be challenged or blocked.
        Leave action blank to cover every action.
      </p>
      {error && <div className="error-box">{error}</div>}

      {grants.length > 0 && (
        <table style={{ marginBottom: 12 }}>
          <thead>
            <tr>
              <th>User ID</th>
              <th>Action</th>
              <th>Reason</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.grant_id}>
                <td>{g.user_id}</td>
                <td>{g.action || <span className="muted">all</span>}</td>
                <td className="muted">{g.reason || "-"}</td>
                <td className="muted">{g.expires_at ? new Date(g.expires_at).toLocaleString() : "never"}</td>
                <td>
                  <button className="danger" onClick={() => handleRevoke(g.grant_id)}>
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <form className="inline" onSubmit={handleAdd}>
        <div className="field">
          <label>User ID</label>
          <input
            type="number"
            value={newGrant.user_id}
            onChange={(e) => setNewGrant({ ...newGrant, user_id: e.target.value })}
            required
          />
        </div>
        <div className="field">
          <label>Action (blank = all)</label>
          <select value={newGrant.action} onChange={(e) => setNewGrant({ ...newGrant, action: e.target.value })}>
            <option value="">All actions</option>
            {ACTIONS.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Reason</label>
          <input
            value={newGrant.reason}
            onChange={(e) => setNewGrant({ ...newGrant, reason: e.target.value })}
            placeholder="e.g. approved by CISO"
          />
        </div>
        <button className="secondary" type="submit">
          Grant access
        </button>
      </form>
    </div>
  );
}

const ACTIONS = ["READ", "DOWNLOAD", "WRITE", "DELETE"];

function OperationRulesPanel({ resource }) {
  const { isAdmin } = useAuth();
  const [rules, setRules] = useState([]);
  const [error, setError] = useState(null);
  const [newRule, setNewRule] = useState({ action: "DELETE", required_role: "Administrator" });

  function refresh() {
    api
      .listPolicies({ policy_type: "OBAC" })
      .then((all) => setRules(all.filter((p) => p.rule_definition?.resource_id === resource.resource_id)))
      .catch((err) => setError(err.detail));
  }

  useEffect(() => {
    if (isAdmin) refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAdmin, resource.resource_id]);

  if (!isAdmin) return null;

  async function handleAdd(e) {
    e.preventDefault();
    setError(null);
    try {
      await api.createPolicy({
        policy_type: "OBAC",
        policy_name: `${newRule.action} requires ${newRule.required_role}`,
        rule_definition: {
          resource_id: resource.resource_id,
          action: newRule.action,
          required_role: newRule.required_role,
        },
      });
      refresh();
    } catch (err) {
      setError(err.detail || "Failed to create rule");
    }
  }

  async function handleDelete(policyId) {
    await api.deletePolicy(policyId);
    refresh();
  }

  return (
    <div className="card" style={{ marginTop: 12, background: "#0e1626" }}>
      <strong>Operation-specific rules (OBAC)</strong>
      <p className="muted">
        Same resource, different rules per action - e.g. everyone in-department can READ, but only an
        Administrator can DELETE. No rule for an action means it falls back to RBAC/MAC/ABAC/TBAC only.
      </p>
      {error && <div className="error-box">{error}</div>}

      {rules.length > 0 && (
        <table style={{ marginBottom: 12 }}>
          <thead>
            <tr>
              <th>Action</th>
              <th>Required role</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.policy_id}>
                <td>{r.rule_definition.action}</td>
                <td>{r.rule_definition.required_role || <span className="muted">-</span>}</td>
                <td>
                  <button className="danger" onClick={() => handleDelete(r.policy_id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <form className="inline" onSubmit={handleAdd}>
        <div className="field">
          <label>Action</label>
          <select value={newRule.action} onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}>
            {ACTIONS.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Required role</label>
          <input
            value={newRule.required_role}
            onChange={(e) => setNewRule({ ...newRule, required_role: e.target.value })}
            placeholder="e.g. Administrator"
            required
          />
        </div>
        <button className="secondary" type="submit">
          Add rule
        </button>
      </form>
    </div>
  );
}

function AccessPanel({ resource }) {
  const [action, setAction] = useState("READ");
  const [deviceId, setDeviceId] = useState("");
  const [location, setLocation] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const [otpSecret, setOtpSecret] = useState(null);
  const [code, setCode] = useState("");
  const [mfaMessage, setMfaMessage] = useState(null);
  const [emailCode, setEmailCode] = useState("");
  const [emailMessage, setEmailMessage] = useState(null);

  async function handleRequest(e) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setResult(null);
    setMfaMessage(null);
    setEmailMessage(null);
    try {
      const response = await api.requestAccess(resource.resource_id, {
        action,
        device_id: deviceId || null,
        location: location || null,
      });
      setResult(response);
    } catch (err) {
      setError(err.detail || "Access request failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleMfaSetup() {
    const setup = await api.mfaSetup();
    setOtpSecret(setup.otp_secret);
  }

  async function handleMfaVerify(e) {
    e.preventDefault();
    setMfaMessage(null);
    try {
      await api.mfaVerify(result.event_id, code);
      setMfaMessage({ ok: true, text: "MFA verified - access upgraded to ALLOW." });
    } catch (err) {
      setMfaMessage({ ok: false, text: err.detail || "Verification failed" });
    }
  }

  async function handleEmailVerify(e) {
    e.preventDefault();
    setEmailMessage(null);
    try {
      await api.emailVerify(result.event_id, emailCode);
      setEmailMessage({ ok: true, text: "Email code verified - access upgraded to ALLOW." });
    } catch (err) {
      setEmailMessage({ ok: false, text: err.detail || "Verification failed" });
    }
  }

  return (
    <div className="card" style={{ background: "#0e1626" }}>
      <form className="inline" onSubmit={handleRequest}>
        <div className="field">
          <label>Action</label>
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option>READ</option>
            <option>DOWNLOAD</option>
            <option>WRITE</option>
            <option>DELETE</option>
          </select>
        </div>
        <div className="field">
          <label>Device ID (optional)</label>
          <input value={deviceId} onChange={(e) => setDeviceId(e.target.value)} placeholder="e.g. laptop-1" />
        </div>
        <div className="field">
          <label>Location (optional)</label>
          <input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="e.g. HQ" />
        </div>
        <button className="primary" type="submit" disabled={submitting}>
          {submitting ? "Evaluating..." : "Request access"}
        </button>
      </form>

      {error && <div className="error-box" style={{ marginTop: 12 }}>{error}</div>}

      {result && (
        <div style={{ marginTop: 16 }}>
          <div className="section-row">
            <strong>
              Decision: <DecisionBadge decision={result.final_decision} />
            </strong>
            <span>
              Risk score: <RiskMeter score={result.risk_score} />
            </span>
          </div>

          <table>
            <thead>
              <tr>
                <th>Policy</th>
                <th>Result</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {result.policy_results.map((p) => (
                <tr key={p.policy_type}>
                  <td>{p.policy_type}</td>
                  <td>{p.decision}</td>
                  <td className="muted">{p.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {result.risk_reasons?.length > 0 && (
            <ul className="reasons-list">
              {result.risk_reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}

          {result.account_locked && (
            <div className="card" style={{ marginTop: 14, borderColor: "var(--critical)" }}>
              <strong style={{ color: "var(--critical)" }}>Account locked</strong>
              <p className="muted">
                Too many suspicious or blocked access attempts in a row. This account is now locked and can only be
                reactivated by an administrator (Users tab &rarr; set account status to ACTIVE).
              </p>
            </div>
          )}

          {result.final_decision === "EMAIL_VERIFICATION_REQUIRED" && (
            <div className="card" style={{ marginTop: 14 }}>
              <strong>Email verification required</strong>
              <p className="muted">
                This activity is authorized by policy but was flagged as behaviorally risky, and no authenticator
                app is set up for this account. A one-time code was emailed to your registered address.
              </p>
              {result.email_verification_hint && <p className="muted">{result.email_verification_hint}</p>}
              <form className="inline" onSubmit={handleEmailVerify}>
                <div className="field">
                  <label>6-digit code</label>
                  <input value={emailCode} onChange={(e) => setEmailCode(e.target.value)} maxLength={6} required />
                </div>
                <button className="primary" type="submit">
                  Verify
                </button>
              </form>
              {emailMessage && (
                <p style={{ color: emailMessage.ok ? "var(--ok)" : "var(--critical)" }}>{emailMessage.text}</p>
              )}
            </div>
          )}

          {result.final_decision === "MFA_REQUIRED" && (
            <div className="card" style={{ marginTop: 14 }}>
              <strong>Step-up authentication required</strong>
              <p className="muted">
                This activity is authorized by policy but was flagged as behaviorally risky. Verify with a
                time-based one-time code to proceed.
              </p>
              {!otpSecret ? (
                <button className="secondary" onClick={handleMfaSetup}>
                  Set up MFA
                </button>
              ) : (
                <>
                  <p className="muted">
                    Secret: <code>{otpSecret}</code> (pair this with an authenticator app, or compute the current
                    code from it for this demo).
                  </p>
                  <form className="inline" onSubmit={handleMfaVerify}>
                    <div className="field">
                      <label>6-digit code</label>
                      <input value={code} onChange={(e) => setCode(e.target.value)} maxLength={6} required />
                    </div>
                    <button className="primary" type="submit">
                      Verify
                    </button>
                  </form>
                </>
              )}
              {mfaMessage && (
                <p style={{ color: mfaMessage.ok ? "var(--ok)" : "var(--critical)" }}>{mfaMessage.text}</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
