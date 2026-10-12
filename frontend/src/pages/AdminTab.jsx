import { useEffect, useState } from "react";
import { api } from "../api";

const CLEARANCES = ["PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"];

export default function AdminTab() {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState(null);
  const [editingId, setEditingId] = useState(null);

  function refresh() {
    api.listUsers().then(setUsers).catch((err) => setError(err.detail || "Failed to load users"));
  }

  useEffect(refresh, []);

  async function toggleDeviceTrust(user) {
    const next = user.device_trust === "TRUSTED" ? "UNTRUSTED" : "TRUSTED";
    await api.updateUser(user.user_id, { device_trust: next });
    refresh();
  }

  async function reactivate(user) {
    await api.updateUser(user.user_id, { account_status: "ACTIVE" });
    refresh();
  }

  async function saveEdit(userId, payload) {
    await api.updateUser(userId, payload);
    setEditingId(null);
    refresh();
  }

  return (
    <div>
      <h2>User Administration</h2>
      <p className="muted">
        Device trust (ABAC), account reactivation after lockout, and a user's role/department/clearance are all
        security decisions (README §4.1/§4.2) - otherwise self-declared at registration with no approval step - so
        they're admin-only here.
      </p>
      {error && <div className="error-box">{error}</div>}

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>User</th>
              <th>Role</th>
              <th>Department</th>
              <th>Clearance</th>
              <th>Device trust</th>
              <th>Account status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) =>
              editingId === u.user_id ? (
                <EditRow key={u.user_id} user={u} onCancel={() => setEditingId(null)} onSave={saveEdit} />
              ) : (
                <tr key={u.user_id}>
                  <td>{u.username}</td>
                  <td>{u.role}</td>
                  <td>{u.department}</td>
                  <td>{u.clearance_level}</td>
                  <td>{u.device_trust}</td>
                  <td>{u.account_status}</td>
                  <td style={{ display: "flex", gap: 6 }}>
                    <button className="secondary" onClick={() => setEditingId(u.user_id)}>
                      Edit
                    </button>
                    <button className="secondary" onClick={() => toggleDeviceTrust(u)}>
                      {u.device_trust === "TRUSTED" ? "Untrust device" : "Trust device"}
                    </button>
                    {u.account_status === "LOCKED" && (
                      <button className="primary" onClick={() => reactivate(u)}>
                        Reactivate
                      </button>
                    )}
                  </td>
                </tr>
              )
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EditRow({ user, onCancel, onSave }) {
  const [role, setRole] = useState(user.role);
  const [department, setDepartment] = useState(user.department);
  const [clearance, setClearance] = useState(user.clearance_level);

  return (
    <tr>
      <td>{user.username}</td>
      <td>
        <input value={role} onChange={(e) => setRole(e.target.value)} />
      </td>
      <td>
        <input value={department} onChange={(e) => setDepartment(e.target.value)} />
      </td>
      <td>
        <select value={clearance} onChange={(e) => setClearance(e.target.value)}>
          {CLEARANCES.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
      </td>
      <td colSpan={2} className="muted">
        device trust / status unchanged here
      </td>
      <td style={{ display: "flex", gap: 6 }}>
        <button
          className="primary"
          onClick={() => onSave(user.user_id, { role, department, clearance_level: clearance })}
        >
          Save
        </button>
        <button className="secondary" onClick={onCancel}>
          Cancel
        </button>
      </td>
    </tr>
  );
}
