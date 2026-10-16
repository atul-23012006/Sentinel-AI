import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth.jsx";
import { CheckIcon, ShieldIcon } from "../components/Icons.jsx";

const ROLES = ["Finance Employee", "HR Employee", "Administrator"];
const CLEARANCES = ["PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"];

const FEATURES = [
  ["Hybrid policy engine", "RBAC, MAC, ABAC, TBAC and OBAC evaluated on every request."],
  ["Behavioral risk scoring", "An Isolation Forest flags activity that doesn't look like you."],
  ["Adaptive step-up", "Suspicious sessions are asked to re-verify before going further."],
  ["Admin-approved access", "New accounts stay pending until an administrator signs off."],
];

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState("login");
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [registerForm, setRegisterForm] = useState({
    username: "",
    email: "",
    password: "",
    role: ROLES[0],
    department: "Finance",
    clearance_level: CLEARANCES[1],
  });

  function switchMode(next) {
    setMode(next);
    setError(null);
    setNotice(null);
  }

  async function handleLogin(e) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setSubmitting(true);
    try {
      await login(loginForm.username, loginForm.password);
      navigate("/dashboard");
    } catch (err) {
      setError(err.detail || "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const created = await api.register(registerForm);
      if (created.account_status === "PENDING") {
        setLoginForm({ username: registerForm.username, password: "" });
        setMode("login");
        setNotice("Account created. An administrator has been notified and needs to approve it before you can sign in.");
        return;
      }
      await login(registerForm.username, registerForm.password);
      navigate("/dashboard");
    } catch (err) {
      setError(err.detail || "Registration failed");
    } finally {
      setSubmitting(false);
    }
  }

  const setReg = (key) => (e) => setRegisterForm({ ...registerForm, [key]: e.target.value });

  return (
    <div className="login-shell">
      <section className="login-hero">
        <div className="brand" style={{ padding: 0 }}>
          <div className="brand-mark">
            <ShieldIcon size={18} />
          </div>
          <div className="brand-name">SentinelAI</div>
        </div>

        <div>
          <h1>Access control that notices when something's off.</h1>
          <p className="lede">
            Being authorized isn't the same as behaving safely. SentinelAI checks both, on every request.
          </p>
          <ul className="feature-list">
            {FEATURES.map(([title, body]) => (
              <li key={title}>
                <span className="tick">
                  <CheckIcon size={14} />
                </span>
                <span>
                  <strong>{title}</strong>
                  <span className="dim">{body}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>

        <p className="muted" style={{ margin: 0 }}>
          CBS3002 Information Security
        </p>
      </section>

      <section className="login-panel">
        <div className="login-card">
          <h2>{mode === "login" ? "Welcome back" : "Create your account"}</h2>
          <p className="tagline">
            {mode === "login" ? "Sign in to the security console." : "New accounts are reviewed by an administrator."}
          </p>

          <div className="segmented">
            <button type="button" className={mode === "login" ? "on" : ""} onClick={() => switchMode("login")}>
              Sign in
            </button>
            <button type="button" className={mode === "register" ? "on" : ""} onClick={() => switchMode("register")}>
              Register
            </button>
          </div>

          {notice && <div className="notice notice-ok">{notice}</div>}
          {error && <div className="error-box">{error}</div>}

          {mode === "login" ? (
            <form onSubmit={handleLogin}>
              <div className="field">
                <label>Username</label>
                <input
                  autoFocus
                  value={loginForm.username}
                  onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
                  required
                />
              </div>
              <div className="field">
                <label>Password</label>
                <input
                  type="password"
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                  required
                />
              </div>
              <button className="primary" type="submit" disabled={submitting}>
                {submitting ? "Signing in…" : "Sign in"}
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister}>
              <div className="form-row">
                <div className="field">
                  <label>Username</label>
                  <input value={registerForm.username} onChange={setReg("username")} required />
                </div>
                <div className="field">
                  <label>Department</label>
                  <input value={registerForm.department} onChange={setReg("department")} required />
                </div>
              </div>
              <div className="field">
                <label>Email</label>
                <input type="email" value={registerForm.email} onChange={setReg("email")} required />
              </div>
              <div className="field">
                <label>Password</label>
                <input
                  type="password"
                  minLength={8}
                  placeholder="At least 8 characters"
                  value={registerForm.password}
                  onChange={setReg("password")}
                  required
                />
              </div>
              <div className="form-row">
                <div className="field">
                  <label>Role</label>
                  <select value={registerForm.role} onChange={setReg("role")}>
                    {ROLES.map((r) => (
                      <option key={r}>{r}</option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label>Clearance</label>
                  <select value={registerForm.clearance_level} onChange={setReg("clearance_level")}>
                    {CLEARANCES.map((c) => (
                      <option key={c}>{c}</option>
                    ))}
                  </select>
                </div>
              </div>
              <button className="primary" type="submit" disabled={submitting}>
                {submitting ? "Creating account…" : "Create account"}
              </button>
            </form>
          )}
        </div>
      </section>
    </div>
  );
}
