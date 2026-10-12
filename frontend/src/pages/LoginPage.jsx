import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth.jsx";

const ROLES = ["Finance Employee", "HR Employee", "Administrator"];
const CLEARANCES = ["PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"];

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState("login");
  const [error, setError] = useState(null);
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

  async function handleLogin(e) {
    e.preventDefault();
    setError(null);
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
      await api.register(registerForm);
      await login(registerForm.username, registerForm.password);
      navigate("/dashboard");
    } catch (err) {
      setError(err.detail || "Registration failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-shell">
      <div className="card login-card">
        <h1>SentinelAI</h1>
        <p className="tagline">Adaptive access control &amp; insider threat detection</p>

        {error && <div className="error-box">{error}</div>}

        {mode === "login" ? (
          <form onSubmit={handleLogin}>
            <div className="field">
              <label>Username</label>
              <input
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
              {submitting ? "Signing in..." : "Sign in"}
            </button>
          </form>
        ) : (
          <form onSubmit={handleRegister}>
            <div className="field">
              <label>Username</label>
              <input
                value={registerForm.username}
                onChange={(e) => setRegisterForm({ ...registerForm, username: e.target.value })}
                required
              />
            </div>
            <div className="field">
              <label>Email</label>
              <input
                type="email"
                value={registerForm.email}
                onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })}
                required
              />
            </div>
            <div className="field">
              <label>Password (min 8 chars)</label>
              <input
                type="password"
                minLength={8}
                value={registerForm.password}
                onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                required
              />
            </div>
            <div className="field">
              <label>Role</label>
              <select
                value={registerForm.role}
                onChange={(e) => setRegisterForm({ ...registerForm, role: e.target.value })}
              >
                {ROLES.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Department</label>
              <input
                value={registerForm.department}
                onChange={(e) => setRegisterForm({ ...registerForm, department: e.target.value })}
                required
              />
            </div>
            <div className="field">
              <label>Clearance level</label>
              <select
                value={registerForm.clearance_level}
                onChange={(e) => setRegisterForm({ ...registerForm, clearance_level: e.target.value })}
              >
                {CLEARANCES.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </div>
            <button className="primary" type="submit" disabled={submitting}>
              {submitting ? "Creating account..." : "Create account"}
            </button>
          </form>
        )}

        <div className="toggle-row">
          {mode === "login" ? (
            <span>
              No account? <button onClick={() => setMode("register")}>Register</button>
            </span>
          ) : (
            <span>
              Have an account? <button onClick={() => setMode("login")}>Sign in</button>
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
