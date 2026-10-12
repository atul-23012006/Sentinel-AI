import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../auth.jsx";

export default function DashboardLayout() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login");
  }

  return (
    <div className="app-shell">
      <nav className="sidebar">
        <h1>SentinelAI</h1>
        <p className="tagline">Security Console</p>
        <NavLink to="/dashboard/overview">Overview</NavLink>
        <NavLink to="/dashboard/resources">Resources &amp; Access</NavLink>
        <NavLink to="/dashboard/alerts">Security Alerts</NavLink>
        <NavLink to="/dashboard/audit">Audit Log</NavLink>
        {isAdmin && <NavLink to="/dashboard/admin">User Administration</NavLink>}

        <div className="who">
          <div>
            <strong>{user?.username}</strong>
          </div>
          <div>
            {user?.role} · {user?.department}
          </div>
          <button className="navlink" style={{ marginTop: 10 }} onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
