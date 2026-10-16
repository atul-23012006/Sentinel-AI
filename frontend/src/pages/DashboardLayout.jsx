import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth.jsx";
import { BellIcon, GridIcon, KeyIcon, ListIcon, LogoutIcon, ShieldIcon, UsersIcon } from "../components/Icons.jsx";

export default function DashboardLayout() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [pendingCount, setPendingCount] = useState(0);

  useEffect(() => {
    if (!isAdmin) return;
    api
      .listUsers({ account_status: "PENDING" })
      .then((users) => setPendingCount(users.length))
      .catch(() => {});
  }, [isAdmin, location.pathname]);

  function handleLogout() {
    logout();
    navigate("/login");
  }

  const initials = (user?.username || "?").slice(0, 2).toUpperCase();

  return (
    <div className="app-shell">
      <nav className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldIcon size={18} />
          </div>
          <div>
            <div className="brand-name">SentinelAI</div>
            <div className="brand-sub">Security Console</div>
          </div>
        </div>

        <div className="nav-section">Monitor</div>
        <NavLink to="/dashboard/overview">
          <GridIcon /> Overview
        </NavLink>
        <NavLink to="/dashboard/resources">
          <KeyIcon /> Resources &amp; Access
        </NavLink>
        <NavLink to="/dashboard/alerts">
          <BellIcon /> Security Alerts
        </NavLink>
        <NavLink to="/dashboard/audit">
          <ListIcon /> Audit Log
        </NavLink>

        {isAdmin && (
          <>
            <div className="nav-section">Manage</div>
            <NavLink to="/dashboard/admin">
              <UsersIcon /> Users
              {pendingCount > 0 && <span className="nav-count">{pendingCount}</span>}
            </NavLink>
          </>
        )}

        <div className="who">
          <div className="who-row">
            <div className="avatar">{initials}</div>
            <div style={{ minWidth: 0 }}>
              <div className="who-name">{user?.username}</div>
              <div className="who-meta">
                {user?.role} · {user?.department}
              </div>
            </div>
          </div>
          <button className="navlink" onClick={handleLogout}>
            <LogoutIcon /> Sign out
          </button>
        </div>
      </nav>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
