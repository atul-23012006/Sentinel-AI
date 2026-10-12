import { Navigate, BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import DashboardLayout from "./pages/DashboardLayout.jsx";
import OverviewTab from "./pages/OverviewTab.jsx";
import ResourcesTab from "./pages/ResourcesTab.jsx";
import AuditTab from "./pages/AuditTab.jsx";
import AlertsTab from "./pages/AlertsTab.jsx";
import AdminTab from "./pages/AdminTab.jsx";

function RequireAuth({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <p style={{ padding: 24 }}>Loading...</p>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function RequireAdmin({ children }) {
  const { isAdmin } = useAuth();
  if (!isAdmin) return <Navigate to="/dashboard/overview" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/dashboard"
            element={
              <RequireAuth>
                <DashboardLayout />
              </RequireAuth>
            }
          >
            <Route index element={<Navigate to="overview" replace />} />
            <Route path="overview" element={<OverviewTab />} />
            <Route path="resources" element={<ResourcesTab />} />
            <Route path="alerts" element={<AlertsTab />} />
            <Route path="audit" element={<AuditTab />} />
            <Route
              path="admin"
              element={
                <RequireAdmin>
                  <AdminTab />
                </RequireAdmin>
              }
            />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
