const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
    this.status = status;
    this.detail = detail;
  }
}

function getToken() {
  return localStorage.getItem("sentinelai_token");
}

export function setToken(token) {
  if (token) localStorage.setItem("sentinelai_token", token);
  else localStorage.removeItem("sentinelai_token");
}

async function request(path, { method = "GET", body, params, auth = true } = {}) {
  const url = new URL(BASE_URL + path);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
    });
  }

  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (response.status === 204) return null;

  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new ApiError(response.status, data?.detail || response.statusText);
  }
  return data;
}

export const api = {
  login: (username, password) => request("/auth/login", { method: "POST", body: { username, password }, auth: false }),
  register: (payload) => request("/auth/register", { method: "POST", body: payload, auth: false }),
  me: () => request("/auth/me"),
  mfaSetup: () => request("/auth/mfa/setup"),
  mfaVerify: (event_id, code) => request("/auth/mfa/verify", { method: "POST", body: { event_id, code } }),
  emailVerify: (event_id, code) => request("/auth/email-verify/verify", { method: "POST", body: { event_id, code } }),

  listUsers: (params) => request("/users", { params }),
  updateUser: (userId, payload) => request(`/users/${userId}`, { method: "PATCH", body: payload }),

  listResources: () => request("/resources"),
  createResource: (payload) => request("/resources", { method: "POST", body: payload }),
  updateResource: (resourceId, payload) => request(`/resources/${resourceId}`, { method: "PATCH", body: payload }),
  deleteResource: (resourceId) => request(`/resources/${resourceId}`, { method: "DELETE" }),
  requestAccess: (resourceId, payload) => request(`/resources/${resourceId}/access`, { method: "POST", body: payload }),

  listGrants: (resourceId) => request(`/resources/${resourceId}/grants`),
  createGrant: (resourceId, payload) => request(`/resources/${resourceId}/grants`, { method: "POST", body: payload }),
  deleteGrant: (resourceId, grantId) => request(`/resources/${resourceId}/grants/${grantId}`, { method: "DELETE" }),

  auditSummary: () => request("/audit/summary"),
  auditEvents: (params) => request("/audit/events", { params }),

  listAlerts: (params) => request("/alerts", { params }),
  updateAlert: (alertId, status) => request(`/alerts/${alertId}`, { method: "PATCH", body: { status } }),
  explainAlert: (alertId) => request(`/alerts/${alertId}/explain`),

  listPolicies: (params) => request("/policies", { params }),
  createPolicy: (payload) => request("/policies", { method: "POST", body: payload }),
  deletePolicy: (policyId) => request(`/policies/${policyId}`, { method: "DELETE" }),
};

export { ApiError };
