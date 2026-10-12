"""Admin-driven overrides added on top of the attribute-based hybrid engine:
editing a user's role/department/clearance, editing/deleting a resource, and
explicit per-user ResourceGrants that bypass RBAC/MAC/ABAC/TBAC/OBAC (but
never the risk engine) for one user.
"""

from app.config import settings


def register(client, username, role="Finance Employee", department="Finance", clearance_level="CONFIDENTIAL"):
    payload = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "correct-horse-battery-staple",
        "role": role,
        "department": department,
        "clearance_level": clearance_level,
    }
    client.post("/auth/register", json=payload)
    return payload


def login_headers(client, username, password="correct-horse-battery-staple"):
    response = client.post("/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def admin_headers(client):
    register(client, "admin", role="Administrator")
    return login_headers(client, "admin")


# --- Admin editing a user's role/department/clearance ---


def test_admin_can_change_user_role_department_clearance(client):
    register(client, "jdoe", role="Finance Employee", department="Finance", clearance_level="PUBLIC")
    user_headers = login_headers(client, "jdoe")
    me = client.get("/auth/me", headers=user_headers).json()
    admin = admin_headers(client)

    response = client.patch(
        f"/users/{me['user_id']}",
        json={"role": "HR Employee", "department": "HR", "clearance_level": "SECRET"},
        headers=admin,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "HR Employee"
    assert body["department"] == "HR"
    assert body["clearance_level"] == "SECRET"


def test_non_admin_cannot_change_their_own_role(client):
    register(client, "selfpromote", role="Finance Employee")
    headers = login_headers(client, "selfpromote")
    me = client.get("/auth/me", headers=headers).json()

    response = client.patch(f"/users/{me['user_id']}", json={"role": "Administrator"}, headers=headers)
    assert response.status_code == 403


# --- Admin editing/deleting a resource ---


def test_admin_can_reclassify_a_resource(client):
    admin = admin_headers(client)
    resource = client.post(
        "/resources",
        json={"resource_name": "Draft.pdf", "classification": "PUBLIC", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    response = client.patch(
        f"/resources/{resource['resource_id']}",
        json={"classification": "TOP_SECRET", "required_role": "Administrator"},
        headers=admin,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["classification"] == "TOP_SECRET"
    assert body["required_role"] == "Administrator"


def test_clear_required_role_flag_nulls_it_out(client):
    admin = admin_headers(client)
    resource = client.post(
        "/resources",
        json={"resource_name": "HR.pdf", "classification": "CONFIDENTIAL", "department": "HR", "required_role": "HR Employee"},
        headers=admin,
    ).json()

    response = client.patch(
        f"/resources/{resource['resource_id']}", json={"clear_required_role": True}, headers=admin
    )
    assert response.json()["required_role"] is None


def test_admin_can_delete_a_resource(client):
    admin = admin_headers(client)
    resource = client.post(
        "/resources",
        json={"resource_name": "Temp.pdf", "classification": "PUBLIC", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    delete = client.delete(f"/resources/{resource['resource_id']}", headers=admin)
    assert delete.status_code == 204
    assert client.get(f"/resources/{resource['resource_id']}", headers=admin).status_code == 404


def test_resource_edit_and_delete_require_admin_role(client):
    register(client, "plain", role="Finance Employee")
    headers = login_headers(client, "plain")
    admin = admin_headers(client)
    resource = client.post(
        "/resources",
        json={"resource_name": "X.pdf", "classification": "PUBLIC", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    assert client.patch(f"/resources/{resource['resource_id']}", json={"classification": "SECRET"}, headers=headers).status_code == 403
    assert client.delete(f"/resources/{resource['resource_id']}", headers=headers).status_code == 403


# --- Explicit per-user resource grants ---


def test_explicit_grant_overrides_a_mac_denial(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)

    admin = admin_headers(client)
    register(client, "intern", clearance_level="PUBLIC")
    headers = login_headers(client, "intern")
    me = client.get("/auth/me", headers=headers).json()
    client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin)

    resource = client.post(
        "/resources",
        json={"resource_name": "Classified.pdf", "classification": "TOP_SECRET", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    # Without a grant: denied by MAC (PUBLIC < TOP_SECRET).
    denied = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers).json()
    assert denied["final_decision"] == "DENY"
    assert next(r for r in denied["policy_results"] if r["policy_type"] == "MAC")["decision"] == "FAIL"

    # Admin issues an explicit, reasoned exception.
    grant = client.post(
        f"/resources/{resource['resource_id']}/grants",
        json={"user_id": me["user_id"], "reason": "Temporary audit access, approved by CISO"},
        headers=admin,
    )
    assert grant.status_code == 201

    allowed = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers).json()
    assert allowed["final_decision"] == "ALLOW"
    mac_in_results = next(r for r in allowed["policy_results"] if r["policy_type"] == "MAC")
    assert mac_in_results["decision"] == "FAIL"  # still shown as failed for audit transparency
    grant_in_results = next(r for r in allowed["policy_results"] if r["policy_type"] == "GRANT")
    assert grant_in_results["decision"] == "PASS"


def test_grant_scoped_to_one_action_does_not_cover_others(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)

    admin = admin_headers(client)
    register(client, "scoped_user", clearance_level="PUBLIC")
    headers = login_headers(client, "scoped_user")
    me = client.get("/auth/me", headers=headers).json()
    client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin)

    resource = client.post(
        "/resources",
        json={"resource_name": "Secret.pdf", "classification": "TOP_SECRET", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    client.post(
        f"/resources/{resource['resource_id']}/grants",
        json={"user_id": me["user_id"], "action": "READ"},
        headers=admin,
    )

    read_response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers).json()
    assert read_response["final_decision"] == "ALLOW"

    download_response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers).json()
    assert download_response["final_decision"] == "DENY"


def test_expired_grant_does_not_apply(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)

    admin = admin_headers(client)
    register(client, "expired_user", clearance_level="PUBLIC")
    headers = login_headers(client, "expired_user")
    me = client.get("/auth/me", headers=headers).json()
    client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin)

    resource = client.post(
        "/resources",
        json={"resource_name": "Old.pdf", "classification": "TOP_SECRET", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    client.post(
        f"/resources/{resource['resource_id']}/grants",
        json={"user_id": me["user_id"], "expires_at": "2000-01-01T00:00:00Z"},
        headers=admin,
    )

    response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers).json()
    assert response["final_decision"] == "DENY"


def test_admin_can_list_and_revoke_grant(client):
    admin = admin_headers(client)
    register(client, "grantee")
    user_headers = login_headers(client, "grantee")
    me = client.get("/auth/me", headers=user_headers).json()
    resource = client.post(
        "/resources",
        json={"resource_name": "File.pdf", "classification": "PUBLIC", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    created = client.post(
        f"/resources/{resource['resource_id']}/grants", json={"user_id": me["user_id"]}, headers=admin
    ).json()

    listing = client.get(f"/resources/{resource['resource_id']}/grants", headers=admin).json()
    assert any(g["grant_id"] == created["grant_id"] for g in listing)

    revoke = client.delete(f"/resources/{resource['resource_id']}/grants/{created['grant_id']}", headers=admin)
    assert revoke.status_code == 204

    listing_after = client.get(f"/resources/{resource['resource_id']}/grants", headers=admin).json()
    assert all(g["grant_id"] != created["grant_id"] for g in listing_after)


def test_grants_require_admin_role(client):
    register(client, "plain_user2")
    headers = login_headers(client, "plain_user2")
    admin = admin_headers(client)
    resource = client.post(
        "/resources",
        json={"resource_name": "Y.pdf", "classification": "PUBLIC", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    assert client.post(
        f"/resources/{resource['resource_id']}/grants", json={"user_id": 1}, headers=headers
    ).status_code == 403
    assert client.get(f"/resources/{resource['resource_id']}/grants", headers=headers).status_code == 403


def test_grant_does_not_bypass_risk_engine(client, monkeypatch):
    # A grant fixes authorization, not behavioral trust - a high risk score
    # still escalates even though the user is explicitly granted access.
    from app.risk.engine import RiskResult, risk_engine

    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(
        risk_engine, "score", lambda *a, **k: RiskResult(score=95, reasons=["simulated"], raw_features={}, model_used=False)
    )

    admin = admin_headers(client)
    register(client, "risky_grantee", clearance_level="PUBLIC")
    headers = login_headers(client, "risky_grantee")
    me = client.get("/auth/me", headers=headers).json()
    client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin)

    resource = client.post(
        "/resources",
        json={"resource_name": "Sensitive.pdf", "classification": "TOP_SECRET", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()
    client.post(f"/resources/{resource['resource_id']}/grants", json={"user_id": me["user_id"]}, headers=admin)

    response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers).json()
    # Policy layer says ALLOW (via GRANT), but the adaptive layer still blocks.
    assert response["final_decision"] == "BLOCK"
