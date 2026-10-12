def register_and_login(client, username="jdoe", role="Finance Employee", **overrides):
    payload = {
        "username": username,
        "email": f"{username}@example.com",
        "password": "correct-horse-battery-staple",
        "role": role,
        "department": "Finance",
        "clearance_level": "CONFIDENTIAL",
    }
    payload.update(overrides)
    client.post("/auth/register", json=payload)
    login = client.post("/auth/login", json={"username": username, "password": payload["password"]})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_create_and_list_obac_policy(client):
    admin = register_and_login(client, username="admin", role="Administrator")
    resource = client.post(
        "/resources",
        json={"resource_name": "Payroll.xlsx", "classification": "CONFIDENTIAL", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    payload = {
        "policy_type": "OBAC",
        "policy_name": "Only admins may delete payroll",
        "rule_definition": {"resource_id": resource["resource_id"], "action": "DELETE", "required_role": "Administrator"},
        "priority": 10,
    }
    create = client.post("/policies", json=payload, headers=admin)
    assert create.status_code == 201
    policy_id = create.json()["policy_id"]

    listing = client.get("/policies", params={"policy_type": "OBAC"}, headers=admin)
    assert listing.status_code == 200
    assert any(p["policy_id"] == policy_id for p in listing.json())


def test_obac_policy_blocks_only_the_targeted_action(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)

    admin = register_and_login(client, username="admin2", role="Administrator")
    employee = register_and_login(client, username="employee", role="Finance Employee")
    me = client.get("/auth/me", headers=employee).json()
    client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin)

    resource = client.post(
        "/resources",
        json={"resource_name": "Payroll.xlsx", "classification": "CONFIDENTIAL", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()

    client.post(
        "/policies",
        json={
            "policy_type": "OBAC",
            "policy_name": "Only admins may delete payroll",
            "rule_definition": {"resource_id": resource["resource_id"], "action": "DELETE", "required_role": "Administrator"},
        },
        headers=admin,
    )

    read_response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=employee
    ).json()
    assert read_response["final_decision"] == "ALLOW"

    delete_response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "DELETE"}, headers=employee
    ).json()
    assert delete_response["final_decision"] == "DENY"
    obac_result = next(r for r in delete_response["policy_results"] if r["policy_type"] == "OBAC")
    assert obac_result["decision"] == "FAIL"


def test_update_and_delete_policy(client):
    admin = register_and_login(client, username="admin3", role="Administrator")
    resource = client.post(
        "/resources",
        json={"resource_name": "Data.csv", "classification": "PUBLIC", "department": "Finance", "required_role": None},
        headers=admin,
    ).json()
    created = client.post(
        "/policies",
        json={
            "policy_type": "OBAC",
            "policy_name": "Temp rule",
            "rule_definition": {"resource_id": resource["resource_id"], "action": "WRITE", "required_role": "Administrator"},
        },
        headers=admin,
    ).json()

    update = client.patch(f"/policies/{created['policy_id']}", json={"enabled": False}, headers=admin)
    assert update.status_code == 200
    assert update.json()["enabled"] is False

    delete = client.delete(f"/policies/{created['policy_id']}", headers=admin)
    assert delete.status_code == 204
    assert client.get(f"/policies/{created['policy_id']}", headers=admin).status_code == 404


def test_policies_require_admin_role(client):
    employee = register_and_login(client, username="plain_user", role="Finance Employee")
    assert client.get("/policies", headers=employee).status_code == 403
    assert client.post(
        "/policies",
        json={"policy_type": "OBAC", "policy_name": "x", "rule_definition": {}},
        headers=employee,
    ).status_code == 403
