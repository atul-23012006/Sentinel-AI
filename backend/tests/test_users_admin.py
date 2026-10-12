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


def test_admin_can_trust_a_users_device(client):
    headers = register_and_login(client, username="jdoe")
    me = client.get("/auth/me", headers=headers).json()
    admin = register_and_login(client, username="admin", role="Administrator")

    response = client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin)

    assert response.status_code == 200
    assert response.json()["device_trust"] == "TRUSTED"


def test_admin_can_reactivate_a_locked_account_and_lockout_counter_resets(client):
    from app.config import settings

    headers = register_and_login(client, username="victim")
    admin = register_and_login(client, username="admin", role="Administrator")

    for _ in range(settings.max_failed_logins):
        client.post("/auth/login", json={"username": "victim", "password": "wrong"})

    locked_attempt = client.post(
        "/auth/login", json={"username": "victim", "password": "correct-horse-battery-staple"}
    )
    assert locked_attempt.status_code == 403

    me = client.get("/users", headers=admin).json()
    victim = next(u for u in me if u["username"] == "victim")
    assert victim["account_status"] == "LOCKED"

    reactivate = client.patch(
        f"/users/{victim['user_id']}", json={"account_status": "ACTIVE"}, headers=admin
    )
    assert reactivate.status_code == 200
    assert reactivate.json()["account_status"] == "ACTIVE"

    relogin = client.post(
        "/auth/login", json={"username": "victim", "password": "correct-horse-battery-staple"}
    )
    assert relogin.status_code == 200
    _ = headers  # victim's own token is unused after lockout; kept for readability


def test_update_user_requires_admin_role(client):
    headers = register_and_login(client, username="jdoe")
    me = client.get("/auth/me", headers=headers).json()

    response = client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=headers)
    assert response.status_code == 403


def test_update_missing_user_returns_404(client):
    admin = register_and_login(client, username="admin", role="Administrator")
    response = client.patch("/users/9999", json={"device_trust": "TRUSTED"}, headers=admin)
    assert response.status_code == 404
