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


def test_login_attempts_are_audited(client):
    client.post("/auth/login", json={"username": "ghost", "password": "whatever"})
    admin_headers = register_and_login(client, username="admin", role="Administrator")

    response = client.get("/audit/events", params={"action": "LOGIN"}, headers=admin_headers)

    assert response.status_code == 200
    reasons = [e["reason"] for e in response.json()]
    assert any("Unknown username" in r for r in reasons)
    assert any(r == "Login successful" for r in reasons)


def test_audit_events_require_admin_role(client):
    headers = register_and_login(client, username="jdoe", role="Finance Employee")
    response = client.get("/audit/events", headers=headers)
    assert response.status_code == 403


def test_audit_events_require_authentication(client):
    response = client.get("/audit/events")
    assert response.status_code == 401


def test_audit_summary_counts_decisions(client):
    admin_headers = register_and_login(client, username="admin", role="Administrator")
    client.post("/auth/login", json={"username": "no-such-user", "password": "x"})

    response = client.get("/audit/summary", headers=admin_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] >= 2  # admin's own successful login + the failed attempt
    assert body["deny_count"] >= 1
    assert body["allow_count"] >= 1


def test_get_single_event(client):
    admin_headers = register_and_login(client, username="admin", role="Administrator")

    events = client.get("/audit/events", headers=admin_headers).json()
    event_id = events[0]["event_id"]

    response = client.get(f"/audit/events/{event_id}", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["event_id"] == event_id


def test_get_missing_event_returns_404(client):
    admin_headers = register_and_login(client, username="admin", role="Administrator")
    response = client.get("/audit/events/9999", headers=admin_headers)
    assert response.status_code == 404
