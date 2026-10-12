def register_and_login(client, **overrides):
    payload = {
        "username": "jdoe",
        "email": "jdoe@example.com",
        "password": "correct-horse-battery-staple",
        "role": "Finance Employee",
        "department": "Finance",
        "clearance_level": "CONFIDENTIAL",
    }
    payload.update(overrides)
    client.post("/auth/register", json=payload)
    login = client.post("/auth/login", json={"username": payload["username"], "password": payload["password"]})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def create_resource(client, headers, **overrides):
    payload = {
        "resource_name": "Financial_Report.pdf",
        "classification": "CONFIDENTIAL",
        "department": "Finance",
        "required_role": None,
    }
    payload.update(overrides)
    response = client.post("/resources", json=payload, headers=headers)
    return response.json()


def test_access_denied_for_new_user_with_untrusted_device(client):
    headers = register_and_login(client)
    resource = create_resource(client, headers)

    response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    # Registration has no device-trust field, so new users default to
    # UNTRUSTED - RBAC/MAC/department all pass, but ABAC still fails.
    assert body["final_decision"] == "DENY"
    abac = next(r for r in body["policy_results"] if r["policy_type"] == "ABAC")
    assert abac["decision"] == "FAIL"


def test_mac_denies_access_to_resource_above_clearance(client):
    headers = register_and_login(client, clearance_level="PUBLIC")
    resource = create_resource(client, headers, classification="TOP_SECRET")

    response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["final_decision"] == "DENY"
    mac = next(r for r in body["policy_results"] if r["policy_type"] == "MAC")
    assert mac["decision"] == "FAIL"


def test_access_event_is_logged(client):
    headers = register_and_login(client)
    resource = create_resource(client, headers)

    response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers)

    assert response.status_code == 200
    assert "event_id" in response.json()


def test_access_requires_authentication(client):
    response = client.post("/resources/1/access", json={"action": "READ"})
    assert response.status_code == 401


def test_access_to_missing_resource_returns_404(client):
    headers = register_and_login(client)
    response = client.post("/resources/9999/access", json={"action": "READ"}, headers=headers)
    assert response.status_code == 404
