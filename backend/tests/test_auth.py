def register_user(client, **overrides):
    payload = {
        "username": "jdoe",
        "email": "jdoe@example.com",
        "password": "correct-horse-battery-staple",
        "role": "Finance Employee",
        "department": "Finance",
        "clearance_level": "CONFIDENTIAL",
    }
    payload.update(overrides)
    return client.post("/auth/register", json=payload)


def test_register_creates_user_without_leaking_password(client):
    response = register_user(client)
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "jdoe"
    assert "password" not in body
    assert "password_hash" not in body


def test_register_rejects_duplicate_username(client):
    register_user(client)
    response = register_user(client, email="other@example.com")
    assert response.status_code == 409


def test_login_succeeds_with_correct_password(client):
    register_user(client)
    response = client.post("/auth/login", json={"username": "jdoe", "password": "correct-horse-battery-staple"})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_login_fails_with_wrong_password(client):
    register_user(client)
    response = client.post("/auth/login", json={"username": "jdoe", "password": "wrong-password"})
    assert response.status_code == 401


def test_account_locks_after_max_failed_logins(client):
    register_user(client)
    for _ in range(5):
        client.post("/auth/login", json={"username": "jdoe", "password": "wrong-password"})

    response = client.post("/auth/login", json={"username": "jdoe", "password": "correct-horse-battery-staple"})
    assert response.status_code == 403


def test_me_requires_authentication(client):
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_me_returns_current_user_with_valid_token(client):
    register_user(client)
    login_response = client.post("/auth/login", json={"username": "jdoe", "password": "correct-horse-battery-staple"})
    token = login_response.json()["access_token"]

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "jdoe"
