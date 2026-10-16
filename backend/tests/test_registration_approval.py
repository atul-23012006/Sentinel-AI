"""Admin-gated registration: a new account can't log in until an
Administrator approves it. Disabled by default in conftest.py's `client`
fixture (every other test assumes instant-active registration) - these
tests turn it back on explicitly.
"""

from app.auth import email_service
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
    return client.post("/auth/register", json=payload)


def login(client, username, password="correct-horse-battery-staple"):
    return client.post("/auth/login", json={"username": username, "password": password})


def test_first_ever_user_is_auto_activated_as_bootstrap_admin(client, monkeypatch):
    monkeypatch.setattr(settings, "require_admin_approval", True)

    response = register(client, "founder", role="Administrator")
    assert response.json()["account_status"] == "ACTIVE"

    login_response = login(client, "founder")
    assert login_response.status_code == 200


def test_second_user_is_pending_and_cannot_log_in(client, monkeypatch):
    monkeypatch.setattr(settings, "require_admin_approval", True)

    register(client, "admin", role="Administrator")  # bootstrap, auto-active

    response = register(client, "newhire", role="Finance Employee")
    assert response.json()["account_status"] == "PENDING"

    login_response = login(client, "newhire")
    assert login_response.status_code == 403
    assert "approval" in login_response.json()["detail"].lower()


def test_registration_notifies_active_admins_by_email(client, monkeypatch):
    monkeypatch.setattr(settings, "require_admin_approval", True)
    notified = []

    def fake_notify(admin_email, username, user_id):
        notified.append((admin_email, username))
        return False

    monkeypatch.setattr(email_service, "send_registration_pending_notification", fake_notify)

    register(client, "admin", role="Administrator")
    register(client, "newhire", role="Finance Employee")

    assert notified == [("admin@example.com", "newhire")]


def test_admin_approval_lets_a_pending_user_log_in(client, monkeypatch):
    monkeypatch.setattr(settings, "require_admin_approval", True)

    register(client, "admin", role="Administrator")
    admin_login = login(client, "admin").json()
    admin_headers = {"Authorization": f"Bearer {admin_login['access_token']}"}

    new_user = register(client, "newhire", role="Finance Employee").json()
    assert login(client, "newhire").status_code == 403

    approve = client.patch(
        f"/users/{new_user['user_id']}", json={"account_status": "ACTIVE"}, headers=admin_headers
    )
    assert approve.status_code == 200
    assert approve.json()["account_status"] == "ACTIVE"

    assert login(client, "newhire").status_code == 200


def test_admin_can_reject_a_pending_user(client, monkeypatch):
    monkeypatch.setattr(settings, "require_admin_approval", True)

    register(client, "admin", role="Administrator")
    admin_headers = {"Authorization": f"Bearer {login(client, 'admin').json()['access_token']}"}

    new_user = register(client, "suspicious", role="Finance Employee").json()

    reject = client.patch(
        f"/users/{new_user['user_id']}", json={"account_status": "DISABLED"}, headers=admin_headers
    )
    assert reject.status_code == 200
    assert reject.json()["account_status"] == "DISABLED"

    rejected_login = login(client, "suspicious")
    assert rejected_login.status_code == 403
    assert "disabled" in rejected_login.json()["detail"].lower()


def test_pending_users_are_filterable_for_the_admin_console(client, monkeypatch):
    monkeypatch.setattr(settings, "require_admin_approval", True)

    register(client, "admin", role="Administrator")
    admin_headers = {"Authorization": f"Bearer {login(client, 'admin').json()['access_token']}"}
    register(client, "newhire", role="Finance Employee")

    pending = client.get("/users", params={"account_status": "PENDING"}, headers=admin_headers).json()
    assert [u["username"] for u in pending] == ["newhire"]


def test_approval_gate_is_disabled_by_default_for_the_rest_of_the_suite(client):
    # Sanity check for the conftest.py fixture override that keeps the other
    # ~85 tests unaffected by this feature.
    response = register(client, "anyone", role="Finance Employee")
    assert response.json()["account_status"] == "ACTIVE"
    assert login(client, "anyone").status_code == 200
