"""Integration tests for adaptive security (README §9), security alerts
(README §10) and the AI analyst (README §11).

The risk engine's `.score` is monkeypatched to a fixed RiskResult in most of
these tests: the ML-blended score's exact value is already covered by
test_risk_engine.py's real-model test, and pinning it here would make these
tests flaky against the trained model's exact decision boundary. What's
under test here is the adaptive-response wiring itself: given a risk score,
does the system escalate, alert, and allow step-up recovery correctly.
"""

import pyotp

from app.auth import email_service
from app.config import settings
from app.risk.engine import RiskResult, risk_engine


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


def trust_device(client, admin, user_id):
    client.patch(f"/users/{user_id}", json={"device_trust": "TRUSTED"}, headers=admin)


def setup_allowed_user(client, username):
    register(client, username)
    headers = login_headers(client, username)
    me = client.get("/auth/me", headers=headers).json()
    admin = admin_headers(client)
    trust_device(client, admin, me["user_id"])
    resource = client.post(
        "/resources",
        json={
            "resource_name": "Confidential_Report.pdf",
            "classification": "CONFIDENTIAL",
            "department": "Finance",
            "required_role": None,
        },
        headers=admin,
    ).json()
    return headers, admin, me, resource


def _fake_score(score, reasons=("Simulated for test",)):
    def _inner(*_args, **_kwargs):
        return RiskResult(score=score, reasons=list(reasons), raw_features={}, model_used=False)

    return _inner


def test_normal_access_is_allowed_and_not_alerted(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)

    headers, admin, _me, resource = setup_allowed_user(client, "alice")

    # No device_id/location given: this user has no prior access history, so
    # a device_id or location here would score as "never seen before" purely
    # for lack of history, not because anything is actually suspicious.
    response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["final_decision"] == "ALLOW"
    assert body["risk_score"] is not None

    alerts = client.get("/alerts", headers=admin).json()
    assert alerts == []


def test_moderate_risk_allows_but_raises_monitoring_alert(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(risk_engine, "score", _fake_score(45))

    headers, admin, _me, resource = setup_allowed_user(client, "monitored_user")

    response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers
    )
    body = response.json()
    assert body["final_decision"] == "ALLOW"
    assert body["risk_score"] == 45

    alerts = client.get("/alerts", headers=admin).json()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["status"] == "OPEN"


def test_elevated_risk_requires_mfa_and_step_up_verification_restores_access(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)

    headers, admin, me, resource = setup_allowed_user(client, "step_up_user")

    # User already has TOTP configured, so the step-up challenge is MFA, not
    # email verification (see test_elevated_risk_without_mfa_... below).
    setup = client.get("/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["otp_secret"]

    monkeypatch.setattr(risk_engine, "score", _fake_score(70))
    response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers
    )
    body = response.json()
    assert body["final_decision"] == "MFA_REQUIRED"
    assert body["mfa_setup_required"] is False

    alerts = client.get("/alerts", headers=admin).json()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"

    bad_verify = client.post(
        "/auth/mfa/verify", json={"event_id": body["event_id"], "code": "000000"}, headers=headers
    )
    assert bad_verify.status_code == 401

    code = pyotp.TOTP(secret).now()
    good_verify = client.post(
        "/auth/mfa/verify", json={"event_id": body["event_id"], "code": code}, headers=headers
    )
    assert good_verify.status_code == 200

    events = client.get("/audit/events", params={"user_id": me["user_id"]}, headers=admin).json()
    upgraded = next(e for e in events if e["event_id"] == body["event_id"])
    assert upgraded["final_decision"] == "ALLOW"

    # Re-verifying the same (already-resolved) event is rejected.
    replay = client.post(
        "/auth/mfa/verify", json={"event_id": body["event_id"], "code": code}, headers=headers
    )
    assert replay.status_code == 409


def test_elevated_risk_without_mfa_sends_email_verification_and_step_up_restores_access(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(risk_engine, "score", _fake_score(70))

    captured = {}

    def fake_send(to_email, code):
        captured["email"] = to_email
        captured["code"] = code
        return False  # simulates SMTP not configured, same as the real fallback

    monkeypatch.setattr(email_service, "send_verification_code", fake_send)

    # No /auth/mfa/setup call here - this user has never configured TOTP, so
    # the step-up challenge falls back to a one-time emailed code instead.
    headers, admin, me, resource = setup_allowed_user(client, "email_step_up_user")

    response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers
    )
    body = response.json()
    assert body["final_decision"] == "EMAIL_VERIFICATION_REQUIRED"
    assert body["mfa_setup_required"] is False
    assert body["email_verification_hint"] is not None
    assert captured["email"] == "email_step_up_user@example.com"

    bad_verify = client.post(
        "/auth/email-verify/verify", json={"event_id": body["event_id"], "code": "000000"}, headers=headers
    )
    assert bad_verify.status_code == 401

    good_verify = client.post(
        "/auth/email-verify/verify",
        json={"event_id": body["event_id"], "code": captured["code"]},
        headers=headers,
    )
    assert good_verify.status_code == 200

    events = client.get("/audit/events", params={"user_id": me["user_id"]}, headers=admin).json()
    upgraded = next(e for e in events if e["event_id"] == body["event_id"])
    assert upgraded["final_decision"] == "ALLOW"

    replay = client.post(
        "/auth/email-verify/verify",
        json={"event_id": body["event_id"], "code": captured["code"]},
        headers=headers,
    )
    assert replay.status_code == 409


def test_repeated_blocks_auto_lock_account_pending_admin_reactivation(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(risk_engine, "score", _fake_score(95))
    monkeypatch.setattr(settings, "max_blocked_requests", 3)

    headers, admin, me, resource = setup_allowed_user(client, "abuser")

    last_body = None
    for _ in range(3):
        response = client.post(
            f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers
        )
        last_body = response.json()

    assert last_body["final_decision"] == "BLOCK"
    assert last_body["account_locked"] is True

    locked_user = client.get(f"/users/{me['user_id']}", headers=admin).json()
    assert locked_user["account_status"] == "LOCKED"

    lockout_alerts = [
        a for a in client.get("/alerts", headers=admin).json() if a["alert_type"] == "REPEATED_ABUSE_LOCKOUT"
    ]
    assert len(lockout_alerts) == 1
    assert lockout_alerts[0]["severity"] == "CRITICAL"

    # The account-active check happens before any resource/risk logic runs.
    still_locked = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers
    )
    assert still_locked.status_code == 403

    reactivate = client.patch(f"/users/{me['user_id']}", json={"account_status": "ACTIVE"}, headers=admin)
    assert reactivate.status_code == 200
    assert reactivate.json()["account_status"] == "ACTIVE"

    headers = login_headers(client, "abuser")
    response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers
    )
    body = response.json()
    assert body["final_decision"] == "BLOCK"  # risk is still high
    assert body["account_locked"] is False  # but the counter was reset by reactivation


def test_critical_risk_blocks_and_ai_analyst_explains_it(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(
        risk_engine,
        "score",
        _fake_score(95, ["47 files accessed in 8 minutes (+30)", "18 downloads in the last hour (+25)"]),
    )

    headers, admin, _me, resource = setup_allowed_user(client, "blocked_user")

    response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers
    )
    body = response.json()
    assert body["final_decision"] == "BLOCK"

    alerts = client.get("/alerts", params={"severity": "CRITICAL"}, headers=admin).json()
    assert len(alerts) == 1
    alert_id = alerts[0]["alert_id"]

    explanation = client.get(f"/alerts/{alert_id}/explain", headers=admin).json()
    assert explanation["source"] == "template"  # no ANTHROPIC_API_KEY configured in tests
    assert "Risk score: 95/100" in explanation["explanation"]
    assert "Recommended actions" in explanation["explanation"]

    update = client.patch(f"/alerts/{alert_id}", json={"status": "RESOLVED"}, headers=admin)
    assert update.status_code == 200
    assert update.json()["status"] == "RESOLVED"


def test_alerts_and_explain_require_admin_role(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(risk_engine, "score", _fake_score(90))
    headers, admin, _me, resource = setup_allowed_user(client, "non_admin_viewer")
    client.post(f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers)

    assert client.get("/alerts", headers=headers).status_code == 403

    alert_id = client.get("/alerts", headers=admin).json()[0]["alert_id"]
    assert client.get(f"/alerts/{alert_id}/explain", headers=headers).status_code == 403
    assert client.patch(f"/alerts/{alert_id}", json={"status": "RESOLVED"}, headers=headers).status_code == 403


def test_rapid_fire_access_is_blocked_and_flagged_even_at_low_risk(client, monkeypatch):
    # Burst detection is a deterministic rate-limit independent of the ML
    # risk score - pin the score low so a BLOCK here can only be explained
    # by request volume, not behavioral risk.
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(risk_engine, "score", _fake_score(5))
    monkeypatch.setattr(settings, "max_burst_requests", 10)
    monkeypatch.setattr(settings, "burst_window_seconds", 3600)

    headers, admin, _me, resource = setup_allowed_user(client, "clicker")

    last_body = None
    for _ in range(10):
        response = client.post(
            f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers
        )
        last_body = response.json()

    # The first 9 are ordinary low-risk ALLOWs; the 10th crosses the burst
    # threshold and gets blocked regardless of its (low) risk score.
    assert last_body["final_decision"] == "BLOCK"
    assert last_body["risk_score"] == 5

    alerts = client.get("/alerts", params={"severity": "CRITICAL"}, headers=admin).json()
    rapid_fire = [a for a in alerts if a["alert_type"] == "RAPID_FIRE_ACCESS"]
    assert len(rapid_fire) == 1
    assert rapid_fire[0]["event_id"] == last_body["event_id"]


def test_burst_detection_does_not_fire_outside_the_window(client, monkeypatch):
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(risk_engine, "score", _fake_score(5))
    monkeypatch.setattr(settings, "max_burst_requests", 3)
    monkeypatch.setattr(settings, "burst_window_seconds", 0)  # window closes instantly

    headers, admin, _me, resource = setup_allowed_user(client, "slow_clicker")

    last_body = None
    for _ in range(5):
        response = client.post(
            f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers
        )
        last_body = response.json()

    assert last_body["final_decision"] == "ALLOW"
    alerts = client.get("/alerts", params={"severity": "CRITICAL"}, headers=admin).json()
    assert not [a for a in alerts if a["alert_type"] == "RAPID_FIRE_ACCESS"]
