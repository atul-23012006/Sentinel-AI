"""Controlled attack scenarios from SentinelAI_README.md §16.

Tests 1, 4 and 5 exercise rule-based detection: account lockout, the hybrid
policy engine, and the audit trail. Test 2 and Test 3 exercise the adaptive
layer built in Phase 4/5 (risk engine + adaptive response); Test 3's risk
score is monkeypatched for determinism, matching tests/test_adaptive_access.py's
rationale (the exact ML-blended score is already covered there and in
tests/test_risk_engine.py).
"""

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


def test_scenario_1_brute_force_locks_account_and_is_audited(client):
    register(client, "victim")

    for _ in range(settings.max_failed_logins):
        response = client.post("/auth/login", json={"username": "victim", "password": "wrong"})
        assert response.status_code == 401

    # Account is now locked even with the correct password.
    locked_attempt = client.post(
        "/auth/login", json={"username": "victim", "password": "correct-horse-battery-staple"}
    )
    assert locked_attempt.status_code == 403

    events = client.get(
        "/audit/events", params={"action": "LOGIN"}, headers=admin_headers(client)
    ).json()
    victim_events = [e for e in events if e["reason"] and "victim" not in e["reason"]]  # exclude admin's own login
    lockout_events = [e for e in events if e["reason"] == "Account locked after repeated failed logins"]
    assert len(lockout_events) >= 1


def test_scenario_4_privilege_abuse_denied_by_rbac(client):
    register(client, "finance_user", role="Finance Employee", department="Finance")
    headers = login_headers(client, "finance_user")

    hr_admin = admin_headers(client)
    hr_resource = client.post(
        "/resources",
        json={
            "resource_name": "HR_Records.pdf",
            "classification": "CONFIDENTIAL",
            "department": "HR",
            "required_role": "HR Employee",
        },
        headers=hr_admin,
    ).json()

    response = client.post(
        f"/resources/{hr_resource['resource_id']}/access", json={"action": "READ"}, headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["final_decision"] == "DENY"
    rbac_result = next(r for r in body["policy_results"] if r["policy_type"] == "RBAC")
    assert rbac_result["decision"] == "FAIL"


def test_scenario_5_policy_violation_denied_by_mac(client):
    register(client, "intern", clearance_level="PUBLIC")
    headers = login_headers(client, "intern")

    admin = admin_headers(client)
    secret_resource = client.post(
        "/resources",
        json={
            "resource_name": "Classified_Plan.pdf",
            "classification": "TOP_SECRET",
            "department": "Finance",
            "required_role": None,
        },
        headers=admin,
    ).json()

    response = client.post(
        f"/resources/{secret_resource['resource_id']}/access", json={"action": "READ"}, headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["final_decision"] == "DENY"
    mac_result = next(r for r in body["policy_results"] if r["policy_type"] == "MAC")
    assert mac_result["decision"] == "FAIL"

    # The denial is auditable after the fact, independent of who is asking.
    events = client.get(
        "/audit/events", params={"resource_id": secret_resource["resource_id"]}, headers=admin
    ).json()
    assert any(e["final_decision"] == "DENY" for e in events)


def test_scenario_2_credential_compromise_denied_despite_valid_credentials(client, monkeypatch):
    # Simulates a login at an unusual hour from an unrecognized device: the
    # credentials are valid (this is not a brute-force case) but TBAC still
    # denies, matching README §9's point that authorization != safe behavior.
    monkeypatch.setattr(settings, "tbac_start_hour", 25)  # unreachable window -> TBAC always fails
    monkeypatch.setattr(settings, "tbac_end_hour", 25)

    register(client, "night_owl")
    headers = login_headers(client, "night_owl")

    admin = admin_headers(client)
    resource = client.post(
        "/resources",
        json={
            "resource_name": "Quarterly_Report.pdf",
            "classification": "CONFIDENTIAL",
            "department": "Finance",
            "required_role": None,
        },
        headers=admin,
    ).json()

    response = client.post(f"/resources/{resource['resource_id']}/access", json={"action": "READ"}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["final_decision"] == "DENY"
    tbac_result = next(r for r in body["policy_results"] if r["policy_type"] == "TBAC")
    assert tbac_result["decision"] == "FAIL"


def test_scenario_3_mass_download_triggers_adaptive_block_and_alert(client, monkeypatch):
    # README §16 Test 3: a burst of downloads that is, on its own, fully
    # authorized by policy (RBAC/MAC/ABAC/TBAC all pass) but behaviorally
    # anomalous - the risk engine escalates it past the policy engine's ALLOW.
    monkeypatch.setattr(settings, "tbac_start_hour", 0)
    monkeypatch.setattr(settings, "tbac_end_hour", 24)
    monkeypatch.setattr(
        risk_engine,
        "score",
        lambda *a, **k: RiskResult(
            score=93,
            reasons=["47 files accessed in 8 minutes", "18 downloads", "unknown device"],
            raw_features={},
            model_used=False,
        ),
    )

    register(client, "exfiltrator")
    headers = login_headers(client, "exfiltrator")
    me = client.get("/auth/me", headers=headers).json()
    admin = admin_headers(client)
    client.patch(f"/users/{me['user_id']}", json={"device_trust": "TRUSTED"}, headers=admin)

    resource = client.post(
        "/resources",
        json={
            "resource_name": "ResearchData.pdf",
            "classification": "CONFIDENTIAL",
            "department": "Finance",
            "required_role": None,
        },
        headers=admin,
    ).json()

    response = client.post(
        f"/resources/{resource['resource_id']}/access", json={"action": "DOWNLOAD"}, headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["final_decision"] == "BLOCK"

    # Policy itself still says ALLOW - the block is the adaptive layer, not a
    # policy denial - matching README §9's separation of authorization vs risk.
    rbac_result = next(r for r in body["policy_results"] if r["policy_type"] == "RBAC")
    assert rbac_result["decision"] == "PASS"

    alerts = client.get("/alerts", params={"severity": "CRITICAL"}, headers=admin).json()
    assert any(a["event_id"] == body["event_id"] for a in alerts)
