from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import Policy, Resource, User
from app.policies.engine import (
    HybridPolicyEngine,
    evaluate_abac,
    evaluate_mac,
    evaluate_obac,
    evaluate_rbac,
    evaluate_tbac,
)


def make_user(**overrides) -> User:
    defaults = dict(
        username="jdoe",
        email="jdoe@example.com",
        password_hash="x",
        role="Finance Employee",
        department="Finance",
        clearance_level="CONFIDENTIAL",
        device_trust="TRUSTED",
        account_status="ACTIVE",
    )
    defaults.update(overrides)
    return User(**defaults)


def make_resource(**overrides) -> Resource:
    defaults = dict(
        resource_name="Financial_Report.pdf",
        classification="CONFIDENTIAL",
        department="Finance",
        required_role=None,
    )
    defaults.update(overrides)
    return Resource(**defaults)


def during_business_hours() -> datetime:
    return datetime(2026, 1, 5, 12, 0, tzinfo=timezone.utc)  # Monday noon


def outside_business_hours() -> datetime:
    return datetime(2026, 1, 5, 2, 17, tzinfo=timezone.utc)  # 02:17 AM


def test_rbac_passes_when_no_role_required():
    result = evaluate_rbac(make_user(), make_resource(required_role=None))
    assert result.decision == "PASS"


def test_rbac_passes_when_role_matches():
    result = evaluate_rbac(make_user(role="HR Employee"), make_resource(required_role="HR Employee"))
    assert result.decision == "PASS"


def test_rbac_fails_when_role_does_not_match():
    result = evaluate_rbac(make_user(role="Finance Employee"), make_resource(required_role="HR Employee"))
    assert result.decision == "FAIL"


def test_mac_passes_when_clearance_meets_classification():
    result = evaluate_mac(make_user(clearance_level="SECRET"), make_resource(classification="CONFIDENTIAL"))
    assert result.decision == "PASS"


def test_mac_fails_when_clearance_below_classification():
    result = evaluate_mac(make_user(clearance_level="PUBLIC"), make_resource(classification="SECRET"))
    assert result.decision == "FAIL"


def test_abac_fails_on_department_mismatch():
    result = evaluate_abac(make_user(department="Finance"), make_resource(department="HR"))
    assert result.decision == "FAIL"
    assert "department" in result.reason.lower()


def test_abac_fails_on_untrusted_device():
    result = evaluate_abac(make_user(device_trust="UNTRUSTED"), make_resource())
    assert result.decision == "FAIL"
    assert "device" in result.reason.lower()


def test_abac_passes_when_department_and_device_ok():
    result = evaluate_abac(make_user(), make_resource())
    assert result.decision == "PASS"


def test_tbac_passes_during_business_hours():
    result = evaluate_tbac(during_business_hours())
    assert result.decision == "PASS"


def test_tbac_fails_outside_business_hours():
    result = evaluate_tbac(outside_business_hours())
    assert result.decision == "FAIL"


def test_hybrid_engine_allows_when_all_policies_pass():
    engine = HybridPolicyEngine()
    evaluation = engine.evaluate(make_user(), make_resource(), "READ", now=during_business_hours())
    assert evaluation.final_decision == "ALLOW"
    assert evaluation.failures == []


def test_hybrid_engine_mac_deny_overrides_rbac_pass():
    # Mirrors README §9: RBAC/ABAC/TBAC can all PASS while MAC alone denies.
    user = make_user(clearance_level="PUBLIC")
    resource = make_resource(classification="TOP_SECRET", required_role=None)
    engine = HybridPolicyEngine()

    evaluation = engine.evaluate(user, resource, "READ", now=during_business_hours())

    assert evaluation.final_decision == "DENY"
    failed_types = {f.policy_type for f in evaluation.failures}
    assert failed_types == {"MAC"}


def test_hybrid_engine_denies_outside_business_hours_even_if_authorized():
    engine = HybridPolicyEngine()
    evaluation = engine.evaluate(make_user(), make_resource(), "READ", now=outside_business_hours())
    assert evaluation.final_decision == "DENY"
    failed_types = {f.policy_type for f in evaluation.failures}
    assert failed_types == {"TBAC"}


# --- OBAC: per-operation rules on the same resource ---


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    session_factory = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = session_factory()
    yield session
    session.close()


def _persisted_resource(db_session, **overrides) -> Resource:
    resource = make_resource(**overrides)
    db_session.add(resource)
    db_session.commit()
    db_session.refresh(resource)
    return resource


def test_obac_passes_with_no_database_context():
    # Pure-function unit tests (no db) can't have a resource_id to look rules
    # up by, so OBAC must not block them - it has nothing to evaluate.
    result = evaluate_obac(None, make_user(), make_resource(), "DELETE")
    assert result.decision == "PASS"


def test_obac_passes_when_no_matching_rule(db_session):
    resource = _persisted_resource(db_session)
    result = evaluate_obac(db_session, make_user(), resource, "DOWNLOAD")
    assert result.decision == "PASS"


def test_obac_restricts_a_specific_action_by_role(db_session):
    resource = _persisted_resource(db_session)
    db_session.add(
        Policy(
            policy_type="OBAC",
            policy_name="Only admins may delete financial reports",
            rule_definition={"resource_id": resource.resource_id, "action": "DELETE", "required_role": "Administrator"},
        )
    )
    db_session.commit()

    finance_employee = make_user(role="Finance Employee")
    admin = make_user(role="Administrator")

    # READ is unaffected - the rule only targets DELETE.
    read_result = evaluate_obac(db_session, finance_employee, resource, "READ")
    assert read_result.decision == "PASS"

    delete_result = evaluate_obac(db_session, finance_employee, resource, "DELETE")
    assert delete_result.decision == "FAIL"
    assert "DELETE" in delete_result.reason

    admin_delete_result = evaluate_obac(db_session, admin, resource, "DELETE")
    assert admin_delete_result.decision == "PASS"


def test_obac_restricts_a_specific_action_by_clearance(db_session):
    resource = _persisted_resource(db_session, classification="CONFIDENTIAL")
    db_session.add(
        Policy(
            policy_type="OBAC",
            policy_name="Downloads require SECRET clearance even though reads only need CONFIDENTIAL",
            rule_definition={"resource_id": resource.resource_id, "action": "DOWNLOAD", "min_clearance": "SECRET"},
        )
    )
    db_session.commit()

    confidential_user = make_user(clearance_level="CONFIDENTIAL")
    secret_user = make_user(clearance_level="SECRET")

    assert evaluate_obac(db_session, confidential_user, resource, "DOWNLOAD").decision == "FAIL"
    assert evaluate_obac(db_session, secret_user, resource, "DOWNLOAD").decision == "PASS"


def test_obac_disabled_rule_is_ignored(db_session):
    resource = _persisted_resource(db_session)
    db_session.add(
        Policy(
            policy_type="OBAC",
            policy_name="Disabled rule",
            rule_definition={"resource_id": resource.resource_id, "action": "DELETE", "required_role": "Administrator"},
            enabled=False,
        )
    )
    db_session.commit()

    result = evaluate_obac(db_session, make_user(role="Finance Employee"), resource, "DELETE")
    assert result.decision == "PASS"


def test_hybrid_engine_denies_restricted_operation_but_allows_others(db_session):
    resource = _persisted_resource(db_session)
    db_session.add(
        Policy(
            policy_type="OBAC",
            policy_name="Only admins may delete",
            rule_definition={"resource_id": resource.resource_id, "action": "DELETE", "required_role": "Administrator"},
        )
    )
    db_session.commit()

    engine = HybridPolicyEngine()
    user = make_user(role="Finance Employee")

    read_eval = engine.evaluate(user, resource, "READ", db=db_session, now=during_business_hours())
    assert read_eval.final_decision == "ALLOW"

    delete_eval = engine.evaluate(user, resource, "DELETE", db=db_session, now=during_business_hours())
    assert delete_eval.final_decision == "DENY"
    assert {f.policy_type for f in delete_eval.failures} == {"OBAC"}
