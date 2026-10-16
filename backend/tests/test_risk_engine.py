"""Unit tests for the behavioral risk engine (README §7/§8, Phase 4/5).

The rule-based scorer and the ALLOW/MFA_REQUIRED/BLOCK threshold mapping are
pure functions and are tested deterministically here. End-to-end adaptive
behavior (with the real trained Isolation Forest in the loop) is covered by
tests/test_adaptive_access.py.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.models import User
from app.resources.router import _adaptive_decision
from app.risk.engine import rule_based_score
from app.risk.features import RawFeatures
from app.risk.engine import risk_engine as _risk_engine


def _features(**overrides):
    base = dict(
        login_hour=12,
        events_last_hour=2,
        distinct_resources_last_hour=1,
        downloads_last_hour=0,
        denied_ratio_last_24h=0.0,
        failed_login_count=0,
        new_device=0,
        new_location=0,
        outside_business_hours=0,
    )
    base.update(overrides)
    return RawFeatures(**base)


def test_normal_behavior_scores_zero():
    score, _ = rule_based_score(_features())
    assert score == 0


def test_outside_business_hours_adds_twenty():
    score, reasons = rule_based_score(_features(outside_business_hours=1))
    assert score == 20
    assert any("business hours" in r for r in reasons)


def test_mass_download_and_high_frequency_stack():
    score, reasons = rule_based_score(_features(events_last_hour=25, downloads_last_hour=10))
    assert score == 30 + 25
    assert any("download" in r.lower() for r in reasons)


def test_new_device_and_location_add_points():
    score, _ = rule_based_score(_features(new_device=1, new_location=1))
    assert score == 25


def test_high_denied_ratio_adds_points():
    score, _ = rule_based_score(_features(denied_ratio_last_24h=0.5))
    assert score == 10


def test_score_is_capped_at_100():
    score, _ = rule_based_score(
        _features(
            outside_business_hours=1,
            events_last_hour=50,
            downloads_last_hour=50,
            new_device=1,
            new_location=1,
            denied_ratio_last_24h=0.9,
        )
    )
    assert score == 100


def test_policy_deny_always_wins_regardless_of_risk():
    assert _adaptive_decision("DENY", 0, mfa_available=True) == "DENY"
    assert _adaptive_decision("DENY", 100, mfa_available=False) == "DENY"


def test_low_risk_allow_stays_allow():
    assert _adaptive_decision("ALLOW", 0, mfa_available=True) == "ALLOW"
    assert _adaptive_decision("ALLOW", 30, mfa_available=False) == "ALLOW"


def test_elevated_risk_requires_mfa_when_configured():
    assert _adaptive_decision("ALLOW", 61, mfa_available=True) == "MFA_REQUIRED"
    assert _adaptive_decision("ALLOW", 80, mfa_available=True) == "MFA_REQUIRED"


def test_elevated_risk_requires_email_verification_when_mfa_not_configured():
    assert _adaptive_decision("ALLOW", 61, mfa_available=False) == "EMAIL_VERIFICATION_REQUIRED"
    assert _adaptive_decision("ALLOW", 80, mfa_available=False) == "EMAIL_VERIFICATION_REQUIRED"


def test_high_risk_blocks_regardless_of_mfa_availability():
    assert _adaptive_decision("ALLOW", 81, mfa_available=True) == "BLOCK"
    assert _adaptive_decision("ALLOW", 100, mfa_available=False) == "BLOCK"


def test_burst_detected_forces_step_up_even_at_low_risk_score():
    # Rapid-fire detection is a deterministic rate-limit, not a risk-score
    # signal - it must force at least a step-up challenge even when
    # behavioral risk reads near zero, giving the user a chance to
    # reconfirm identity rather than an immediate hard block.
    assert _adaptive_decision("ALLOW", 0, mfa_available=True, burst_detected=True) == "MFA_REQUIRED"
    assert _adaptive_decision("ALLOW", 30, mfa_available=False, burst_detected=True) == "EMAIL_VERIFICATION_REQUIRED"


def test_burst_detected_does_not_downgrade_an_independent_block():
    # If the risk score already crosses the block threshold on its own,
    # burst detection doesn't soften that back down to a step-up.
    assert _adaptive_decision("ALLOW", 81, mfa_available=True, burst_detected=True) == "BLOCK"


def test_burst_detected_never_overrides_a_policy_deny():
    assert _adaptive_decision("DENY", 0, mfa_available=True, burst_detected=True) == "DENY"


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    session_factory = sessionmaker(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_risk_engine_loads_the_shipped_model_and_scores_in_range(db_session):
    # Exercises the real artifact at app/risk/artifacts/ (produced by
    # ml/training/train.py and checked into the repo) end-to-end, rather than
    # mocking it out - if the artifact is missing or stale this fails loudly.
    user = User(
        username="tester",
        email="tester@example.com",
        password_hash="x",
        role="Finance Employee",
        department="Finance",
        clearance_level="CONFIDENTIAL",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    result = _risk_engine.score(db_session, user, action="READ", device_id="d1", location="HQ")

    assert 0 <= result.score <= 100
    assert result.model_used is True
    assert len(result.reasons) >= 1
