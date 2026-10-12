from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Policy, Resource, ResourceGrant, User

CLEARANCE_RANK = {"PUBLIC": 0, "CONFIDENTIAL": 1, "SECRET": 2, "TOP_SECRET": 3}


@dataclass
class PolicyResult:
    policy_type: str  # RBAC | MAC | ABAC | TBAC
    decision: str  # PASS | FAIL
    reason: str


@dataclass
class PolicyEvaluation:
    results: list[PolicyResult]
    final_decision: str  # ALLOW | DENY

    @property
    def failures(self) -> list[PolicyResult]:
        return [r for r in self.results if r.decision == "FAIL"]


def evaluate_rbac(user: User, resource: Resource) -> PolicyResult:
    if not resource.required_role:
        return PolicyResult("RBAC", "PASS", "Resource has no role restriction")
    if user.role == resource.required_role:
        return PolicyResult("RBAC", "PASS", f"User role '{user.role}' matches required role")
    return PolicyResult(
        "RBAC", "FAIL", f"Resource requires role '{resource.required_role}', user has role '{user.role}'"
    )


def evaluate_mac(user: User, resource: Resource) -> PolicyResult:
    user_rank = CLEARANCE_RANK[user.clearance_level]
    resource_rank = CLEARANCE_RANK[resource.classification]
    if user_rank >= resource_rank:
        return PolicyResult(
            "MAC", "PASS", f"User clearance '{user.clearance_level}' meets '{resource.classification}'"
        )
    return PolicyResult(
        "MAC",
        "FAIL",
        f"User clearance '{user.clearance_level}' is below resource classification '{resource.classification}'",
    )


def evaluate_abac(user: User, resource: Resource) -> PolicyResult:
    # Scoped to department + device trust; clearance is MAC's responsibility so it
    # is intentionally not re-checked here to keep each policy dimension distinct.
    if user.department != resource.department:
        return PolicyResult(
            "ABAC", "FAIL", f"User department '{user.department}' does not match resource department '{resource.department}'"
        )
    if user.device_trust != "TRUSTED":
        return PolicyResult("ABAC", "FAIL", f"Device trust is '{user.device_trust}', TRUSTED required")
    return PolicyResult("ABAC", "PASS", "Department and device trust checks satisfied")


def evaluate_obac(db: Session | None, user: User, resource: Resource, action: str) -> PolicyResult:
    """Operation-Based Access Control: lets the SAME resource require
    different access rules for different operations, e.g. anyone in-department
    may READ a file but only an Administrator may DELETE it - something
    RBAC/MAC/ABAC/TBAC can't express since none of them are action-aware.

    Rules are rows in the `policies` table with policy_type='OBAC' and
    rule_definition = {"resource_id": int, "action": str,
    "required_role": str | None, "min_clearance": str | None}, managed via
    POST/GET/PATCH/DELETE /policies (app/policies/router.py). If several
    enabled rules match the same (resource_id, action), the highest-priority
    one wins. No matching rule -> PASS (no extra restriction beyond the other
    three dimensions) - OBAC is opt-in per resource/action, not a default-deny.

    `db` is optional (None) so the pure-function unit tests in
    tests/test_policy_engine.py that construct in-memory User/Resource
    objects (never persisted, so resource.resource_id is None) don't need a
    live database just to exercise RBAC/MAC/ABAC/TBAC - OBAC simply has
    nothing to look up in that case and passes.
    """
    if db is None or resource.resource_id is None:
        return PolicyResult("OBAC", "PASS", "No operation-specific policy evaluated (no database context)")

    rules = (
        db.query(Policy)
        .filter(Policy.policy_type == "OBAC", Policy.enabled.is_(True))
        .order_by(Policy.priority.desc())
        .all()
    )
    rule = next(
        (
            r
            for r in rules
            if r.rule_definition.get("resource_id") == resource.resource_id
            and r.rule_definition.get("action") == action
        ),
        None,
    )
    if rule is None:
        return PolicyResult("OBAC", "PASS", f"No operation-specific policy for action '{action}' on this resource")

    required_role = rule.rule_definition.get("required_role")
    if required_role and user.role != required_role:
        return PolicyResult(
            "OBAC",
            "FAIL",
            f"Action '{action}' on this resource requires role '{required_role}' "
            f"(policy '{rule.policy_name}'), user has '{user.role}'",
        )

    min_clearance = rule.rule_definition.get("min_clearance")
    if min_clearance and CLEARANCE_RANK[user.clearance_level] < CLEARANCE_RANK[min_clearance]:
        return PolicyResult(
            "OBAC",
            "FAIL",
            f"Action '{action}' on this resource requires clearance >= '{min_clearance}' "
            f"(policy '{rule.policy_name}'), user has '{user.clearance_level}'",
        )

    return PolicyResult("OBAC", "PASS", f"Operation-specific policy '{rule.policy_name}' satisfied")


def evaluate_tbac(now: datetime | None = None) -> PolicyResult:
    current = now or datetime.now(timezone.utc)
    if settings.tbac_start_hour <= current.hour < settings.tbac_end_hour:
        return PolicyResult("TBAC", "PASS", f"Access at {current.hour:02d}:00 is within allowed hours")
    return PolicyResult(
        "TBAC",
        "FAIL",
        f"Access at {current.hour:02d}:00 is outside allowed hours "
        f"({settings.tbac_start_hour:02d}:00-{settings.tbac_end_hour:02d}:00)",
    )


def evaluate_grant(db: Session | None, user: User, resource: Resource, action: str) -> PolicyResult:
    """Explicit, admin-issued exception (README-extension: "give this user
    access to this resource directly"). An active ResourceGrant for this
    (user, resource[, action]) overrides a policy DENY from RBAC/MAC/ABAC/
    TBAC/OBAC - a deliberate bypass, not a 6th attribute-based dimension.
    It is only ever consulted by HybridPolicyEngine.evaluate() when the other
    five dimensions already produced DENY (see below) - a grant can rescue an
    otherwise-denied request, it never has anything to do when they already
    passed. It does NOT affect the risk engine: a grant changes authorization,
    not behavioral trust (README §9's separation still applies).
    """
    if db is None or resource.resource_id is None:
        return PolicyResult("GRANT", "FAIL", "No explicit grant evaluated (no database context)")

    now = datetime.now(timezone.utc)
    grants = (
        db.query(ResourceGrant)
        .filter(ResourceGrant.user_id == user.user_id, ResourceGrant.resource_id == resource.resource_id)
        .all()
    )

    def not_expired(expires_at: datetime | None) -> bool:
        if expires_at is None:
            return True
        # SQLite (used in tests) doesn't round-trip tzinfo on DateTime(timezone=True)
        # columns, so a value read back can be naive even though it was written aware.
        aware = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
        return aware > now

    matching = [g for g in grants if (g.action is None or g.action == action) and not_expired(g.expires_at)]
    if not matching:
        return PolicyResult("GRANT", "FAIL", "No explicit access grant found for this user/resource/action")

    grant = matching[0]
    scope = f"action '{grant.action}'" if grant.action else "all actions"
    expiry = f", expires {grant.expires_at.isoformat()}" if grant.expires_at else ""
    reason_text = f" - reason: {grant.reason}" if grant.reason else ""
    return PolicyResult(
        "GRANT",
        "PASS",
        f"Explicit access grant (admin-issued) covering {scope}{expiry}{reason_text}",
    )


class HybridPolicyEngine:
    """Evaluates RBAC, MAC, ABAC, TBAC and OBAC together (AND composition, per
    README §5); an explicit admin ResourceGrant can additionally override a
    DENY from those five (see evaluate_grant above).
    """

    def evaluate(
        self,
        user: User,
        resource: Resource,
        action: str = "READ",
        db: Session | None = None,
        now: datetime | None = None,
    ) -> PolicyEvaluation:
        results = [
            evaluate_rbac(user, resource),
            evaluate_mac(user, resource),
            evaluate_abac(user, resource),
            evaluate_tbac(now),
            evaluate_obac(db, user, resource, action),
        ]
        final_decision = "ALLOW" if all(r.decision == "PASS" for r in results) else "DENY"

        if final_decision == "DENY":
            grant_result = evaluate_grant(db, user, resource, action)
            if grant_result.decision == "PASS":
                results.append(grant_result)
                final_decision = "ALLOW"

        return PolicyEvaluation(results=results, final_decision=final_decision)
