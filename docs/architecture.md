# SentinelAI — Architecture

## Request flow

```
Client (frontend/, React)
    |
    v
POST /resources/{id}/access  (backend/app/resources/router.py)
    |
    +--> HybridPolicyEngine.evaluate()        (app/policies/engine.py)
    |        RBAC -> MAC -> ABAC -> TBAC, combined with AND
    |
    +--> RiskEngine.score()                   (app/risk/engine.py)
    |        app/risk/features.py extracts a 9-feature behavioral vector
    |        from this user's access_events history, then:
    |          - rule_based_score(): deterministic point table (README §8)
    |          - Isolation Forest .decision_function() (ml/training/train.py,
    |            shipped as app/risk/artifacts/isolation_forest.joblib)
    |        final risk_score = 0.6 * ml_score + 0.4 * rule_score
    |
    +--> _adaptive_decision(policy_decision, risk_score)
    |        policy DENY always wins; a policy ALLOW can still be escalated
    |        to MFA_REQUIRED (risk >= 61) or BLOCK (risk >= 81)
    |
    +--> log_access_event()                   (app/audit/service.py)
    |        every evaluation, pass or fail, is written to access_events
    |
    +--> create_alert_if_needed()              (app/alerts/service.py)
             risk >= 31 raises a SecurityAlert (severity scales with score)
```

A user escalated to `MFA_REQUIRED` completes step-up authentication via
`GET /auth/mfa/setup` + `POST /auth/mfa/verify` (TOTP, `app/auth/router.py`),
which upgrades the original `access_events` row to `ALLOW` and logs the
verification itself.

An admin can later call `GET /alerts/{id}/explain` (`app/ai/service.py`) to
get a plain-language incident summary — from the Anthropic API if
`ANTHROPIC_API_KEY` is set, otherwise a deterministic template. This layer is
read-only: it never feeds back into an access decision.

## Why the risk engine blends rule-based and ML scores

A pure ML score is accurate but opaque; a pure rule-based score is
explainable but brittle (can only catch patterns someone thought to encode).
Blending both means every risk score still comes with a human-readable list
of contributing factors (used directly in alert descriptions and AI
explanations) while the Isolation Forest can still catch anomalies the rule
table doesn't explicitly enumerate. See the Literature Review in Review 1 for
the papers this design choice is based on.

## Why the model ships as a committed artifact, not trained at startup

`ml/` is a separate pipeline (own `requirements.txt`, run manually or in CI)
from `backend/`, which only needs `scikit-learn` + `joblib` to *load* a model,
not `pandas`/training dependencies. `ml/training/train.py` copies its output
directly into `backend/app/risk/artifacts/`, which is checked into the repo
(unlike `ml/models/`, which is gitignored and regeneratable) so a fresh
`docker compose up` has a working risk engine without a manual training step.
If the artifact is ever missing, `RiskEngine` degrades to the rule-based
score alone rather than failing (see `app/risk/engine.py`).

## Directory map

```
backend/app/
  auth/        authentication, JWT, TOTP step-up (MFA)
  users/       user CRUD + admin device-trust/account-status management
  resources/   resource CRUD + the main /access endpoint (policy + risk + adaptive decision)
  policies/    HybridPolicyEngine (RBAC/MAC/ABAC/TBAC)
  risk/        features.py + engine.py (rule-based + Isolation Forest blend) + artifacts/
  alerts/      SecurityAlert creation + admin CRUD + /explain
  ai/          AI Security Analyst (template fallback / Anthropic API)
  audit/       centralized access_events logging + admin query endpoints

ml/
  data/        synthetic labeled dataset generator (README §16 attack patterns)
  training/    IsolationForest training -> ml/models/ + copied to backend/app/risk/artifacts/
  evaluation/  precision/recall/F1/FPR/ROC-AUC/confusion matrix -> results.json

frontend/      React + Vite admin console (login, access simulator, alerts, audit log, user admin)
```
