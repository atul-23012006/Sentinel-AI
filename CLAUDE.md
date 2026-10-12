# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

**SentinelAI** is an AI-powered adaptive access control / insider threat detection platform (college project for CBS3002 Information Security). `SentinelAI_README.md` at the repo root is the full design spec/proposal (hybrid RBAC+MAC+ABAC+TBAC policy engine, ML anomaly detection, risk scoring, adaptive responses, AI analyst) — read it for the "why" behind any component.

All seven phases from the README's roadmap (§18) are implemented:
- **Phase 1/2 (Foundation + Access Control)** — `backend/app/{auth,users,resources,policies}/`: JWT auth, account lockout, the hybrid policy engine (RBAC+MAC+ABAC+TBAC+OBAC, AND-combined — OBAC lets the *same* resource require different rules per operation, e.g. anyone in-department can READ but only an Administrator can DELETE; rules are admin-managed via `/policies`, `app/policies/router.py`).
- **Phase 3 (Security Monitoring)** — `backend/app/audit/`, `backend/app/alerts/`: centralized audit log + `SecurityAlert` persistence/CRUD; `docs/threat-model.md` maps each README §16 attack scenario to its test.
- **Phase 4 (Machine Learning)** — `ml/`: synthetic dataset generation, Isolation Forest training, evaluation (precision/recall/F1/FPR/ROC-AUC — see `docs/ml-evaluation.md` for the measured numbers, never fabricated).
- **Phase 5 (Adaptive Security)** — `backend/app/risk/`: the live risk engine (rule-based + the trained Isolation Forest, blended) drives `_adaptive_decision()` in `app/resources/router.py` (ALLOW → MFA_REQUIRED → BLOCK), with TOTP step-up auth in `app/auth/router.py` (`/auth/mfa/setup`, `/auth/mfa/verify`).
- **Phase 6 (AI Analyst)** — `backend/app/ai/`: `GET /alerts/{id}/explain`, Anthropic API if `ANTHROPIC_API_KEY` is set, else a deterministic template. Advisory only — never feeds back into an access decision.
- **Phase 7 (Finalization)** — `frontend/` (React + Vite admin console), full Docker Compose (db + backend + frontend), `docs/` (architecture, security-model, threat-model, ml-evaluation), 56 backend tests.

`ml/models/*.joblib` and `ml/data/*.csv` are gitignored (regeneratable — see `docs/ml-evaluation.md` for the commands); the trained artifact the backend actually loads at runtime is committed at `backend/app/risk/artifacts/isolation_forest.joblib` (copied there by `ml/training/train.py`) since nothing retrains it at container startup.

## Intent Layer

This project has grown past a single-file context node. Re-run the intent-layer skill's `estimate_tokens.sh` against `backend/app/` before adding child `AGENTS.md` nodes if it's crossed the 20k-token threshold.

### Global Invariants

- `database/schema.sql` and `app/models.py` are maintained in parallel by hand, not generated from each other — any schema change touches both.
- Every login attempt, MFA verification, and every `HybridPolicyEngine` evaluation (pass or fail) must produce an `access_events` row via `log_access_event` — the audit trail is expected to capture denials/failures, not just successes.
- Policy dimensions (RBAC/MAC/ABAC/TBAC/OBAC) are kept non-overlapping by design (e.g. ABAC does not re-check clearance) — don't "fix" perceived duplication across `evaluate_*` functions without checking whether it's an intentional separation of concerns. OBAC specifically is *opt-in per (resource_id, action)*: a resource/action pair with no matching enabled `Policy` row passes trivially — it adds restrictions on top of RBAC/MAC/ABAC/TBAC, it never loosens them.
- Passwords are capped at 72 bytes before hashing (bcrypt's own truncation limit) — never remove that guard when touching `security.py`.
- A policy `DENY` can never be turned into an `ALLOW` by the risk engine — `_adaptive_decision()` (`app/resources/router.py`) only ever escalates an `ALLOW`, never downgrades a `DENY`. Authorization and behavioral risk are deliberately separate (README §9); don't collapse them into one check.
- `app/risk/features.py`'s `FEATURE_NAMES` order is shared by both the live `RiskEngine` and `ml/training/train.py` (which imports it directly from `backend/`, via a `sys.path` insert — see the top of `ml/training/train.py`). Changing the feature set means updating `features.py`, regenerating the dataset, and retraining — the two can't drift independently.
- `app/ai/service.py` is read-only with respect to access control: it must never be called from anywhere in the decision path (`policies/engine.py`, `risk/engine.py`, `resources/router.py`), only from the `/alerts/{id}/explain` endpoint.

## Commands

All backend commands run from `backend/`. A `.venv` already exists there.

```bash
cd backend
source .venv/bin/activate

# Install/update deps
pip install -r requirements.txt

# Run the full test suite (uses in-memory SQLite, no Postgres needed)
pytest

# Run a single test file / test
pytest tests/test_risk_engine.py
pytest tests/test_adaptive_access.py::test_elevated_risk_requires_mfa_and_step_up_verification_restores_access

# Run the API locally against Postgres (needs DATABASE_URL — see below)
uvicorn app.main:app --reload
```

ML pipeline (run from repo root; needs `ml/requirements.txt` — note this pulls in `pandas`, which `backend/requirements.txt` deliberately omits since the backend only *loads* a trained model, it doesn't train one):

```bash
pip install -r ml/requirements.txt
python3 ml/data/generate_dataset.py   # -> ml/data/dataset.csv
python3 ml/training/train.py          # -> ml/models/ + copies to backend/app/risk/artifacts/
python3 ml/evaluation/evaluate.py     # -> ml/evaluation/results.json
```

Frontend (from `frontend/`):

```bash
npm install
npm run dev     # Vite dev server on :5173, proxies to VITE_API_BASE_URL (see .env.example)
npm run build
```

Full stack (Postgres + backend + frontend) via Docker:

```bash
docker compose up --build
```

This starts Postgres on `5432` (schema auto-applied from `database/schema.sql` on first init), the backend on `8000` with `--reload`, and the frontend dev server on `5173` — all with their source dirs bind-mounted.

Backend config is via env vars / `backend/.env` (see `backend/.env.example` for all keys, including the risk-threshold and `ANTHROPIC_API_KEY` settings added in Phase 4-6). Defaults live in `app/config.py`. Frontend config is `frontend/.env` / `.env.example` (`VITE_API_BASE_URL`).

## Architecture

### Table creation is schema-first, not ORM-first
`database/schema.sql` is the source of truth for the Postgres schema and is applied automatically by the `db` container via `docker-entrypoint-initdb.d`. `app/main.py` deliberately does **not** call `Base.metadata.create_all()` at import/startup — this is so tests can bind their own throwaway engine (see `tests/conftest.py`, which creates an in-memory SQLite DB per test and overrides the `get_db` dependency). If you add a table/column, update **both** `database/schema.sql` and the matching SQLAlchemy model in `app/models.py` — they are not generated from each other. (Note for any manual/ad-hoc scripting against a throwaway DB: `app.models` must actually be imported before `Base.metadata.create_all()` runs, or `Base.metadata` is empty and nothing gets created — `tests/conftest.py` and `app/main.py` both pull it in transitively via their router imports, but a standalone script importing only `app.database` will not.)

### Module layout (`backend/app/`)
Each subpackage is a FastAPI router + (where relevant) a service module, mounted in `main.py`:
- `auth/` — `router.py` (register/login/me + `/mfa/setup`, `/mfa/verify`), `security.py` (bcrypt hashing, JWT encode/decode), `dependencies.py` (`get_current_user`, `require_role(*roles)` for admin-gated endpoints)
- `users/` — CRUD + `PATCH /users/{id}` (admin-only: `device_trust`, `account_status`, `role`, `department`, `clearance_level` — these last three are otherwise only self-declared at registration with no approval step; `device_trust` is the only way to get ABAC's device-trust check to ever PASS, since registration always defaults to `UNTRUSTED`, and `account_status: ACTIVE` is the only way to reactivate a `LOCKED` account)
- `resources/` — CRUD (including admin-only `PATCH`/`DELETE /{id}` to reclassify or remove a resource after creation) + `POST /{id}/access`, the central endpoint: runs the policy engine, the risk engine, `_adaptive_decision()`, logs the event, and raises an alert if warranted; also admin-only `POST/GET/DELETE /{id}/grants` for explicit `ResourceGrant`s (see below)
- `policies/` — `engine.py` (`HybridPolicyEngine`, the core authorization logic, see below), `router.py` (admin-only CRUD on `Policy` rows — today exclusively OBAC rules)
- `risk/` — `features.py` (behavioral feature extraction, shared with `ml/`), `engine.py` (`RiskEngine`: rule-based score blended with the Isolation Forest, `rule_based_score()` is also reused as the AI analyst's "contributing factors" text), `artifacts/` (committed model + metadata)
- `alerts/` — `service.py` (`create_alert_if_needed`, severity banded off the same thresholds as the adaptive decision), `router.py` (admin CRUD + `/explain`)
- `ai/` — `service.py` (`explain_alert`: Anthropic API or template fallback — see Global Invariants above for its read-only constraint)
- `audit/` — `service.py` (`log_access_event`, called by every auth/access/MFA code path), `router.py` (admin-only query endpoints: `/audit/events`, `/audit/events/{id}`, `/audit/summary`)
- `models.py` — all SQLAlchemy ORM models (`User`, `Resource`, `Policy`, `AccessEvent`, `SecurityAlert`) in one file
- `schemas.py` — all Pydantic request/response models in one file
- `config.py` — single `Settings` (pydantic-settings) object imported as `from app.config import settings`

### Hybrid policy engine (`app/policies/engine.py`)
`HybridPolicyEngine.evaluate(user, resource, action="READ", db=None, now=None)` runs all five checks and combines them with **AND** — every policy must PASS or the final decision is DENY:
- **RBAC** — `resource.required_role` (if set) must equal `user.role`
- **MAC** — `user.clearance_level` rank must be ≥ `resource.classification` rank (`PUBLIC < CONFIDENTIAL < SECRET < TOP_SECRET`)
- **ABAC** — `user.department == resource.department` AND `user.device_trust == "TRUSTED"` (clearance is intentionally *not* rechecked here — that's MAC's job, kept as a separate dimension)
- **TBAC** — current hour must fall within `[tbac_start_hour, tbac_end_hour)`; accepts an injectable `now` for testability
- **OBAC** — operation-specific override: looks up enabled `Policy` rows with `policy_type='OBAC'` whose `rule_definition` matches this `(resource_id, action)` pair (highest `priority` wins among matches) and checks `required_role`/`min_clearance` from it; `db=None` (e.g. the pure-function unit tests that never persist their `User`/`Resource`) or no matching rule both PASS trivially — this is the mechanism for "different access controls for different operations on the same resource" (e.g. everyone in-department can `READ` but only `Administrator` can `DELETE`)

On top of those five (AND-combined), `evaluate_grant()` is consulted *only* when they produce `DENY`: an active `ResourceGrant` row for this `(user, resource[, action])` — admin-issued via `POST /resources/{id}/grants`, optionally action-scoped and/or time-limited — overrides the `DENY` to `ALLOW` and is appended to `results` (so `GRANT` shows up in `policy_results` precisely when it mattered, not on every ordinary request). It bypasses RBAC/MAC/ABAC/TBAC/OBAC specifically, never the risk engine — `_adaptive_decision()` downstream still treats a grant-driven `ALLOW` exactly like any other `ALLOW`, so a behaviorally risky action by an explicitly-granted user can still be escalated to `MFA_REQUIRED`/`BLOCK` (see `tests/test_admin_overrides.py::test_grant_does_not_bypass_risk_engine`).

### Risk engine and adaptive decision (`app/risk/engine.py`, `app/resources/router.py`)
`RiskEngine.score()` extracts a 9-feature behavioral vector (`app/risk/features.py`: login hour, events/downloads in the last hour, distinct resources touched, denied-request ratio over 24h, failed-login count, new-device/new-location flags, outside-business-hours flag) from the user's `access_events` history, computes a deterministic rule-based score (README §8's point table) and — if `app/risk/artifacts/isolation_forest.joblib` is present — an Isolation Forest anomaly score, and blends them 40/60. `_adaptive_decision(policy_decision, risk_score)` then maps a policy `ALLOW` to `ALLOW` / `MFA_REQUIRED` (risk ≥ 61) / `BLOCK` (risk ≥ 81) per `settings.risk_*_threshold`; a policy `DENY` is never overridden. `create_alert_if_needed()` raises a `SecurityAlert` whenever risk ≥ 31, severity banded off the same thresholds.

This is invoked from `POST /resources/{id}/access`, and every evaluation (pass or fail) is written to `access_events` via `log_access_event`, regardless of outcome, with the computed `risk_score` attached. Login attempts (unknown user, wrong password, locked account, success) and MFA verifications are logged the same way — the audit trail must capture failed/anomalous activity, not just successful actions.

### Auth flow
JWT-based; `sub` claim is the stringified `user_id`, plus a `role` claim. Passwords are bcrypt-hashed and explicitly capped at 72 bytes (`security.py`) since bcrypt silently truncates beyond that — reject rather than silently allow hash collisions between different long passwords. Account lockout: `failed_login_count` increments on bad password, account flips to `LOCKED` at `settings.max_failed_logins`; an admin reactivates via `PATCH /users/{id}` (`account_status: ACTIVE`), which also resets the counter. `require_role("Administrator")` gates admin-only endpoints (`/users`, `/audit/*`, `/alerts/*`); role names are plain strings, not an enum. Step-up MFA (`/auth/mfa/setup`, `/auth/mfa/verify`) is TOTP via `pyotp`, tied to a specific `MFA_REQUIRED` `access_events` row by `event_id` — verifying upgrades that row to `ALLOW` rather than issuing a new session/token.

### Testing conventions
Every test hits a real `TestClient` against an isolated in-memory SQLite DB (per-test, via the `client` fixture in `conftest.py`) — no mocking of the DB layer, **except** the risk engine's `.score()` method, which is deliberately monkeypatched to a fixed `RiskResult` in most adaptive-security tests (`test_adaptive_access.py`, `test_attack_scenarios.py`'s Test 3) — the ML-blended score's exact value near a threshold boundary is nondeterministic-feeling enough (depends on the trained model) that pinning it in an integration test would be flaky; the real trained model is instead exercised directly (unmocked) in `test_risk_engine.py::test_risk_engine_loads_the_shipped_model_and_scores_in_range`. `test_attack_scenarios.py` maps directly to the "Attack / Test Scenarios" in the README (§16): brute force, credential compromise, mass download/exfiltration, privilege abuse, policy violation. When adding a new access-control rule or attack scenario, prefer extending that mapping rather than creating an unrelated ad hoc test file.
