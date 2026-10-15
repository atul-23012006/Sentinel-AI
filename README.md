# SentinelAI

**AI-powered adaptive access control & insider threat detection.** A college security project (CBS3002 — Information Security) that goes beyond standard access control: most systems only ask *"is this user authorized?"* — SentinelAI adds a second layer asking *"does this authorized user's current behavior still look safe?"*

It combines a five-dimension hybrid policy engine (RBAC + MAC + ABAC + TBAC + OBAC, plus admin-issued explicit grants) with a machine-learning behavioral risk engine, so that even a valid, logged-in account can get challenged or blocked if it starts acting like a compromised credential or an insider abusing access.

## Features

- **Hybrid policy engine** — RBAC, MAC, ABAC, TBAC evaluated together (AND-combined), plus **OBAC** for per-operation rules on the same resource (e.g. everyone in-department can `READ`, only an `Administrator` can `DELETE`), plus admin-issued **explicit grants** that can override a denial for one specific user/resource/action.
- **Behavioral risk engine** — a trained Isolation Forest (measured F1 90.5%, recall 98.8%, ROC-AUC 0.99 — see [`docs/ml-evaluation.md`](docs/ml-evaluation.md)) blended with a deterministic rule-based score, driving adaptive responses: `ALLOW` → step-up (TOTP MFA, or a one-time emailed code if MFA isn't set up) → `BLOCK`.
- **Repeated-abuse lockout & burst detection** — enough step-up challenges/blocks in a row, or too many raw access attempts in too short a window (independent of the risk score), auto-locks the account and raises a `CRITICAL` alert, pending admin reactivation.
- **Security alerts & AI analyst** — automatic alerting on risky behavior, plus an AI-generated plain-language incident explanation (Anthropic API, with a template fallback) — advisory only, never overrides a policy decision.
- **Centralized audit log** — every login, access request, and MFA verification is recorded, pass or fail.
- **Admin console** — a React/Vite dashboard: access simulator, alerts queue, audit log, user/resource administration.

See [`docs/architecture.md`](docs/architecture.md) for the full request-flow diagram, [`docs/threat-model.md`](docs/threat-model.md) and [`docs/security-model.md`](docs/security-model.md) for the security design, and [`SentinelAI_README.md`](SentinelAI_README.md) for the original full design spec.

## Tech stack

Python / FastAPI / SQLAlchemy · PostgreSQL · scikit-learn (Isolation Forest) · React / Vite · Docker Compose

## Quick start

### Docker Compose (easiest — full stack)

```bash
docker compose up --build
```

Starts Postgres (`:5432`, schema auto-applied), the backend (`:8000`), and the frontend (`:5173`). Open **http://localhost:5173**.

### Manual (no Docker — e.g. a native local Postgres install)

Needs Postgres already running locally, with `database/schema.sql` applied once to a `sentinelai` database.

**1. Backend** (own terminal):

```bash
cd backend
source .venv/bin/activate   # or: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cp .env.example .env        # edit DATABASE_URL if your Postgres user/password differ
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**2. Frontend** (separate terminal):

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Then open **http://localhost:5173**. The backend's interactive API docs are at **http://localhost:8000/docs**.

> **Don't start a second `uvicorn`/`vite` in another terminal without stopping the first** — two processes bound to the same port at once causes hard-to-diagnose CORS/login failures. If a server seems stuck or broken, stop it (`Ctrl+C` in its terminal, or `lsof -nP -iTCP:8000 -sTCP:LISTEN` / `:5173` to find a stray process) and start it again rather than launching a duplicate.

**Demo accounts**: `python3 scripts/seed_demo_users.py` (run with the backend already up) seeds one user per role × clearance level, all sharing the password printed at the end — useful for exercising RBAC/MAC without registering accounts by hand.

### Tests

```bash
cd backend && source .venv/bin/activate && pytest
```

Uses an in-memory SQLite DB — no Postgres required, 85 tests covering the policy engine, risk engine, adaptive security (MFA + email step-up, repeated-abuse lockout, burst detection), alerts, AI analyst, and admin overrides.

### ML pipeline (optional — a trained model is already committed)

```bash
pip install -r ml/requirements.txt
python3 ml/data/generate_dataset.py
python3 ml/training/train.py       # -> backend/app/risk/artifacts/
python3 ml/evaluation/evaluate.py  # -> ml/evaluation/results.json
```

## Trying the adaptive security features

Via **http://localhost:8000/docs** (or the frontend's access simulator):

- **Step-up MFA / email verification**: trigger elevated risk on `POST /resources/{id}/access` (e.g. an unfamiliar `device_id`/`location`, or enough prior activity) — the response's `final_decision` becomes `MFA_REQUIRED` (if you've set up TOTP via `/auth/mfa/setup`) or `EMAIL_VERIFICATION_REQUIRED` otherwise. With no SMTP configured, the one-time code is logged to the backend console instead of actually emailed.
- **Burst detection**: call `POST /resources/{id}/access` on the same resource **10 times within a minute** — the 10th call returns `"final_decision": "BLOCK"` and raises a `RAPID_FIRE_ACCESS` alert, independent of behavioral risk score.
- **Repeated-abuse lockout**: enough step-up challenges or blocks in a row (default 5) flips the account to `LOCKED`; an Administrator reactivates it via `PATCH /users/{id}` with `{"account_status": "ACTIVE"}` (or the Users tab in the admin console).

## Project structure

```
backend/   FastAPI app: auth, users, resources, policies, risk, alerts, ai, audit
ml/        Dataset generation, Isolation Forest training, evaluation
frontend/  React + Vite admin console
database/  Postgres schema (source of truth)
docs/      Architecture, security model, threat model, ML evaluation
```

## Author

Atul Bharadwaj — Reg. No. 24BBS0007
