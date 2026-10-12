# SentinelAI

**AI-powered adaptive access control & insider threat detection.** A college security project (CBS3002 — Information Security) that goes beyond standard access control: most systems only ask *"is this user authorized?"* — SentinelAI adds a second layer asking *"does this authorized user's current behavior still look safe?"*

It combines a five-dimension hybrid policy engine (RBAC + MAC + ABAC + TBAC + OBAC, plus admin-issued explicit grants) with a machine-learning behavioral risk engine, so that even a valid, logged-in account can get challenged or blocked if it starts acting like a compromised credential or an insider abusing access.

## Features

- **Hybrid policy engine** — RBAC, MAC, ABAC, TBAC evaluated together (AND-combined), plus **OBAC** for per-operation rules on the same resource (e.g. everyone in-department can `READ`, only an `Administrator` can `DELETE`), plus admin-issued **explicit grants** that can override a denial for one specific user/resource/action.
- **Behavioral risk engine** — a trained Isolation Forest (measured F1 90.5%, recall 98.8%, ROC-AUC 0.99 — see [`docs/ml-evaluation.md`](docs/ml-evaluation.md)) blended with a deterministic rule-based score, driving adaptive responses: `ALLOW` → `MFA_REQUIRED` (TOTP step-up) → `BLOCK`.
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

### Manual

**Backend** (needs a reachable Postgres — apply `database/schema.sql` once):

```bash
cd backend
source .venv/bin/activate   # or: python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # edit DATABASE_URL if needed
uvicorn app.main:app --reload
```

**Frontend**:

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

### Tests

```bash
cd backend && source .venv/bin/activate && pytest
```

Uses an in-memory SQLite DB — no Postgres required, 78 tests covering the policy engine, risk engine, adaptive security, MFA, alerts, AI analyst, and admin overrides.

### ML pipeline (optional — a trained model is already committed)

```bash
pip install -r ml/requirements.txt
python3 ml/data/generate_dataset.py
python3 ml/training/train.py       # -> backend/app/risk/artifacts/
python3 ml/evaluation/evaluate.py  # -> ml/evaluation/results.json
```

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
