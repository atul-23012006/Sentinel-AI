from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.alerts.router import router as alerts_router
from app.audit.router import router as audit_router
from app.auth.router import router as auth_router
from app.policies.router import router as policies_router
from app.resources.router import router as resources_router
from app.users.router import router as users_router

# Table creation is handled by database/schema.sql (applied automatically
# by the db container on first start, see docker-compose.yml). The app
# does not create tables itself so that tests can bind a separate engine.

app = FastAPI(title="SentinelAI", version="0.1.0")

# Admin dashboard (frontend/) runs on a separate origin in dev (Vite on 5173).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(resources_router)
app.include_router(audit_router)
app.include_router(alerts_router)
app.include_router(policies_router)


@app.get("/health")
def health():
    return {"status": "ok"}
