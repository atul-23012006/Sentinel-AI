import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base, get_db
from app.main import app

TEST_DATABASE_URL = "sqlite:///:memory:"


@pytest.fixture()
def client():
    # StaticPool: the FastAPI TestClient dispatches requests on a worker
    # thread, so an in-memory sqlite db needs a single shared connection
    # (the default pool hands out a fresh, empty db per thread).
    engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # Every existing test assumes a registered user can log in immediately -
    # tests that specifically exercise admin-gated registration turn this
    # back on with monkeypatch (same pattern as tbac_start_hour/end_hour
    # elsewhere in this suite).
    original_require_admin_approval = settings.require_admin_approval
    settings.require_admin_approval = False

    with TestClient(app) as test_client:
        yield test_client

    settings.require_admin_approval = original_require_admin_approval
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)
