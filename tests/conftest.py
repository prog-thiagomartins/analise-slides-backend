import pytest
from app.models.user import UserORM
from app.services.password import hash_password
from tests.factories.user_factory import create_user
from datetime import datetime, UTC
from fastapi.testclient import TestClient
from app.main import app
from tests.mocks.email_mock import mock_send_email, clear_sent_emails
import app.api.routes.auth as auth_module
from app.core.config import SessionLocal
import logging
import uuid
import json

logging.getLogger("httpx").setLevel(logging.WARNING)

@pytest.fixture(autouse=True)
def email_mock(monkeypatch):
    monkeypatch.setattr(auth_module, "send_email", mock_send_email)
    clear_sent_emails()
    yield
    clear_sent_emails()

@pytest.fixture
def clean_db():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    yield
    db.query(UserORM).delete()
    db.commit()
    db.close()

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def setup_user():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    user = create_user()
    user_orm = UserORM(
        id=str(uuid.uuid4()),
        name=user.name,
        email=user.email,
        status=user.status,
        created_at=user.created_at,
        updated_at=user.updated_at,
        roles=json.dumps(user.roles),
        password_hash=hash_password("senhaForte123")
    )
    db.add(user_orm)
    db.commit()
    db.refresh(user_orm)
    db.close()
    return user_orm

@pytest.fixture
def setup_user_me():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    user_orm = UserORM(
        id="1",
        name="User Teste",
        email="user1@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=json.dumps(["user"]),
        password_hash=hash_password("senhaForte123")
    )
    db.add(user_orm)
    db.commit()
    db.refresh(user_orm)
    db.close()
    yield
    db.query(UserORM).delete()
    db.commit()
    db.close()

@pytest.fixture
def setup_user_update_password():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    user_orm = UserORM(
        id="1",
        name="User Teste",
        email="user1@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=json.dumps(["user"]),
        password_hash=hash_password("senhaForte123")
    )
    db.add(user_orm)
    db.commit()
    db.refresh(user_orm)
    db.close()
    yield
    db.query(UserORM).delete()
    db.commit()
    db.close()

@pytest.fixture
def setup_user_reset_password():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    user_orm = UserORM(
        id="1",
        name="User Teste",
        email="user1@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=json.dumps(["user"]),
        password_hash=hash_password("senhaAntiga123"),
        reset_token="valid-token-123"
    )
    db.add(user_orm)
    db.commit()
    db.refresh(user_orm)
    db.close()
    yield
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    db.close()

@pytest.fixture
def setup_user_logout():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    user = create_user(email="logout@example.com", password="SenhaLogout123", status="active")
    user_orm = UserORM(
        id=str(uuid.uuid4()),
        name=user.name,
        email=user.email,
        status=user.status,
        created_at=user.created_at,
        updated_at=user.updated_at,
        roles=json.dumps(user.roles),
        password_hash=hash_password("SenhaLogout123")  # Corrigido para bater com o teste
    )
    db.add(user_orm)
    db.commit()
    db.refresh(user_orm)
    db.close()
    yield user_orm
    db.query(UserORM).delete()
    db.commit()
    db.close()

@pytest.fixture
def setup_users():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    user_active = UserORM(
        id="1",
        name="Ativo",
        email="ativo@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=json.dumps(["user"]),
        password_hash=hash_password("senhaAtiva123")
    )
    user_inactive = UserORM(
        id="2",
        name="Inativo",
        email="inativo@example.com",
        status="inactive",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=json.dumps(["user"]),
        password_hash=hash_password("senhaInativa123")
    )
    db.add(user_active)
    db.add(user_inactive)
    db.commit()
    db.refresh(user_active)
    db.refresh(user_inactive)
    db.close()
    yield user_active, user_inactive
    db.query(UserORM).delete()
    db.commit()
    db.close()
