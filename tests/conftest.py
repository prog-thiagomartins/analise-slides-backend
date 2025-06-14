import pytest
from app.api.routes.auth import db_users
from app.models.user import User
from app.services.password import hash_password
from tests.factories.user_factory import create_user
from datetime import datetime, UTC
from fastapi.testclient import TestClient
from app.main import app
from tests.mocks.email_mock import mock_send_email, clear_sent_emails
import app.api.routes.auth as auth_module
import logging

logging.getLogger("httpx").setLevel(logging.WARNING)

@pytest.fixture(autouse=True)
def email_mock(monkeypatch):
    monkeypatch.setattr(auth_module, "send_email", mock_send_email)
    clear_sent_emails()
    yield
    clear_sent_emails()

@pytest.fixture
def clean_db():
    """
    Limpa db_users antes e depois do teste. Use explicitamente em testes que precisam de isolamento total.
    Não usar com autouse=True para não interferir em testes que dependem de setup_module/setup_users.
    """
    db_users.clear()
    yield
    db_users.clear()

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def setup_user():
    db_users.clear()
    user = create_user()
    db_users.append(user)
    yield user
    db_users.clear()

@pytest.fixture
def setup_user_me():
    db_users.clear()
    db_users.append(User(
        id="1",
        name="User Teste",
        email="user1@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=["user"],
        password_hash=hash_password("senhaForte123")
    ))
    yield
    db_users.clear()

@pytest.fixture
def setup_user_update_password():
    db_users.clear()
    db_users.append(User(
        id="1",
        name="User Teste",
        email="user1@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=["user"],
        password_hash=hash_password("senhaForte123")
    ))
    yield
    db_users.clear()

@pytest.fixture
def setup_user_reset_password():
    db_users.clear()
    db_users.append(User(
        id="1",
        name="User Teste",
        email="user1@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=["user"],
        password_hash=hash_password("senhaAntiga123")
    ))
    yield
    db_users.clear()

@pytest.fixture
def setup_user_logout():
    db_users.clear()
    user = create_user(email="logout@example.com", password="SenhaLogout123", status="active")
    db_users.append(user)
    yield user
    db_users.clear()

@pytest.fixture
def setup_users():
    db_users.clear()
    user_active = User(
        id="1",
        name="Ativo",
        email="ativo@example.com",
        status="active",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=["user"],
        password_hash=hash_password("senhaAtiva123")
    )
    user_inactive = User(
        id="2",
        name="Inativo",
        email="inativo@example.com",
        status="inactive",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        roles=["user"],
        password_hash=hash_password("senhaInativa123")
    )
    db_users.extend([user_active, user_inactive])
    yield user_active, user_inactive
    db_users.clear()
