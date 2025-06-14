import pytest
from fastapi.testclient import TestClient
from app.models.user import User
from app.models.user import UserORM
from app.services.password import hash_password
from app.core.config import SessionLocal
from datetime import datetime, UTC

def clear_users():
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    db.close()


def test_me_authenticated(client, setup_user):
    db = SessionLocal()
    user = db.query(UserORM).first()
    assert user is not None
    db.close()
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    response = client.get("/users/me")
    assert response.status_code == 200
    body = response.json()
    assert body["data"]["email"] == "user1@example.com"
    assert body["data"]["name"] == "User Teste"
    assert body["data"]["status"] == "active"


def test_me_unauthenticated(client):
    """Retorna 401 ao acessar /users/me sem autenticação."""
    response = client.get("/users/me")
    assert response.status_code == 401
    assert "detail" in response.json()


def test_me_sql_injection(client):
    """Testa proteção contra SQL Injection no endpoint /users/me."""
    # Simula um ataque SQLi no cookie de sessão
    malicious_cookie = "' OR '1'='1"
    client.cookies.set("session", malicious_cookie)
    response = client.get("/users/me")
    assert response.status_code == 401 or response.status_code == 422


def test_me_xss_protection():
    """Testa proteção contra XSS no nome do usuário (model User)."""
    import pytest
    from app.models.user import User
    from app.services.password import hash_password
    from datetime import datetime, UTC
    clear_users()
    with pytest.raises(Exception) as excinfo:
        User(
            id="2",
            name="<script>alert('xss')</script>",
            email="xss@example.com",
            status="active",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            roles=["user"],
            password_hash=hash_password("senhaForte123")
        )
    assert "Nome não pode conter tags HTML" in str(excinfo.value)


def test_register_xss_protection(client):
    """Testa proteção contra XSS no endpoint de registro."""
    data = {
        "name": "<script>alert(1)</script>",
        "email": "xss@example.com",
        "password": "SenhaForte123"
    }
    response = client.post("/auth/register", json=data)
    assert response.status_code in (201, 422)
    if response.status_code == 201:
        assert "<script>" not in response.text
