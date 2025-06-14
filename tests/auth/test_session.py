import pytest
from app.core.config import settings

def test_session_cookie(client):
    """Garante que o cookie de sessão é setado no registro."""
    data = {"name": "Sessão Teste", "email": "session@example.com", "password": "SenhaForte123"}
    response = client.post("/auth/register", json=data)
    assert response.status_code == 201
    session_cookie = response.cookies.get("session")
    assert session_cookie is not None
    assert session_cookie != ""


def test_session_cookie_login(client):
    """Garante que o cookie de sessão é setado no login."""
    # Primeiro registra
    data = {"name": "Sessão Login", "email": "login@example.com", "password": "SenhaForte123"}
    client.post("/auth/register", json=data)
    # Agora faz login
    login_data = {"email": "login@example.com", "password": "SenhaForte123"}
    response = client.post("/auth/login", json=login_data)
    assert response.status_code == 200
    session_cookie = response.cookies.get("session")
    assert session_cookie is not None
    assert session_cookie != ""


def test_session_cookie_flags(client):
    """Verifica flags de segurança (HttpOnly, SameSite, Secure) no cookie de sessão ao registrar."""
    data = {"name": "Sessão Flags", "email": "flags@example.com", "password": "SenhaForte123"}
    response = client.post("/auth/register", json=data)
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    assert "HttpOnly" in cookies
    assert any(site in cookies.lower() for site in ["samesite=lax", "samesite=strict"])
    if settings.ENVIRONMENT == "production":
        assert "secure" in cookies.lower()
    else:
        assert "secure" not in cookies.lower()


def test_session_cookie_flags_login(client):
    """Verifica flags de segurança no cookie de sessão ao logar."""
    # Primeiro registra
    data = {"name": "Sessão Flags Login", "email": "flagslogin@example.com", "password": "SenhaForte123"}
    client.post("/auth/register", json=data)
    # Agora faz login
    login_data = {"email": "flagslogin@example.com", "password": "SenhaForte123"}
    response = client.post("/auth/login", json=login_data)
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    assert "HttpOnly" in cookies
    assert any(site in cookies.lower() for site in ["samesite=lax", "samesite=strict"])
    if settings.ENVIRONMENT == "production":
        assert "secure" in cookies.lower()
    else:
        assert "secure" not in cookies.lower()
