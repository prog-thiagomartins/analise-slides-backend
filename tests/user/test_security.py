import pytest
from fastapi.testclient import TestClient
from app.main import app

def test_cors_headers():
    """Garante que headers CORS corretos são enviados nas rotas de autenticação."""
    client = TestClient(app)
    origin = "http://example.com"
    response = client.options("/auth/login", headers={"Origin": origin, "Access-Control-Request-Method": "POST"})
    # Quando allow_credentials=True, o valor deve ser igual ao Origin
    assert response.headers.get("access-control-allow-origin") == origin
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cookie_httponly_samesite():
    """Verifica flags de segurança (HttpOnly, SameSite) no cookie de sessão."""
    client = TestClient(app)
    data = {"name": "User Cookie", "email": "cookie@example.com", "password": "SenhaForte123"}
    response = client.post("/auth/register", json=data)
    cookies = response.headers.get("set-cookie")
    assert cookies is not None
    assert "httponly" in cookies.lower()
    assert "samesite=lax" in cookies.lower() or "samesite=strict" in cookies.lower()


def test_sql_injection_protection():
    """Testa proteção contra SQL Injection no login."""
    client = TestClient(app)
    data = {"email": "' OR 1=1 --", "password": "qualquer"}
    response = client.post("/auth/login", json=data)
    assert response.status_code == 401 or response.status_code == 422


def test_xss_protection():
    """Testa proteção contra XSS no registro de usuário."""
    client = TestClient(app)
    data = {"name": "<script>alert(1)</script>", "email": "xss@example.com", "password": "SenhaForte123"}
    response = client.post("/auth/register", json=data)
    assert response.status_code == 422 or "<script>" not in response.text


def test_user_security():
    """Garante que dados sensíveis não vazam na resposta do registro."""
    client = TestClient(app)
    data = {"name": "User Security", "email": "security@example.com", "password": "SenhaForte123"}
    response = client.post("/auth/register", json=data)
    assert response.status_code == 201
    # Não deve vazar dados sensíveis
    assert "password" not in response.text
    assert "hash" not in response.text
