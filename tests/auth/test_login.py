import pytest
from fastapi.testclient import TestClient
from app.api.routes.auth import db_users
from app.services.password import hash_password
from app.models.user import User
from datetime import datetime, UTC

def test_login_success(client, setup_users):
    """Deve autenticar usuário ativo com dados corretos (200)."""
    user_active, _ = setup_users
    data = {"email": user_active.email, "password": "senhaAtiva123"}
    response = client.post("/auth/login", json=data)
    assert response.status_code == 200
    assert response.cookies.get("session") is not None
    body = response.json()
    assert body["email"] == data["email"]
    assert body["status"] == "active"

def test_login_invalid_password(client, setup_users):
    """Retorna 401 para senha incorreta."""
    user_active, _ = setup_users
    data = {"email": user_active.email, "password": "senhaErrada"}
    response = client.post("/auth/login", json=data)
    assert response.status_code == 401
    assert response.json()["detail"] == "Senha inválida"

def test_login_inactive_user(client, setup_users):
    """Retorna 403 para usuário inativo."""
    _, user_inactive = setup_users
    data = {"email": user_inactive.email, "password": "senhaInativa123"}
    response = client.post("/auth/login", json=data)
    assert response.status_code == 403
    assert response.json()["detail"] == "Usuário inativo"

def test_login_invalid_fields(client, setup_users):
    """Valida campos obrigatórios vazios no login (422)."""
    data = {"email": "", "password": ""}
    response = client.post("/auth/login", json=data)
    assert response.status_code == 422

@pytest.mark.parametrize("data,expected_status", [
    # Strings absurdamente longas
    ({"email": "a"*250+"@example.com", "password": "senhaAtiva123"}, 422),
    ({"email": "ativo@example.com", "password": "A"*300}, 422),
    # Campos obrigatórios vazios ou só espaços
    ({"email": "", "password": "senhaAtiva123"}, 422),
    ({"email": "   ", "password": "senhaAtiva123"}, 422),
    ({"email": "ativo@example.com", "password": ""}, 422),
    ({"email": "ativo@example.com", "password": "   "}, 422),
    # Tipos errados
    ({"email": 123, "password": "senhaAtiva123"}, 422),
    ({"email": "ativo@example.com", "password": 123}, 422),
    # Campos nulos
    ({"email": None, "password": "senhaAtiva123"}, 422),
    ({"email": "ativo@example.com", "password": None}, 422),
])
def test_login_edge_cases(client, setup_users, data, expected_status):
    """Testa casos limite no login: strings longas, tipos errados, nulos, vazios."""
    response = client.post("/auth/login", json=data)
    assert response.status_code == expected_status
