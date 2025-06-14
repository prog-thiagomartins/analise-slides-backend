import pytest
from fastapi.testclient import TestClient
from app.api.routes.auth import db_users
from app.models.user import User
from app.services.password import hash_password
from datetime import datetime, UTC

def test_update_user_success(setup_user_me, client):
    """Atualiza nome do usuário autenticado com sucesso (200)."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"name": "Novo Nome"}
    response = client.put("/users/me", json=data)
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Novo Nome"
    assert body["email"] == "user1@example.com"
    assert body["status"] == "active"

def test_update_user_unauthenticated(client):
    """Retorna 401 ao tentar atualizar usuário sem autenticação."""
    data = {"name": "Novo Nome"}
    response = client.put("/users/me", json=data)
    assert response.status_code == 401
    assert "detail" in response.json()

def test_update_user_cannot_change_status(setup_user_me, client):
    """Não permite alterar status do usuário via update (deve permanecer 'active')."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"name": "Novo Nome", "status": "admin"}
    response = client.put("/users/me", json=data)
    assert response.status_code in (200, 422)
    if response.status_code == 200:
        body = response.json()
        assert body["status"] == "active"

def test_update_user_with_extra_fields(setup_user_me, client):
    """Rejeita campos extras no update do usuário (422) ou ignora se permitido."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"name": "Novo Nome", "foo": "bar"}
    response = client.put("/users/me", json=data)
    assert response.status_code in (200, 422)
    if response.status_code == 200:
        body = response.json()
        assert "foo" not in body

@pytest.mark.parametrize("data,expected_status", [
    # Strings absurdamente longas
    ({"name": "A"*300}, 422),
    # Campos obrigatórios vazios ou só espaços
    ({"name": ""}, 422),
    ({"name": "   "}, 422),
    # Tipos errados
    ({"name": 123}, 422),
    # Campo nulo
    ({"name": None}, 422),
    # Campo extra inesperado
    ({"name": "Novo Nome", "foo": "bar"}, 422),
])
def test_update_user_edge_cases(setup_user_me, client, data, expected_status):
    """Testa casos limite no update: string longa, vazio, tipo errado, nulo, campo extra."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    response = client.put("/users/me", json=data)
    assert response.status_code == expected_status
