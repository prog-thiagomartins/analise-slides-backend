import pytest
from fastapi.testclient import TestClient
from app.main import app

def test_register_success(client):
    """Deve registrar usuário com dados válidos e retornar status 201."""
    data = {"name": "User Teste", "email": "user1@example.com", "password": "senhaForte123"}
    response = client.post("/auth/register", json=data)
    assert response.status_code == 201
    assert response.cookies.get("session") is not None
    body = response.json()
    assert body["success"] is True
    assert body["data"]["email"] == data["email"]
    assert body["data"]["name"] == data["name"]
    assert body["data"]["status"] == "active"


def test_register_duplicate_email(client):
    """Não permite registro com email já cadastrado (409)."""
    data = {"name": "User Teste", "email": "user2@example.com", "password": "senhaForte123"}
    client.post("/auth/register", json=data)
    response = client.post("/auth/register", json=data)
    assert response.status_code == 409
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["msg"] == "E-mail já cadastrado."


@pytest.mark.parametrize("data", [
    {"name": "A", "email": "user3@example.com", "password": "senhaForte123"},  # nome inválido
    {"name": "User Teste", "email": "user4@example.com", "password": "123"},   # senha fraca
    {"name": "User Teste", "email": "not-an-email", "password": "senhaForte123"}  # email inválido
])
def test_register_invalid_fields(client, data):
    """Valida campos inválidos (nome, senha fraca, email inválido) retornando 422."""
    response = client.post("/auth/register", json=data)
    assert response.status_code == 422


def test_register_with_extra_fields(client):
    """Rejeita campos extras no payload (422) ou ignora se permitido."""
    data = {
        "name": "User Teste",
        "email": "userextra@example.com",
        "password": "senhaForte123",
        "hacker": "malicious"
    }
    response = client.post("/auth/register", json=data)

    if response.status_code == 201:
        body = response.json()
        assert "hacker" not in body["data"]  # Campo extra deve ser ignorado
    elif response.status_code == 422:
        detail = response.json()["errors"]
        assert any(
            (err.get("type") == "extra_forbidden" or "extra" in err.get("type", ""))
            for err in (detail if isinstance(detail, list) else [detail])
        )
    else:
        pytest.fail(f"Resposta inesperada: {response.status_code}")


@pytest.mark.parametrize("data,expected_status", [
    # Strings absurdamente longas
    ({"name": "A"*300, "email": "userlong@example.com", "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": "a"*250+"@example.com", "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": "userlong@example.com", "password": "A"*300}, 422),
    # Campos obrigatórios vazios ou só espaços
    ({"name": "", "email": "userempty@example.com", "password": "senhaForte123"}, 422),
    ({"name": "   ", "email": "userempty@example.com", "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": "", "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": "   ", "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": "userempty@example.com", "password": ""}, 422),
    ({"name": "User Teste", "email": "userempty@example.com", "password": "   "}, 422),
    # Tipos errados
    ({"name": 123, "email": "userwrongtype@example.com", "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": 123, "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": "userwrongtype@example.com", "password": 123}, 422),
    # Campos nulos
    ({"name": None, "email": "usernull@example.com", "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": None, "password": "senhaForte123"}, 422),
    ({"name": "User Teste", "email": "usernull@example.com", "password": None}, 422),
])
def test_register_invalid_payloads(client, data, expected_status):
    """Testa casos limite: strings longas, campos vazios, tipos errados, nulos."""
    response = client.post("/auth/register", json=data)
    assert response.status_code == expected_status


def test_login_serialization_empty_roles(client):
    """Garante que roles sempre é lista (nunca None) no login/register."""
    # Cria usuário sem roles explicitamente
    data = {"name": "Sem Roles", "email": "semroles@example.com", "password": "SenhaForte123"}
    resp = client.post("/auth/register", json=data)
    assert resp.status_code == 201
    body = resp.json()
    assert "roles" in body["data"]
    assert isinstance(body["data"]["roles"], list)

    # Login
    login = client.post("/auth/login", json={"email": data["email"], "password": data["password"]})
    assert login.status_code == 200
    login_body = login.json()
    assert "roles" in login_body["data"]
    assert isinstance(login_body["data"]["roles"], list)


def test_me_serialization_empty_roles(client):
    """Garante que roles sempre é lista (nunca None) no /users/me."""
    # Cria usuário
    data = {"name": "Me Roles", "email": "meroles@example.com", "password": "SenhaForte123"}
    resp = client.post("/auth/register", json=data)
    assert resp.status_code == 201
    login = client.post("/auth/login", json={"email": data["email"], "password": data["password"]})
    assert login.status_code == 200
    client.cookies.set("session", login.cookies.get("session"))
    me = client.get("/users/me")
    assert me.status_code == 200
    me_body = me.json()
    assert "roles" in me_body["data"]
    assert isinstance(me_body["data"]["roles"], list)


def test_error_serialization_detail_string(client):
    """Garante que detail de erro sempre é string ou lista de strings."""
    # Tenta registrar com email inválido
    data = {"name": "Teste", "email": "invalido", "password": "SenhaForte123"}
    resp = client.post("/auth/register", json=data)
    assert resp.status_code == 422
    detail = resp.json()["errors"]
    if isinstance(detail, list):
        for err in detail:
            assert isinstance(err.get("msg", ""), str)
    else:
        assert isinstance(detail, str)
