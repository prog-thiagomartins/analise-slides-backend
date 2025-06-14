import pytest
from fastapi.testclient import TestClient
from app.services.password import verify_password
from datetime import datetime, UTC
from app.models.user import UserORM
from app.core.config import SessionLocal

def test_update_password_success(setup_user_update_password, client):
    """Atualiza senha do usuário autenticado com sucesso (200)."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"current_password": "senhaForte123", "new_password": "NovaSenhaForte456"}
    response = client.post("/users/update-password", json=data)
    assert response.status_code == 200

    db = SessionLocal()
    user = db.query(UserORM).filter(UserORM.email == "user1@example.com").first()
    assert verify_password("NovaSenhaForte456", user.password_hash)
    db.close()

def test_update_password_same_as_current(setup_user_update_password, client):
    """Retorna 422 se nova senha for igual à atual."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"current_password": "senhaForte123", "new_password": "senhaForte123"}
    response = client.post("/users/update-password", json=data)
    assert response.status_code == 422
    assert "diferente" in response.json()["errors"][0]["msg"].lower()

def test_update_password_unauthenticated(client):
    """Retorna 401 ao tentar atualizar senha sem autenticação."""
    data = {"current_password": "qualquer", "new_password": "outraSenha123"}
    response = client.post("/users/update-password", json=data)
    assert response.status_code == 401
    # Handler global de erro de autenticação pode retornar detail, mas se padronizar, use errors
    resp = response.json()
    assert "errors" in resp or "detail" in resp

def test_update_password_wrong_current(setup_user_update_password, client):
    """Retorna 401 se senha atual estiver incorreta."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"current_password": "senhaErrada", "new_password": "NovaSenha123"}
    response = client.post("/users/update-password", json=data)
    assert response.status_code == 401
    assert "senha" in response.json()["errors"][0]["msg"].lower()

@pytest.mark.parametrize("current_password,new_password,expected_status", [
    ("senhaForte123", "NovaSenha456", 200),
    ("senhaForte123", "senhaForte123", 422),
    ("senhaErrada", "OutraSenha123", 401),
])
def test_update_password_cases(current_password, new_password, expected_status, setup_user_update_password, client):
    """Testa combinações de senha atual/nova: sucesso, igual, errada."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"current_password": current_password, "new_password": new_password}
    response = client.post("/users/update-password", json=data)
    assert response.status_code == expected_status, f"Para current_password={current_password} e new_password={new_password}, esperava status {expected_status}, mas veio {response.status_code}."

def test_update_password_weak_new_password(setup_user_update_password, client):
    """Retorna 422 se nova senha for fraca (curta, inválida)."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    data = {"current_password": "senhaForte123", "new_password": "123"}
    response = client.post("/users/update-password", json=data)
    assert response.status_code == 422
    details = response.json()["errors"]
    if isinstance(details, list):
        assert any("senha" in (err.get("msg", "").lower()) for err in details)
    else:
        assert "senha" in details.lower()

@pytest.mark.parametrize("data,expected_status", [
    # Strings absurdamente longas
    ({"current_password": "senhaForte123", "new_password": "A"*300}, 422),
    # Campos obrigatórios vazios ou só espaços
    ({"current_password": "", "new_password": "NovaSenhaForte456"}, 422),
    ({"current_password": "senhaForte123", "new_password": ""}, 422),
    ({"current_password": "   ", "new_password": "NovaSenhaForte456"}, 422),
    ({"current_password": "senhaForte123", "new_password": "   "}, 422),
    # Tipos errados
    ({"current_password": 123, "new_password": "NovaSenhaForte456"}, 422),
    ({"current_password": "senhaForte123", "new_password": 123}, 422),
    # Campos nulos
    ({"current_password": None, "new_password": "NovaSenhaForte456"}, 422),
    ({"current_password": "senhaForte123", "new_password": None}, 422),
    # Campo extra inesperado
    ({"current_password": "senhaForte123", "new_password": "NovaSenhaForte456", "foo": "bar"}, 422),
])
def test_update_password_edge_cases(setup_user_update_password, client, data, expected_status):
    """Testa casos limite: strings longas, vazias, tipos errados, nulos, campo extra."""
    login_data = {"email": "user1@example.com", "password": "senhaForte123"}
    login_resp = client.post("/auth/login", json=login_data)
    assert login_resp.status_code == 200
    client.cookies.set("session", login_resp.cookies.get("session"))
    response = client.post("/users/update-password", json=data)
    assert response.status_code == expected_status
