import pytest
from fastapi.testclient import TestClient
from app.api.routes.auth import db_users
from app.models.user import User
from app.services.password import hash_password, verify_password
from datetime import datetime, UTC


def test_reset_password_valid_token(monkeypatch, setup_user_reset_password, client):
    """Permite resetar senha com token válido."""
    token = "valid-token-123"
    import app.api.routes.auth as auth_module
    def mock_validate_token_success(token):
        return token == "valid-token-123"
    def mock_get_user_by_token(token):
        return db_users[0] if token == "valid-token-123" else None
    monkeypatch.setattr(auth_module, "validate_reset_token", mock_validate_token_success)
    monkeypatch.setattr(auth_module, "get_user_by_token", mock_get_user_by_token)
    data = {"token": token, "new_password": "NovaSenhaForte123"}
    response = client.post("/auth/reset-password", json=data)
    assert response.status_code == 200
    assert verify_password("NovaSenhaForte123", db_users[0].password_hash)


def test_reset_password_invalid_token(monkeypatch, setup_user_reset_password, client):
    """Retorna 400 para token inválido ou expirado no reset de senha."""
    token = "invalid-token"
    import app.api.routes.auth as auth_module
    def mock_validate_token_fail(token):
        return False
    monkeypatch.setattr(auth_module, "validate_reset_token", mock_validate_token_fail)
    data = {"token": token, "new_password": "NovaSenhaForte123"}
    response = client.post("/auth/reset-password", json=data)
    assert response.status_code == 400
    assert response.json()["detail"] == "Token inválido ou expirado"


def test_reset_password_weak_password(monkeypatch, setup_user_reset_password, client):
    """Retorna 422 para nova senha fraca no reset de senha."""
    token = "valid-token-123"
    import app.api.routes.auth as auth_module
    def mock_validate_token_success(token):
        return token == "valid-token-123"
    def mock_get_user_by_token(token):
        return db_users[0] if token == "valid-token-123" else None
    monkeypatch.setattr(auth_module, "validate_reset_token", mock_validate_token_success)
    monkeypatch.setattr(auth_module, "get_user_by_token", mock_get_user_by_token)
    data = {"token": token, "new_password": "123"}
    response = client.post("/auth/reset-password", json=data)
    assert response.status_code == 422
    assert "senha" in response.json()["detail"].lower()
