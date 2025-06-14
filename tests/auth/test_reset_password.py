import pytest
from fastapi.testclient import TestClient
from app.models.user import User
from app.services.password import hash_password, verify_password
from datetime import datetime, UTC
from app.models.user import UserORM
from app.core.config import SessionLocal


def test_reset_password_valid_token(monkeypatch, setup_user_reset_password, client):
    """Permite resetar senha com token válido."""
    token = "valid-token-123"
    import app.api.routes.auth as auth_module
    def mock_validate_token_success(token):
        return token == "valid-token-123"
    monkeypatch.setattr(auth_module, "validate_reset_token", mock_validate_token_success)
    data = {"token": token, "new_password": "NovaSenhaForte123"}
    response = client.post("/auth/reset-password", json=data)
    assert response.status_code == 200
    db = SessionLocal()
    user = db.query(UserORM).filter(UserORM.email == "user1@example.com").first()
    assert user is not None
    assert verify_password("NovaSenhaForte123", user.password_hash)
    db.close()


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
    monkeypatch.setattr(auth_module, "validate_reset_token", mock_validate_token_success)
    data = {"token": token, "new_password": "123"}
    response = client.post("/auth/reset-password", json=data)
    assert response.status_code == 422
    assert "senha" in response.json()["detail"].lower()


def test_reset_password_expired_token(client):
    """Deve falhar ao tentar resetar senha com token expirado."""
    from app.models.user import UserORM
    from app.core.config import SessionLocal
    from datetime import datetime, timedelta
    db = SessionLocal()
    db.query(UserORM).delete()
    db.commit()
    expired_token = "expired-token-123"
    user_orm = UserORM(
        id="2",
        name="User Expirado",
        email="expirado@example.com",
        status="active",
        created_at=datetime.now(),
        updated_at=datetime.now(),
        roles='["user"]',
        password_hash=hash_password("senhaAntiga123"),
        reset_token=expired_token,
        reset_token_expires_at=datetime.now(UTC) - timedelta(hours=1)
    )
    db.add(user_orm)
    db.commit()
    db.close()
    data = {"token": expired_token, "new_password": "NovaSenhaForte123"}
    response = client.post("/auth/reset-password", json=data)
    assert response.status_code == 400
    assert "expirad" in response.text.lower() or "expired" in response.text.lower()
