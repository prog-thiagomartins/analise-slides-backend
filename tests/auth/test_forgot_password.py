import pytest
from fastapi.testclient import TestClient
from tests.factories.user_factory import create_user
from tests.mocks.email_mock import sent_emails
from app.api.routes import auth as auth_module

def test_forgot_password_flow(client, setup_user):
    """Envia email de reset ao requisitar esqueci minha senha com email válido."""
    data = {"email": setup_user.email}
    response = client.post("/auth/forgot-password", json=data)
    assert response.status_code == 200
    assert len(sent_emails) == 1
    email = sent_emails[0]
    assert email["to"] == data["email"]
    assert "reset" in email["subject"].lower() or "senha" in email["subject"].lower()
    assert "token" in email["body"]

def test_forgot_password_invalid_email(client):
    """Não envia email se o email não existe na base."""
    data = {"email": "naoexiste@example.com"}
    response = client.post("/auth/forgot-password", json=data)
    assert response.status_code == 200
    assert sent_emails == []
