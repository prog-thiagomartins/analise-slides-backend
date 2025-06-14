import pytest
from tests.factories.user_factory import create_user
from app.services.password import hash_password


def test_logout(client, setup_user_logout):
    """Remove o cookie de sessão e bloqueia acesso após logout."""
    # Simula login real
    login = client.post("/auth/login", json={"email": setup_user_logout.email, "password": "SenhaLogout123"})
    assert login.status_code == 200
    assert client.cookies.get("session") is not None

    # Faz logout
    response = client.post("/auth/logout")
    assert response.status_code in (200, 204)

    # O cookie deve ter sido removido
    assert response.cookies.get("session") is None

    # Opcional e mais robusto: verifica se o servidor setou o cookie para expirar
    set_cookie = response.headers.get("set-cookie")
    assert set_cookie is not None
    assert "session=" in set_cookie
    assert "Max-Age=0" in set_cookie or "expires=" in set_cookie.lower()

    # Após logout, tentar acessar rota protegida deve falhar
    me = client.get("/users/me")
    assert me.status_code == 401
