import pytest
from app.services.password import hash_password, verify_password
from app.models.user import User

def test_password_hash_and_verify():
    password = "newuserpassword"
    hashed = hash_password(password)
    user = User(
        id="1",
        name="Test User",
        email="test@example.com",
        status="active",
        created_at="2025-06-14T00:00:00",
        updated_at="2025-06-14T00:00:00",
        roles=["user"],
        password_hash=hashed
    )
    assert user.password_hash != password
    assert verify_password(password, user.password_hash)
