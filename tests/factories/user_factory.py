from app.models.user import User
from app.services.password import hash_password
from datetime import datetime, UTC
import uuid

def create_user(email="user1@example.com", password="senhaForte123", **kwargs):
    return User(
        id=kwargs.get("id", str(uuid.uuid4())),
        name=kwargs.get("name", "User Teste"),
        email=email,
        status=kwargs.get("status", "active"),
        created_at=kwargs.get("created_at", datetime.now(UTC)),
        updated_at=kwargs.get("updated_at", datetime.now(UTC)),
        roles=kwargs.get("roles", ["user"]),
        password_hash=hash_password(password)
    )
