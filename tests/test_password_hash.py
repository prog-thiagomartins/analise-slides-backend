import pytest
from app.services.password import hash_password, verify_password

def test_hash_and_verify_password():
    password = "mysecretpassword"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed)
    assert not verify_password("wrongpassword", hashed)
