from app.core.config import settings

def test_settings_env():
    assert hasattr(settings, "reset_password_token_enabled")
    assert isinstance(settings.reset_password_token_enabled, bool)
