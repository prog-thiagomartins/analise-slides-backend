try:
    from pydantic_settings import BaseSettings
    from pydantic_settings import SettingsConfigDict
except ImportError:
    from pydantic import BaseSettings
    SettingsConfigDict = None
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path
from app.models.user import Base  # importa Base do modelo User

class Settings(BaseSettings):
    PROJECT_NAME: str = "MyApp"
    ENVIRONMENT: str = "development"
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_USER: str = "user"
    DB_PASSWORD: str = "pass"
    DB_NAME: str = "appdb"
    REDIS_URL: str = "redis://localhost:6379/0"
    JWT_SECRET: str = "secret"
    reset_password_token_enabled: bool = True  # Adicionado para suportar variável de ambiente

    if SettingsConfigDict:
        model_config = SettingsConfigDict(env_file=os.getenv("ENV_FILE", ".env.dev"), env_file_encoding="utf-8")
    else:
        class Config:
            env_file = os.getenv("ENV_FILE", ".env.dev")
            env_file_encoding = "utf-8"

settings = Settings()

BASE_DIR = Path(__file__).resolve().parent.parent
if settings.ENVIRONMENT == "test":
    db_url = f"sqlite:///{BASE_DIR}/test.sqlite3"
else:
    db_url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/db.sqlite3")

engine = create_engine(db_url, connect_args={"check_same_thread": False} if db_url.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Criação automática das tabelas no ambiente de desenvolvimento
if settings.ENVIRONMENT == "development":
    Base.metadata.create_all(bind=engine)
