from pydantic import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str
    ENVIRONMENT: str
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASSWORD: str
    DB_NAME: str
    REDIS_URL: str
    JWT_SECRET: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
