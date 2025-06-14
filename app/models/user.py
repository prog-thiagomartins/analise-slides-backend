from datetime import datetime, UTC, timezone
from typing import List, Optional
from pydantic import BaseModel, EmailStr, field_validator
import re
from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import declarative_base
import json

Base = declarative_base()

class User(BaseModel):
    id: str
    name: str
    email: EmailStr
    status: str = 'active'
    created_at: datetime = datetime.now(UTC)
    updated_at: datetime = datetime.now(UTC)
    roles: List[str] = []
    password_hash: str

    @field_validator("name")
    @classmethod
    def no_html_tags(cls, v):
        if re.search(r'<[^>]+>', v):
            raise ValueError("Nome não pode conter tags HTML")
        return v

class UserORM(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    roles = Column(String, default="[]")  # Armazena JSON string
    password_hash = Column(String, nullable=False)

    def get_roles(self):
        return json.loads(self.roles)

    def set_roles(self, roles_list):
        self.roles = json.dumps(roles_list)
