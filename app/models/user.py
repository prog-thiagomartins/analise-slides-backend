from datetime import datetime, UTC
from typing import List, Optional
from pydantic import BaseModel, EmailStr, field_validator
import re

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
