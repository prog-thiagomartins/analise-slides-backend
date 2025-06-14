from fastapi import APIRouter, HTTPException, status, Response
from pydantic import BaseModel, EmailStr, model_validator, validator, field_validator
from app.models.user import User
from app.services.password import hash_password, verify_password
from app.services.token import create_access_token
import uuid
from typing import List
from datetime import datetime, UTC, timedelta
from app.core.config import settings
from fastapi import Body, Cookie, Depends
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import re
from app.models.user import UserORM
from app.core.config import SessionLocal
from sqlalchemy.exc import IntegrityError
import json
import secrets
from app.utils.response import api_response

# Simples armazenamento de tokens de reset para exemplo
token_user_map = {}

def sanitize_input(text: str) -> str:
    # Remove tags HTML simples
    return re.sub(r'<.*?>', '', text)

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

    @field_validator('name')
    @classmethod
    def name_must_be_str_and_valid(cls, v):
        if not isinstance(v, str):
            raise ValueError('O nome deve ser uma string.')
        if len(v.strip()) < 2:
            raise ValueError('O nome deve ter pelo menos 2 caracteres.')
        v = sanitize_input(v)
        if '<' in v or '>' in v:
            raise ValueError('Nome inválido.')
        if len(v) > 100:
            raise ValueError('O nome deve ter no máximo 100 caracteres.')
        return v

    @field_validator('password')
    @classmethod
    def password_must_be_str_and_valid(cls, v):
        if not isinstance(v, str):
            raise ValueError('A senha deve ser uma string.')
        if len(v) < 8:
            raise ValueError('A senha deve ter pelo menos 8 caracteres.')
        if len(v) > 128:
            raise ValueError('A senha deve ter no máximo 128 caracteres.')
        return v

    @model_validator(mode="after")
    def all_fields_required(self):
        for field in ['name', 'email', 'password']:
            v = getattr(self, field, None)
            if v is None or (isinstance(v, str) and not v.strip()):
                raise ValueError(f'O campo {field} é obrigatório.')
        return self

    model_config = {"extra": "forbid"}

class RegisterResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    status: str
    created_at: str
    updated_at: str
    roles: List[str] = []

    model_config = {"extra": "forbid"}

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @model_validator(mode="after")
    def all_fields_required(self):
        for field in ['email', 'password']:
            v = getattr(self, field, None)
            if v is None or (isinstance(v, str) and not v.strip()):
                raise ValueError(f'O campo {field} é obrigatório.')
        return self

    @field_validator('password')
    @classmethod
    def password_must_be_str(cls, v):
        if not isinstance(v, str):
            raise ValueError('A senha deve ser uma string.')
        if len(v) > 128:
            raise ValueError('A senha deve ter no máximo 128 caracteres.')
        return v

    model_config = {"extra": "forbid"}

class LoginResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    status: str
    created_at: str
    updated_at: str
    roles: List[str] = []

    model_config = {"extra": "forbid"}

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class UpdateUserRequest(BaseModel):
    name: str

    @field_validator('name')
    @classmethod
    def name_must_be_str_and_valid(cls, v):
        if not isinstance(v, str):
            raise ValueError('O nome deve ser uma string.')
        if len(v.strip()) < 2:
            raise ValueError('O nome deve ter pelo menos 2 caracteres.')
        v = sanitize_input(v)
        if '<' in v or '>' in v:
            raise ValueError('Nome inválido.')
        if len(v) > 100:
            raise ValueError('O nome deve ter no máximo 100 caracteres.')
        return v

    model_config = {"extra": "forbid"}

class UpdatePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @model_validator(mode="after")
    def all_fields_required(self):
        for field in ['current_password', 'new_password']:
            v = getattr(self, field, None)
            if v is None or (isinstance(v, str) and not v.strip()):
                raise ValueError(f'O campo {field} é obrigatório.')
        return self

    @field_validator('current_password', 'new_password')
    @classmethod
    def password_must_be_str_and_valid(cls, v):
        if not isinstance(v, str):
            raise ValueError('A senha deve ser uma string.')
        if len(v) < 8:
            raise ValueError('A senha deve ter pelo menos 8 caracteres.')
        if len(v) > 128:
            raise ValueError('A senha deve ter no máximo 128 caracteres.')
        return v

    model_config = {"extra": "forbid"}

router = APIRouter()

# Helper to get cookie flags
COOKIE_FLAGS = {
    "httponly": True,
    "secure": settings.ENVIRONMENT == "production",
    "samesite": "lax"
}

# Função de envio de email (mockável nos testes)
def send_email(to_email: str, subject: str, body: str):
    # Aqui seria integração real, mas nos testes é mockado
    print(f"[EMAIL] To: {to_email} | Subject: {subject} | Body: {body}")
    return True

def validate_reset_token(token: str) -> bool:
    return token in token_user_map

def get_user_by_token(token: str):
    user_id = token_user_map.get(token)
    if user_id:
        db = SessionLocal()
        user = db.query(UserORM).filter(UserORM.id == user_id).first()
        db.close()
        return user
    return None

# Dependência para obter usuário autenticado
def get_current_user(session: str = Cookie(None)):
    if not session or session != "fake-session-token":
        raise HTTPException(status_code=401, detail="Não autenticado")
    db = SessionLocal()
    user = db.query(UserORM).filter(UserORM.status == "active").first()
    db.close()
    if not user:
        raise HTTPException(status_code=401, detail="Não autenticado")
    return user

@router.post("/auth/register", status_code=201)
def register_user(data: RegisterRequest, response: Response):
    db = SessionLocal()
    try:
        user_exists = db.query(UserORM).filter(UserORM.email == data.email).first()
        if user_exists:
            db.close()
            content = api_response(
                success=False,
                message="Não foi possível completar a operação.",
                errors=[{"loc": ["body", "email"], "msg": "E-mail já cadastrado.", "type": "conflict"}],
                data=None
            )
            resp = JSONResponse(status_code=409, content=jsonable_encoder(content))
            return resp
        now = datetime.now(UTC)
        user = UserORM(
            id=str(uuid.uuid4()),
            name=data.name,
            email=data.email,
            status="active",
            created_at=now,
            updated_at=now,
            roles=json.dumps(["user"]),
            password_hash=hash_password(data.password)
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        content = api_response(
            success=True,
            message="Usuário registrado com sucesso.",
            errors=[],
            data={
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "status": user.status,
                "created_at": str(user.created_at),
                "updated_at": str(user.updated_at),
                "roles": json.loads(user.roles)
            }
        )
        resp = JSONResponse(status_code=201, content=jsonable_encoder(content))
        resp.set_cookie(
            key="session",
            value="fake-session-token",
            httponly=COOKIE_FLAGS["httponly"],
            secure=COOKIE_FLAGS["secure"],
            samesite=COOKIE_FLAGS["samesite"]
        )
        return resp
    except IntegrityError:
        db.rollback()
        content = api_response(
            success=False,
            message="Não foi possível completar a operação.",
            errors=[{"loc": ["body", "email"], "msg": "E-mail já cadastrado.", "type": "conflict"}],
            data=None
        )
        resp = JSONResponse(status_code=409, content=jsonable_encoder(content))
        return resp
    finally:
        db.close()

@router.post("/auth/login")
def login_user(data: LoginRequest, response: Response):
    db = SessionLocal()
    try:
        user = db.query(UserORM).filter(UserORM.email == data.email).first()
        if not user:
            db.close()
            return JSONResponse(status_code=401, content=api_response(
                success=False,
                message="Senha inválida",
                errors=[{"loc": ["body", "password"], "msg": "Senha inválida", "type": "unauthorized"}],
                data=None
            ))
        if not verify_password(data.password, user.password_hash):
            db.close()
            return JSONResponse(status_code=401, content=api_response(
                success=False,
                message="Senha inválida",
                errors=[{"loc": ["body", "password"], "msg": "Senha inválida", "type": "unauthorized"}],
                data=None
            ))
        if user.status != "active":
            db.close()
            return JSONResponse(status_code=403, content=api_response(
                success=False,
                message="Usuário inativo",
                errors=[{"loc": ["body", "email"], "msg": "Usuário inativo", "type": "forbidden"}],
                data=None
            ))
        import json
        roles = user.roles
        if isinstance(roles, str):
            try:
                roles = json.loads(roles)
            except Exception:
                roles = []
        response.set_cookie(
            key="session",
            value="fake-session-token",
            httponly=COOKIE_FLAGS["httponly"],
            secure=COOKIE_FLAGS["secure"],
            samesite=COOKIE_FLAGS["samesite"]
        )
        content = api_response(
            success=True,
            message="Login realizado com sucesso.",
            errors=[],
            data={
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "status": user.status,
                "created_at": str(user.created_at),
                "updated_at": str(user.updated_at),
                "roles": roles
            }
        )
        resp = JSONResponse(status_code=200, content=jsonable_encoder(content))
        resp.set_cookie(
            key="session",
            value="fake-session-token",
            httponly=COOKIE_FLAGS["httponly"],
            secure=COOKIE_FLAGS["secure"],
            samesite=COOKIE_FLAGS["samesite"]
        )
        return resp
    finally:
        db.close()

@router.post("/auth/logout", status_code=204)
def logout_user(response: Response):
    resp = JSONResponse(status_code=204, content=None)
    resp.set_cookie(
        key="session",
        value="",
        httponly=COOKIE_FLAGS["httponly"],
        secure=COOKIE_FLAGS["secure"],
        samesite=COOKIE_FLAGS["samesite"],
        max_age=0,
        expires=0
    )
    return resp

@router.post("/auth/forgot-password", status_code=200)
def forgot_password(data: ForgotPasswordRequest):
    db = SessionLocal()
    user = db.query(UserORM).filter(UserORM.email == data.email).first()
    if user:
        token = secrets.token_urlsafe(32)
        user.reset_token = token
        user.reset_token_expires_at = datetime.now(UTC) + timedelta(hours=1)
        db.commit()
        send_email(
            to_email=user.email,
            subject="Reset de senha",
            body=f"Use este token para resetar sua senha: {token}"
        )
    db.close()
    return {"message": "Se o email existir, um link de reset foi enviado."}

@router.post("/auth/reset-password", status_code=200)
def reset_password(data: ResetPasswordRequest):
    if not validate_reset_token(data.token):
        raise HTTPException(status_code=400, detail="Token inválido ou expirado")
    db = SessionLocal()
    user = db.query(UserORM).filter(UserORM.reset_token == data.token).first()
    if not user:
        db.close()
        raise HTTPException(status_code=400, detail="Token inválido ou expirado")
    if user.reset_token_expires_at and user.reset_token_expires_at < datetime.utcnow():
        db.close()
        raise HTTPException(status_code=400, detail="Token expirado.")
    # Verifica força da nova senha
    new_password = data.new_password
    if len(new_password) < 8:
        db.close()
        raise HTTPException(status_code=422, detail="A senha deve ter pelo menos 8 caracteres.")
    if not validate_password_strength(new_password):
        db.close()
        raise HTTPException(status_code=422, detail="A senha não atende aos requisitos de segurança.")
    # Atualiza senha
    user.password_hash = hash_password(data.new_password)
    user.reset_token = None
    user.reset_token_expires_at = None
    db.commit()
    db.close()
    return {"message": "Senha redefinida com sucesso."}

@router.get("/users/me")
def get_me(current_user: User = Depends(get_current_user)):
    import json
    roles = current_user.roles
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []
    return api_response(
        success=True,
        message="Usuário autenticado.",
        errors=[],
        data={
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "status": current_user.status,
            "created_at": str(current_user.created_at),
            "updated_at": str(current_user.updated_at),
            "roles": roles or []
        }
    )

@router.put("/users/me")
def update_me(data: UpdateUserRequest, current_user: User = Depends(get_current_user)):
    from app.core.config import SessionLocal
    import json
    sanitized_name = sanitize_input(data.name)
    if '<' in sanitized_name or '>' in sanitized_name:
        return JSONResponse(status_code=422, content=api_response(
            success=False,
            message="Nome inválido.",
            errors=[{"loc": ["body", "name"], "msg": "Nome inválido.", "type": "value_error"}],
            data=None
        ))
    db = SessionLocal()
    user = db.query(UserORM).filter(UserORM.id == current_user.id).first()
    user.name = sanitized_name
    user.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(user)
    roles = user.roles
    if isinstance(roles, str):
        try:
            roles = json.loads(roles)
        except Exception:
            roles = []
    db.close()
    return api_response(
        success=True,
        message="Usuário atualizado com sucesso.",
        errors=[],
        data={
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "status": user.status,
            "created_at": str(user.created_at),
            "updated_at": str(user.updated_at),
            "roles": roles or []
        }
    )

@router.post("/users/update-password", status_code=200)
def update_password(data: UpdatePasswordRequest, current_user: User = Depends(get_current_user)):
    from app.core.config import SessionLocal
    db = SessionLocal()
    user = db.query(UserORM).filter(UserORM.id == current_user.id).first()
    if not verify_password(data.current_password, user.password_hash):
        db.close()
        return JSONResponse(status_code=401, content=api_response(
            success=False,
            message="Senha atual incorreta",
            errors=[{"loc": ["body", "current_password"], "msg": "Senha atual incorreta", "type": "unauthorized"}],
            data=None
        ))
    if data.current_password == data.new_password:
        db.close()
        return JSONResponse(status_code=422, content=api_response(
            success=False,
            message="A nova senha deve ser diferente da senha atual.",
            errors=[{"loc": ["body", "new_password"], "msg": "A nova senha deve ser diferente da senha atual.", "type": "value_error"}],
            data=None
        ))
    if len(data.new_password) < 8:
        db.close()
        return JSONResponse(status_code=422, content=api_response(
            success=False,
            message="A senha deve ter pelo menos 8 caracteres.",
            errors=[{"loc": ["body", "new_password"], "msg": "A senha deve ter pelo menos 8 caracteres.", "type": "value_error"}],
            data=None
        ))
    if not validate_password_strength(data.new_password):
        db.close()
        return JSONResponse(status_code=422, content=api_response(
            success=False,
            message="A senha não atende aos requisitos de segurança.",
            errors=[{"loc": ["body", "new_password"], "msg": "A senha não atende aos requisitos de segurança.", "type": "value_error"}],
            data=None
        ))
    user.password_hash = hash_password(data.new_password)
    user.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(user)
    db.close()
    return api_response(
        success=True,
        message="Senha atualizada com sucesso.",
        errors=[],
        data=None
    )

def validate_password_strength(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 8 or len(password) > 128:
        return False
    # Pode adicionar mais regras de força aqui (números, maiúsculas, etc)
    return True
