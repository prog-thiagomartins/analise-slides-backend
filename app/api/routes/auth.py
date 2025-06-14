from fastapi import APIRouter, HTTPException, status, Response
from pydantic import BaseModel, EmailStr, model_validator, validator, field_validator
from app.models.user import User
from app.services.password import hash_password, verify_password
from app.services.token import create_access_token
import uuid
from typing import List
from datetime import datetime, UTC
from app.core.config import settings
from fastapi import Body, Cookie, Depends
from fastapi.responses import JSONResponse
import re

# Simulação de banco em memória para exemplo
db_users: List[User] = []

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
        return next((u for u in db_users if u.id == user_id), None)
    return None

# Dependência para obter usuário autenticado
def get_current_user(session: str = Cookie(None)):
    # Simples: se o cookie de sessão existe e é válido, retorna o usuário
    if not session or session != "fake-session-token":
        # Em produção, validar token real
        raise HTTPException(status_code=401, detail="Não autenticado")
    # Retorna o primeiro usuário ativo (mock)
    user = next((u for u in db_users if u.status == "active"), None)
    if not user:
        raise HTTPException(status_code=401, detail="Não autenticado")
    return user

@router.post("/auth/register", response_model=RegisterResponse, status_code=201)
def register_user(data: RegisterRequest, response: Response):
    # Verifica se email já existe
    if any(u.email == data.email for u in db_users):
        raise HTTPException(status_code=409, detail="Email já cadastrado")
    now = datetime.now(UTC)
    # Cria usuário
    user = User(
        id=str(len(db_users) + 1),
        name=data.name,
        email=data.email,
        status="active",
        created_at=now,
        updated_at=now,
        roles=["user"],
        password_hash=hash_password(data.password)
    )
    db_users.append(user)
    # Seta cookie HttpOnly, Secure, SameSite
    response.set_cookie(
        key="session",
        value="fake-session-token",
        httponly=COOKIE_FLAGS["httponly"],
        secure=COOKIE_FLAGS["secure"],
        samesite=COOKIE_FLAGS["samesite"]
    )
    return RegisterResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        status=user.status,
        created_at=str(user.created_at),
        updated_at=str(user.updated_at),
        roles=user.roles
    )

@router.post("/auth/login", response_model=LoginResponse)
def login_user(data: LoginRequest, response: Response):
    user = next((u for u in db_users if u.email == data.email), None)
    if not user:
        raise HTTPException(status_code=401, detail="Senha inválida")
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Senha inválida")
    if user.status != "active":
        raise HTTPException(status_code=403, detail="Usuário inativo")
    response.set_cookie(
        key="session",
        value="fake-session-token",
        httponly=COOKIE_FLAGS["httponly"],
        secure=COOKIE_FLAGS["secure"],
        samesite=COOKIE_FLAGS["samesite"]
    )
    return LoginResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        status=user.status,
        created_at=str(user.created_at),
        updated_at=str(user.updated_at),
        roles=user.roles
    )

@router.post("/auth/logout", status_code=204)
def logout_user(response: Response):
    response.set_cookie(
        key="session",
        value="",
        httponly=COOKIE_FLAGS["httponly"],
        secure=COOKIE_FLAGS["secure"],
        samesite=COOKIE_FLAGS["samesite"],
        max_age=0,
        expires=0
    )
    response.status_code = 204
    return response

@router.post("/auth/forgot-password", status_code=200)
def forgot_password(data: ForgotPasswordRequest):
    user = next((u for u in db_users if u.email == data.email), None)
    if user:
        token = str(uuid.uuid4())
        token_user_map[token] = user.id
        send_email(
            to_email=user.email,
            subject="Reset de senha",
            body=f"Use este token para resetar sua senha: {token}"
        )
    return {"message": "Se o email existir, um link de reset foi enviado."}

@router.post("/auth/reset-password", status_code=200)
def reset_password(data: ResetPasswordRequest):
    if not validate_reset_token(data.token):
        raise HTTPException(status_code=400, detail="Token inválido ou expirado")
    user = get_user_by_token(data.token)
    if not user:
        raise HTTPException(status_code=400, detail="Token inválido ou expirado")
    # Verifica força da nova senha
    if len(data.new_password) < 8:
        raise HTTPException(status_code=422, detail="A senha deve ter pelo menos 8 caracteres.")
    # Atualiza senha
    user.password_hash = hash_password(data.new_password)
    # Remove token após uso
    if data.token in token_user_map:
        del token_user_map[data.token]
    return {"message": "Senha redefinida com sucesso."}

@router.get("/users/me", response_model=LoginResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return LoginResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        status=current_user.status,
        created_at=str(current_user.created_at),
        updated_at=str(current_user.updated_at),
        roles=current_user.roles or []
    )

@router.put("/users/me", response_model=LoginResponse)
def update_me(data: UpdateUserRequest, current_user: User = Depends(get_current_user)):
    sanitized_name = sanitize_input(data.name)
    if '<' in sanitized_name or '>' in sanitized_name:
        raise HTTPException(status_code=422, detail="Nome inválido.")
    current_user.name = sanitized_name
    current_user.updated_at = datetime.now(UTC)
    return LoginResponse(
        id=current_user.id,
        name=current_user.name,
        email=current_user.email,
        status=current_user.status,
        created_at=str(current_user.created_at),
        updated_at=str(current_user.updated_at),
        roles=current_user.roles or []
    )

@router.post("/users/update-password")
def update_password(data: UpdatePasswordRequest, current_user: User = Depends(get_current_user)):
    # Valida senha atual
    if not verify_password(data.current_password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Senha atual incorreta")
    # Nova senha deve ser forte e diferente da atual
    if len(data.new_password) < 8:
        raise HTTPException(status_code=422, detail="A nova senha deve ter pelo menos 8 caracteres.")
    if verify_password(data.new_password, current_user.password_hash):
        raise HTTPException(status_code=422, detail="A nova senha deve ser diferente da atual.")
    # Atualiza senha
    current_user.password_hash = hash_password(data.new_password)
    current_user.updated_at = datetime.now(UTC)
    return {"message": "Senha atualizada com sucesso."}
