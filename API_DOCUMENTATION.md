# Documentação da API – Backend FastAPI

## Sumário

- [Autenticação e Usuário](#autenticação-e-usuário)
  - [Registrar Usuário](#registrar-usuário)
  - [Login](#login)
  - [Logout](#logout)
  - [Esqueci Minha Senha](#esqueci-minha-senha)
  - [Resetar Senha](#resetar-senha)
  - [Obter Dados do Usuário Logado](#obter-dados-do-usuário-logado)
  - [Atualizar Dados do Usuário](#atualizar-dados-do-usuário)
  - [Atualizar Senha](#atualizar-senha)
- [Status do Sistema](#status-do-sistema)
- [Modelos de Dados](#modelos-de-dados)
- [Autenticação e Cookies](#autenticação-e-cookies)
- [Fluxos de Uso](#fluxos-de-uso)
- [Códigos de Erro](#códigos-de-erro)

---

## Autenticação e Usuário

### Registrar Usuário

- **Endpoint:** `POST /auth/register`
- **Descrição:** Cria um novo usuário e faz login automaticamente.
- **Body:**
  ```json
  {
    "name": "Nome do Usuário",
    "email": "usuario@exemplo.com",
    "password": "senha12345"
  }
  ```
- **Resposta (201):**
  ```json
  {
    "id": "1",
    "name": "Nome do Usuário",
    "email": "usuario@exemplo.com",
    "status": "active",
    "created_at": "2025-06-14T12:00:00Z",
    "updated_at": "2025-06-14T12:00:00Z",
    "roles": ["user"]
  }
  ```
- **Autenticação:** Não requer.
- **Observação:** Um cookie de sessão HttpOnly é setado automaticamente.

---

### Login

- **Endpoint:** `POST /auth/login`
- **Descrição:** Realiza login do usuário.
- **Body:**
  ```json
  {
    "email": "usuario@exemplo.com",
    "password": "senha12345"
  }
  ```
- **Resposta (200):**
  ```json
  {
    "id": "1",
    "name": "Nome do Usuário",
    "email": "usuario@exemplo.com",
    "status": "active",
    "created_at": "2025-06-14T12:00:00Z",
    "updated_at": "2025-06-14T12:00:00Z",
    "roles": ["user"]
  }
  ```
- **Autenticação:** Não requer.
- **Observação:** Um cookie de sessão HttpOnly é setado automaticamente.

---

### Logout

- **Endpoint:** `POST /auth/logout`
- **Descrição:** Realiza logout do usuário, removendo o cookie de sessão.
- **Resposta (204):** Sem conteúdo.
- **Autenticação:** Requer cookie de sessão.

---

### Esqueci Minha Senha

- **Endpoint:** `POST /auth/forgot-password`
- **Descrição:** Envia um token de reset de senha para o email informado (mock).
- **Body:**
  ```json
  {
    "email": "usuario@exemplo.com"
  }
  ```
- **Resposta (200):**
  ```json
  {
    "message": "Se o email existir, um link de reset foi enviado."
  }
  ```
- **Autenticação:** Não requer.

---

### Resetar Senha

- **Endpoint:** `POST /auth/reset-password`
- **Descrição:** Reseta a senha do usuário usando o token enviado por email.
- **Body:**
  ```json
  {
    "token": "token_recebido_no_email",
    "new_password": "novasenha123"
  }
  ```
- **Resposta (200):**
  ```json
  {
    "message": "Senha redefinida com sucesso."
  }
  ```
- **Autenticação:** Não requer.

---

### Obter Dados do Usuário Logado

- **Endpoint:** `GET /users/me`
- **Descrição:** Retorna os dados do usuário autenticado.
- **Resposta (200):**
  ```json
  {
    "id": "1",
    "name": "Nome do Usuário",
    "email": "usuario@exemplo.com",
    "status": "active",
    "created_at": "2025-06-14T12:00:00Z",
    "updated_at": "2025-06-14T12:00:00Z",
    "roles": ["user"]
  }
  ```
- **Autenticação:** Requer cookie de sessão.

---

### Atualizar Dados do Usuário

- **Endpoint:** `PUT /users/me`
- **Descrição:** Atualiza o nome do usuário autenticado.
- **Body:**
  ```json
  {
    "name": "Novo Nome"
  }
  ```
- **Resposta (200):** Igual ao endpoint `/users/me`.
- **Autenticação:** Requer cookie de sessão.

---

### Atualizar Senha

- **Endpoint:** `POST /users/update-password`
- **Descrição:** Atualiza a senha do usuário autenticado.
- **Body:**
  ```json
  {
    "current_password": "senha_antiga",
    "new_password": "senha_nova"
  }
  ```
- **Resposta (200):**
  ```json
  {
    "message": "Senha atualizada com sucesso."
  }
  ```
- **Autenticação:** Requer cookie de sessão.

---

## Status do Sistema

- **Endpoint:** `GET /status/`
- **Descrição:** Verifica se o backend está online.
- **Resposta (200):**
  ```json
  {
    "status": "ok"
  }
  ```

---

## Modelos de Dados

### Usuário

```json
{
  "id": "1",
  "name": "Nome do Usuário",
  "email": "usuario@exemplo.com",
  "status": "active",
  "created_at": "2025-06-14T12:00:00Z",
  "updated_at": "2025-06-14T12:00:00Z",
  "roles": ["user"]
}
```

---

## Autenticação e Cookies

- O backend utiliza **cookie de sessão HttpOnly** chamado `session` para autenticação.
- O cookie é setado automaticamente no login e registro.
- Para acessar rotas protegidas, o front-end deve enviar o cookie de sessão.
- Em ambiente de produção, o cookie é `Secure` e `SameSite=Lax`.

---

## Fluxos de Uso

### Registro e Login

1. Usuário se registra (`/auth/register`) → já recebe cookie de sessão.
2. Usuário faz login (`/auth/login`) → recebe cookie de sessão.
3. Front-end armazena o cookie e envia em todas as requisições protegidas.

### Esqueci/Resetar Senha

1. Usuário solicita reset (`/auth/forgot-password`) → recebe token por email.
2. Usuário envia token e nova senha (`/auth/reset-password`).

### Atualização de Dados

1. Usuário logado pode atualizar nome (`PUT /users/me`) ou senha (`POST /users/update-password`).

---

## Códigos de Erro

- `400`: Requisição inválida
- `401`: Não autenticado ou senha incorreta
- `403`: Usuário inativo
- `409`: Email já cadastrado
- `422`: Dados inválidos (ex: senha fraca, nome inválido)

---

## Exemplos de Erros e Respostas

### Exemplo de erro 401 (Não autenticado ou senha incorreta)

```json
{
  "detail": "Senha inválida"
}
```

### Exemplo de erro 403 (Usuário inativo)

```json
{
  "detail": "Usuário inativo"
}
```

### Exemplo de erro 409 (Email já cadastrado)

```json
{
  "detail": "Email já cadastrado"
}
```

### Exemplo de erro 422 (Dados inválidos)

```json
{
  "detail": "A senha deve ter pelo menos 8 caracteres."
}
```

---

## Observações Técnicas para o Front-end

- **CORS:** O backend aceita requisições de qualquer origem (`allow_origins=["*"]`).
- **Cookies:** O cookie de sessão é HttpOnly, Secure (em produção) e SameSite=Lax. O navegador envia automaticamente em requisições subsequentes após login/registro.
- **Token de reset de senha:** O token é enviado por email (mock, aparece no log do backend). O front deve pedir ao usuário o token recebido para resetar a senha.
- **Validações:**
  - Nome: mínimo 2, máximo 100 caracteres, sem tags HTML.
  - Senha: mínimo 8, máximo 128 caracteres.
  - Email: formato válido.
- **Headers:** Não é necessário enviar headers especiais além do padrão. O cookie de sessão é suficiente para autenticação.
- **Campos obrigatórios:** Todos os campos dos formulários são obrigatórios.

---

## Exemplos de Requisições

### Usando fetch (JavaScript)

#### Login

```js
fetch("http://localhost:8000/auth/login", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: "usuario@exemplo.com",
    password: "senha12345",
  }),
})
  .then((res) => res.json())
  .then(console.log);
```

#### Obter usuário logado

```js
fetch("http://localhost:8000/users/me", {
  method: "GET",
  credentials: "include",
})
  .then((res) => res.json())
  .then(console.log);
```

### Usando curl

#### Registro

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Nome", "email": "usuario@exemplo.com", "password": "senha12345"}' -c cookies.txt
```

#### Login

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "usuario@exemplo.com", "password": "senha12345"}' -c cookies.txt
```

#### Obter usuário logado

```bash
curl http://localhost:8000/users/me -b cookies.txt
```

---

## Dependências do Backend

- Python 3.11+
- FastAPI
- Uvicorn
- SQLAlchemy
- Pydantic
- psycopg2-binary (PostgreSQL)
- redis
- passlib[bcrypt]
- jwt

---

## Observações Finais

- O backend está preparado para rodar em Docker e Docker Compose, com serviços de banco de dados PostgreSQL e Redis.
- O front-end pode ser hospedado em qualquer domínio/origem.
- O backend pode ser facilmente expandido para JWT, OAuth2, etc., se necessário.
- Para dúvidas sobre fluxos, payloads ou respostas, consulte este documento ou peça exemplos adicionais.
