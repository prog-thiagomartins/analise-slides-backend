from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exception_handlers import RequestValidationError
from app.utils.response import api_response

async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        errors.append({
            "loc": err.get("loc", []),
            "msg": err.get("msg", "Erro de validação."),
            "type": err.get("type", "validation_error")
        })
    content = api_response(
        success=False,
        message="Erro de validação.",
        errors=errors,
        data=None
    )
    return JSONResponse(status_code=422, content=content)
