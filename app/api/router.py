from fastapi import APIRouter
from app.api.routes import auth

router = APIRouter()
router.include_router(auth.router)
