from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from app.api.router import router as api_router
import os
from app.core.config import db_url
from fastapi.exceptions import RequestValidationError
from app.utils.validation_handler import validation_exception_handler
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"[INFO] DATABASE_URL em uso: {db_url}")
    yield

app = FastAPI(title="finan-api", lifespan=lifespan)

app.add_exception_handler(RequestValidationError, validation_exception_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/status/")
def healthcheck():
    logger.info("Healthcheck OK")
    return {"status": "ok"}
