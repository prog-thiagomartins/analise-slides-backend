from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from app.api.router import router as api_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FastAPI Backend")

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
