from fastapi import APIRouter

router = APIRouter()

@router.get("/status/")
def healthcheck():
    return {"status": "ok"}
