"""API Route handlers for health checks"""

from fastapi import APIRouter, Depends
from fastapi.logger import logger

from app.database import db

router = APIRouter()


@router.get("/")
def health(
    session=Depends(db),
):
    logger.info("Health check")
    return {"status": "ok"}
