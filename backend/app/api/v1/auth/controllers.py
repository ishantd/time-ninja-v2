"""API Route handlers for auth."""

from fastapi import APIRouter, Depends
from fastapi.logger import logger

from app.api.v1.auth import services
from app.api.v1.auth.schemas import TokenData
from app.api.v1.auth.services import get_current_user
from app.api.v1.user.models import User

router = APIRouter()


@router.get("/whoami/", response_model=TokenData)
def whoami(current_user: User = Depends(get_current_user)):
    logger.info(f"[Who Am I] Fetching data for user with ID: {current_user.id}")
    user_data = {
        "user_id": current_user.id,
        "email": current_user.email,
        "admin": current_user.admin,
        "user_type": current_user.user_type.value.upper(),
        "email_confirmed": current_user.email_confirmed,
    }
    if current_user.name:
        user_data["name"] = current_user.name
    if current_user.profile_image:
        user_data["profile_image"] = current_user.profile_image
    return user_data


@router.get("/google/url/")
def google_url(
    user_type: str,
    platform: str = "frontend",
):
    """Get google url."""
    url = services.create_login_with_google_url(platform=platform, user_type=user_type)
    return {"url": url}
