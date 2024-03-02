import requests
from fastapi.logger import logger
from pydantic import BaseModel

from app.settings import settings


class GoogleToken(BaseModel):
    """Google token response."""

    access_token: str
    expires_in: int
    id_token: str
    refresh_token: str
    scope: str
    token_type: str


def get_google_redirect_uri(platform: str = "frontend"):
    """Get google redirect url"""
    redirect_uri = (
        platform == "backend"
        and f"{settings.ether_base_url}/v1/auth/google/callback"
        or f"{settings.frontend_url}/auth/google/callback"
    )
    return redirect_uri


def validate_access_token_and_get_user_info(access_token: str) -> dict:
    """Validate an access token and return user info.
    We'll do this by calling the Google API with the access token.

    Args:
        access_token (str): Access token to validate.

    Returns:
        dict: User info from access token.
    """
    url = "https://www.googleapis.com/userinfo/v2/me"

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise Exception("Invalid access token")

    return response.json()


def exhange_code_for_access_token(code: str) -> GoogleToken:
    """Exchange a code for an access token.

    Args:
        code (str): Code to exchange for access token.

    Returns:
        dict: Access token response.
    """
    url = "https://oauth2.googleapis.com/token"

    data = {
        "code": code,
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        # Redirect URI must match the one used in the initial request
        # Not working with backend as a platform, only frontend
        "redirect_uri": get_google_redirect_uri(),
        # When using Google OAuth Playground use this as redirect URI
        # "redirect_uri": "https://developers.google.com/oauthplayground",
        "grant_type": "authorization_code",
    }

    response = requests.post(url, data=data)

    if response.status_code != 200:
        logger.error(response.json())
        raise Exception("Invalid code")

    return GoogleToken(**response.json())


def exchange_code_for_user_info(code: str) -> dict:
    """Exchange a code for user info.

    Args:
        code (str): Code to exchange for user info.

    Returns:
        dict: User info.
    """
    access_token_response = exhange_code_for_access_token(code)
    user_info = validate_access_token_and_get_user_info(
        access_token_response.access_token,
    )
    return user_info
