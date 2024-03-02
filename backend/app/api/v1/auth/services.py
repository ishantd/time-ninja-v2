import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.api.v1.auth.schemas import (
    Provider,
    TokenData,
    UserLoginPayload,
    UserSignupPayload,
)
from app.api.v1.user.models import User
from app.api.v1.user.services import create_user, get_user_by_email_and_type
from app.database import db
from app.settings import settings
from app.utils.common import dict_to_query_params
from app.utils.google import exchange_code_for_user_info

# JWT Settings
ALGORITHM = "HS256"
SECRET_KEY = settings.token_secret
DEFAULT_TOKEN_EXPIRY_HOURS = 48

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/auth/login/")


def get_user_authentication(
    request: Request,
    session: Session = Depends(db),
) -> Optional[User]:
    """Get user from either a JWT token or an API key."""
    token_data = get_auth_token_data(request)
    if token_data:
        user = fetch_user(session, token_data.user_id, token_data.user_type)
        if user:
            return user

    return None


def decode_token(token: str) -> Optional[TokenData]:
    """Decode the JWT token to get user details."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return TokenData(**payload)
    except JWTError:
        return None


def get_token_from_request(request: Request) -> Optional[str]:
    """Extract token from the request headers or cookies."""
    token = request.headers.get("Authorization")
    if token:
        token = token.split(" ")[-1]
    else:
        token = request.cookies.get("access_token")
    return token


def fetch_user(session: Session, user_id: str, user_type: str) -> Optional[User]:
    """Fetch user from the database."""
    return User.get_by_id_and_type(session, user_id, user_type.upper())


def get_auth_token_data(request: Request) -> Optional[TokenData]:
    """Get authentication token data from the request."""
    token = get_token_from_request(request)
    if not token:
        return None
    token_data = decode_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid authentication token or token has expired",
        )
    return token_data


def get_current_user(request: Request, session: Session = Depends(db)) -> User:
    """Get the current authenticated user or raise an HTTP exception."""
    user = get_user_authentication(request, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )
    return user


def get_optional_current_user(
    request: Request,
    session: Session = Depends(db),
) -> Optional[User]:
    """Try to get the current authenticated user without raising exceptions."""
    return get_user_authentication(request, session)


def user_is_admin(current_user=Depends(get_current_user)):
    """Throws an exception unless a request is authenticated as an admin user"""
    if not current_user.admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="you are not an admin",
        )
    return current_user


def set_access_token_cookie(response: Response, token: str) -> Response:
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="none",
        secure=True,
        expires=datetime.now(timezone.utc)
        + timedelta(hours=DEFAULT_TOKEN_EXPIRY_HOURS),
    )
    response.body = b""
    return response


def remove_access_token_cookie(response: Response) -> Response:
    response.delete_cookie(
        key="access_token",
        httponly=True,
        samesite="none",
        secure=True,
    )
    response.body = b""
    return response


def get_token_expiry(
    expires_delta: Optional[timedelta] = None,
) -> timedelta:
    """Get the expiry time for a JWT.

    Returns:
        timedelta: Expiry time.
    """
    return datetime.now(settings.timezone) + (
        expires_delta or timedelta(hours=DEFAULT_TOKEN_EXPIRY_HOURS)
    )


def create_jwt_with_expiry(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate a JWT with given data and expiry.

    Args:
        data (dict): Data to encode in the JWT
        expires_delta (timedelta, optional): Timedelta defining JWT expiry.
        Defaults to 48 hours.

    Returns:
        str: JWT string
    """
    to_encode = data.copy()

    to_encode.update({"exp": get_token_expiry(expires_delta=expires_delta)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_user_access_token(user: User) -> str:
    """Create an Access Token for the given user.

    JWT payload contains user's id, email, and admin status.

    Args:
        user (User): User to make an access token for.

    Returns:
        str: JWT string
    """
    jwt_payload = TokenData(
        user_id=user.id,
        email=user.email,
        admin=user.admin,
        email_confirmed=user.email_confirmed,
    )
    if user.name:
        jwt_payload.name = user.name
    if user.profile_image:
        jwt_payload.profile_image = user.profile_image

    return create_jwt_with_expiry(jwt_payload.model_dump())


def valid_email(email: str) -> bool:
    """Checks the given email to make sure it is valid.

    Args:
        email (str): email to check.

    Returns:
        bool: True if the email is valid, False otherwise.
    """
    email = email.strip()
    if not email:
        return False

    # Regex pattern for a standard email
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

    return bool(re.match(pattern, email))


def handle_google_signup(
    user_signup_payload: UserSignupPayload,
    session: Session,
) -> User:
    try:
        user_info = exchange_code_for_user_info(user_signup_payload.token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    existing_user = get_user_by_email_and_type(
        session,
        user_info["email"],
        user_signup_payload.user_type,
    )

    if not existing_user:
        user_signup_payload.email = user_info["email"]
        user_signup_payload.name = user_info["name"]
        user_signup_payload.profile_image = user_info["picture"]
        return create_user(user_signup_payload, session)

    existing_user.name = user_info["name"]
    existing_user.profile_image = user_info["picture"]
    existing_user.email_confirmed = True
    session.commit()
    return existing_user


def handle_oauth_user_login(
    user_info: dict,
    user_login_payload: UserLoginPayload,
    session: Session,
) -> Optional[User]:
    user = get_user_by_email_and_type(
        session,
        user_info["email"],
        user_login_payload.user_type,
    )

    if not user:
        # Create a new user
        user_signup_payload = UserSignupPayload(
            provider=Provider.GOOGLE,
            user_type=user_login_payload.user_type,
            name=user_info["name"],
            email=user_info["email"],
            profile_image=user_info["picture"],
        )
        user = create_user(user_signup_payload, session)
    else:
        basic_details_missing = not user.name or not user.profile_image

        if basic_details_missing:
            user.name = user_info["name"]
            user.profile_image = user_info["picture"]
            user.email_confirmed = True
            session.commit()

    session.refresh(user)
    return user


def handle_google_login(
    user_login_payload: UserLoginPayload,
    session: Session,
) -> Optional[User]:
    try:
        user_info = exchange_code_for_user_info(user_login_payload.token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return handle_oauth_user_login(user_info, user_login_payload, session)


def create_login_with_google_url(redirect_url: str) -> str:
    """Create a URL to login with Google.

    Args:
        platform (str): Platform to redirect to after login.

    Returns:
        str: URL to login with Google.
    """
    url = "https://accounts.google.com/o/oauth2/v2/auth"

    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": redirect_url,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    params = dict_to_query_params(params)

    return f"{url}?{params}"
