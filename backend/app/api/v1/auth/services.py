import random
import re
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.logger import logger
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app import constants
from app.api.v1.auth.models import APIKey
from app.api.v1.auth.schemas import (
    APIKeyResponse,
    Provider,
    ResetPasswordPayload,
    TokenData,
    UserLoginPayload,
    UserSignupPayload,
)
from app.api.v1.user.models import User, generate_password_hash
from app.api.v1.user.services import create_user, get_user_by_email_and_type
from app.database import db
from app.settings import settings
from app.utils.common import dict_to_query_params
from app.utils.google import (
    exchange_code_for_user_info,
    get_google_redirect_uri,
    validate_access_token_and_get_user_info,
)
from app.utils.strings import generate_random_string

# JWT Settings
ALGORITHM = "HS256"
SECRET_KEY = settings.token_secret
DEFAULT_TOKEN_EXPIRY_HOURS = 48

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/auth/login/")


def get_api_key_from_request(request: Request) -> Optional[str]:
    """Extract the API key from request headers."""
    api_key = request.headers.get("X-Api-Key")
    return api_key


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

    api_key_str = get_api_key_from_request(request)
    if api_key_str:
        user = verify_api_key(api_key_str, session)
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


def is_valid_password(password: str) -> bool:
    """Checks the given password to make sure it is valid.

    Must be at least 8 characters.
    Must contain an uppercase letter, number, and special character.

    Args:
        password (str): password to check.

    Returns:
        bool: True if the password is valid, False otherwise.
    """
    password = password.strip()
    if not password:
        return False
    if settings.env not in [constants.TESTING, constants.STAGING, constants.PRODUCTION]:
        return True

    # Single regex pattern for all password validations
    pattern = (
        r"^(?=.*[A-Z])"  # At least one uppercase letter
        r"(?=.*\d)"  # At least one number
        r"(?=.*[^a-zA-Z0-9])"  # At least one special character
        r".{8,}$"  # At least 8 characters
    )
    logger.info(
        f"pattern: {pattern}, password: {password}, match: {bool(re.match(pattern, password))}",
    )
    return bool(re.match(pattern, password))


def check_password_hash(attempt, password_hash) -> bool:
    return bcrypt.checkpw(attempt.encode("ascii"), password_hash.encode("ascii"))


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


def authenticate_user_email_password(
    session: Session,
    email: str,
    password: str,
    user_type: str,
) -> Optional[User]:
    """Authenticates the email and password.

    Args:
        session (Session): DB session
        email (str): email of the user
        password (str): password of the user

    Returns:
        User: User model of the user in question, if the password matches. Else, None.
    """
    user = session.query(User).filter_by(email=email, user_type=user_type).first()
    if not user:
        return None
    if not check_password_hash(password, user.password):
        return None
    return user


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
        user_type=user.user_type.value,
        email_confirmed=user.email_confirmed,
    )
    if user.name:
        jwt_payload.name = user.name
    if user.profile_image:
        jwt_payload.profile_image = user.profile_image

    return create_jwt_with_expiry(jwt_payload.model_dump())


def generate_random_password() -> str:
    """
    Returns a cryptographically secure random password
    Must pass is_valid_password reliably
    """

    ascii_uppercase = "".join(secrets.choice(string.ascii_uppercase) for i in range(4))

    ascii_lowercase = "".join(secrets.choice(string.ascii_lowercase) for i in range(4))

    punctuation = "".join(secrets.choice(string.punctuation) for i in range(2))

    digits = "".join(secrets.choice(string.digits) for i in range(2))

    raw_characters = list(ascii_uppercase + ascii_lowercase + punctuation + digits)
    random.shuffle(raw_characters)
    return "".join(raw_characters)


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

    # If environment isn't one of the specified, simply return True
    if settings.env not in [constants.TESTING, constants.STAGING, constants.PRODUCTION]:
        return True

    # Regex pattern for a standard email
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

    return bool(re.match(pattern, email))


def handle_email_signup(
    user_signup_payload: UserSignupPayload,
    session: Session,
) -> User:
    email, password, user_type, name = (
        user_signup_payload.email,
        user_signup_payload.password,
        user_signup_payload.user_type,
        user_signup_payload.name,
    )

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required",
        )

    if not valid_email(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is invalid",
        )

    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Name is required",
        )

    if not is_valid_password(password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters, contain an uppercase letter, number, and special character",
        )

    existing_user = get_user_by_email_and_type(session, email, user_type)

    if existing_user:
        if existing_user.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already exists",
            )
        else:
            existing_user.password = generate_password_hash(password)
            session.commit()
            return existing_user

    return create_user(user_signup_payload, session)


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


def signup(user_signup_payload: UserSignupPayload, session: Session) -> Optional[User]:
    provider = user_signup_payload.provider

    if provider == Provider.EMAIL:
        return handle_email_signup(user_signup_payload, session)

    elif provider == Provider.GOOGLE:
        return handle_google_signup(user_signup_payload, session)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unsupported signup method.",
    )


def generate_email_confirmation_token(user: User) -> str:
    """
    Generate a JWT for email confirmation.
    """
    jwt_payload = {
        "id": user.id,
        "email": user.email,
        "is_admin": user.admin,
        "user_type": user.user_type.value,
        "email_confirmation": True,
    }
    return create_jwt_with_expiry(jwt_payload)


def verify_email_confirmation_token(session: Session, token: str) -> Optional[User]:
    """
    Verify a JWT for email confirmation.
    """
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception:
        return None

    if not decoded_token.get("email_confirmation"):
        return None

    user_id = decoded_token.get("id")
    email = decoded_token.get("email")
    user_type = decoded_token.get("user_type")
    user_type = user_type.upper() if user_type else None

    if not user_id or not email or not user_type:
        return None

    return User.get_by_email_and_type(session, email, user_type)


def handle_email_login(
    user_login_payload: UserLoginPayload,
    session: Session,
) -> Optional[User]:
    email, password, user_type = (
        user_login_payload.email,
        user_login_payload.password,
        user_login_payload.user_type,
    )

    if not email or not password:
        return None

    user = authenticate_user_email_password(session, email, password, user_type)

    if not user:
        return None

    return user


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


def handle_google_retool_login(
    user_login_payload: UserLoginPayload,
    session: Session,
) -> Optional[User]:
    try:
        user_info = validate_access_token_and_get_user_info(
            user_login_payload.retool_token,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return handle_oauth_user_login(user_info, user_login_payload, session)


def login(user_login_payload: UserLoginPayload, session: Session) -> Optional[User]:
    provider = user_login_payload.provider

    if provider == Provider.EMAIL:
        return handle_email_login(user_login_payload, session)
    elif provider == Provider.GOOGLE and (
        user_login_payload.token is not None and user_login_payload.retool_token is None
    ):
        return handle_google_login(user_login_payload, session)
    elif provider == Provider.GOOGLE and (
        user_login_payload.retool_token is not None and user_login_payload.token is None
    ):
        return handle_google_retool_login(user_login_payload, session)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unsupported login method.",
    )


def generate_password_reset_token(user: User) -> str:
    """
    Generate a JWT for email confirmation.
    """
    jwt_payload = {
        "id": user.id,
        "email": user.email,
        "is_admin": user.admin,
        "user_type": user.user_type.value,
        "password_reset": True,
    }
    return create_jwt_with_expiry(jwt_payload)


def verify_password_reset_token(session: Session, token: str) -> Optional[User]:
    """
    Verify a JWT for email confirmation.
    """
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except Exception as e:
        logger.error(f"Invalid token: {repr(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid token: {str(e)}",
        )

    if not decoded_token.get("password_reset"):
        return None

    user_id = decoded_token.get("id")
    email = decoded_token.get("email")
    user_type = decoded_token.get("user_type")
    user_type = user_type.upper() if user_type else None

    if not user_id or not email or not user_type:
        return None

    return User.get_by_email_and_type(session, email, user_type)


def reset_password(user: User, password: str, session: Session) -> User:
    if not is_valid_password(password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters, contain an uppercase letter, number, and special character",
        )

    user.password = generate_password_hash(password)
    session.commit()
    session.refresh(user)
    return user


def verify_token_and_reset_password(
    reset_password_payload: ResetPasswordPayload,
    session: Session,
) -> User:
    user = verify_password_reset_token(session, reset_password_payload.token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token",
        )

    return reset_password(user, reset_password_payload.password, session)


def create_login_with_google_url(platform: str, user_type: str) -> str:
    """Create a URL to login with Google.

    Args:
        platform (str): Platform to redirect to after login.

    Returns:
        str: URL to login with Google.
    """
    url = "https://accounts.google.com/o/oauth2/v2/auth"

    state = {
        "platform": platform,
        "user_type": user_type,
    }

    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": get_google_redirect_uri(platform=platform),
        "state": dict_to_query_params(state),
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    params = dict_to_query_params(params)

    return f"{url}?{params}"


def generate_api_key(
    user: User,
    session: Session,
) -> APIKeyResponse:
    api_key = generate_random_string(32)

    api_key_obj = APIKey(
        user_id=user.id,
        key=api_key,
    )

    session.add(api_key_obj)

    session.commit()
    session.refresh(api_key_obj)

    return APIKeyResponse(
        key=api_key,
        expires_at=api_key_obj.expires_at.isoformat(),
        user_id=user.id,
    )


def verify_api_key(
    api_key_str: str,
    session: Session,
) -> Optional[User]:
    api_key = session.query(APIKey).filter_by(key=api_key_str).first()

    if not api_key:
        return

    if api_key.expires_at < datetime.now():
        session.delete(api_key)
        session.commit()
        return

    user = User.get(session, api_key.user_id)

    return user
