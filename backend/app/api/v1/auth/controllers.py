"""API Route handlers for auth."""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.logger import logger
from fastapi.responses import JSONResponse

from app.api.v1.auth import services
from app.api.v1.auth.schemas import (
    APIKeyResponse,
    ForgotPasswordPayload,
    ResetPasswordPayload,
    TokenData,
    UserLoginPayload,
    UserSignupPayload,
)
from app.api.v1.auth.services import get_current_user
from app.api.v1.user.models import User
from app.database import db
from app.settings import settings
from app.utils.email import (
    send_email_confirmation_email,
    send_forgot_password_email,
    send_welcome_email,
)

router = APIRouter()


@router.post("/signup/")
def signup(
    user_signup_payload: UserSignupPayload,
    session=Depends(db),
):
    logger.info(
        f"[User Signup] Attempting to sign up user: {user_signup_payload.email}",
    )
    user = None
    try:
        user = services.signup(user_signup_payload, session)
    except HTTPException as e:
        logger.error(f"[User Signup] {e}")
        raise e
    except Exception as e:
        logger.error(f"[User Signup] {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )
    if not user:
        logger.error("[User Signup] An error occurred while signing up.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while signing up. Please try again.",
        )
    response = JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "status": "ok",
            "user_id": user.id,
            "email_confirmed": user.email_confirmed,
        },
    )
    logger.info("[User Signup] User created successfully.")
    if user.email_confirmed:
        logger.info("[User Signup] Email confirmed.")
        access_token = services.create_user_access_token(user)
        response = services.set_access_token_cookie(response, access_token)
    elif settings.send_confirmation_email_on_signup:
        logger.info("[User Signup] Email not confirmed.")
        send_email_confirmation_email(
            user_name=user.name,
            user_email=user.email,
            token=services.generate_email_confirmation_token(user),
        )
        logger.info("[User Signup] Email confirmation sent.")
    send_welcome_email(user_name=user.name, user_email=user.email)
    return response


@router.post("/login/")
def login(
    user_login_payload: UserLoginPayload,
    session=Depends(db),
):
    logger.info(f"[User Login] Attempting to log in user: {user_login_payload.email}")
    user = services.login(user_login_payload, session)
    if not user:
        logger.error("[User Login] Invalid email or password/token.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password/token",
        )
    if not user.email_confirmed and settings.email_confirmation_required:
        logger.error("[User Login] Email not confirmed.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not confirmed",
        )
    access_token = services.create_user_access_token(user)
    response = Response(status_code=status.HTTP_200_OK)
    response = services.set_access_token_cookie(response, access_token)
    response.headers["X-Access-Token"] = access_token
    logger.info("[User Login] User logged in successfully.")
    return response


@router.post("/logout/")
def logout(response: Response):
    logger.info("[User Logout] User attempting to log out.")

    services.remove_access_token_cookie(response)
    response.headers["X-Access-Token"] = ""
    logger.info("[User Logout] User logged out successfully.")
    return {"status": "ok"}


@router.post("/confirm-email/{token}/")
def confirm_email(
    token: str,
    session=Depends(db),
):
    logger.info(f"[Confirm Email] Attempting to confirm email with token: {token}")
    user = services.verify_email_confirmation_token(session=session, token=token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token",
        )
    user.email_confirmed = True
    session.commit()
    session.refresh(user)

    # login user
    access_token = services.create_user_access_token(user)
    response = Response(status_code=status.HTTP_200_OK)
    response = services.set_access_token_cookie(response, access_token)
    response.headers["X-Access-Token"] = access_token
    logger.info("[Confirm Email] Email confirmed successfully.")

    return response


@router.post("/forgot-password/")
def forgot_password(
    forgot_password_payload: ForgotPasswordPayload,
    session=Depends(db),
):
    logger.info(
        f"[Forgot Password] Password reset request received for email: {forgot_password_payload.email}",
    )
    user = User.get_by_email_and_type(
        session=session,
        email=forgot_password_payload.email,
        user_type=forgot_password_payload.user_type,
    )
    if not user:
        return {"status": "ok"}
    send_forgot_password_email(
        user_name=user.name,
        user_email=user.email,
        token=services.generate_password_reset_token(user),
    )
    return {"status": "ok"}


@router.post("/reset-password/")
def reset_password(
    reset_password_payload: ResetPasswordPayload,
    session=Depends(db),
):
    logger.info("[Reset Password] Attempting to reset password for user.")
    user = services.verify_token_and_reset_password(
        reset_password_payload=reset_password_payload,
        session=session,
    )
    if not user:
        logger.error("[Reset Password] Invalid token.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token",
        )
    return {"status": "ok"}


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


@router.post("/send-email-confirmation/")
def send_email_confirmation(
    current_user: User = Depends(get_current_user),
):
    """Send email confirmation."""
    send_email_confirmation_email(
        user_name=current_user.name,
        user_email=current_user.email,
        token=services.generate_email_confirmation_token(current_user),
    )
    return {"status": "ok"}


@router.post("/api-key/")
def generate_api_key(
    current_user: User = Depends(get_current_user),
    session=Depends(db),
):
    """Generate API Key."""
    api_key: APIKeyResponse = services.generate_api_key(current_user, session)
    return api_key
