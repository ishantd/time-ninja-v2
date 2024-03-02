import enum
from typing import Optional

from pydantic import BaseModel, validator

from app.api.v1.user.models import UserType


class Provider(str, enum.Enum):
    """User providers."""

    GOOGLE = "google"
    APPLE = "apple"
    EMAIL = "email"


class UserSignupPayload(BaseModel):
    """User signup payload."""

    provider: Provider
    user_type: UserType
    email: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    name: Optional[str] = None
    profile_image: Optional[str] = None

    # Email Validator
    @validator("email", pre=True, allow_reuse=True)
    def validate_email(cls, v):
        if v is not None:
            return v.lower().strip()
        return v


class UserLoginPayload(BaseModel):
    """User login payload."""

    provider: Provider
    user_type: UserType
    email: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    retool_token: Optional[str] = None

    @validator("email", pre=True, allow_reuse=True)
    def validate_email(cls, v):
        if v is not None:
            return v.lower().strip()
        return v


class ForgotPasswordPayload(BaseModel):
    """Forgot password payload."""

    user_type: UserType
    email: str

    @validator("email", pre=True, allow_reuse=True)
    def validate_email(cls, v):
        return v.lower().strip()


class ResetPasswordPayload(BaseModel):
    """Reset password payload."""

    password: str
    token: str


class TokenData(BaseModel):
    """Token data."""

    user_id: int
    user_type: str
    email: str
    name: Optional[str] = None
    profile_image: Optional[str] = None
    admin: bool = False
    email_confirmed: bool = False

    @validator("email", pre=True, allow_reuse=True)
    def validate_email(cls, v):
        return v.lower().strip()


class APIKeyResponse(BaseModel):
    """API Key Response."""

    key: str
    expires_at: str
    user_id: int
