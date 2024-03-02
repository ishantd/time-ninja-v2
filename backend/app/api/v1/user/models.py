from __future__ import annotations

import enum
from typing import Optional

import bcrypt
from sqlalchemy import Column, Enum, UniqueConstraint
from sqlalchemy.schema import ForeignKey
from sqlalchemy.sql.sqltypes import Boolean, Integer, String

from app.database import Base


class UserType(enum.Enum):
    """User types."""

    CREATOR = "creator"
    BUSINESS = "business"


class Gender(enum.Enum):
    """Gender for users"""

    MALE = "male"
    FEMALE = "female"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"


class User(Base):
    """User database model."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", "user_type", name="email_user_type_unique"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    active = Column(Boolean, default=True, nullable=False)
    email = Column(String(255), nullable=False, index=True)
    admin = Column(Boolean, default=False, nullable=False)
    password = Column(String(255), nullable=True)
    email_confirmed = Column(Boolean, default=False, nullable=False)
    user_type = Column(
        Enum(UserType),
        default=UserType.CREATOR,
        nullable=False,
        index=True,
        name="user_type",
    )
    name = Column(String, nullable=True)
    profile_image = Column(String, nullable=True)

    def __init__(
        self,
        email: str,
        password: str = None,
        user_type: UserType = UserType.CREATOR,
        email_confirmed: Optional[bool] = False,
        admin: Optional[bool] = False,
        name: Optional[str] = None,
    ):
        self.email = email
        if password:
            self.password = generate_password_hash(password)
        self.email_confirmed = email_confirmed
        self.admin = admin
        self.name = name.title() if name else None
        self.user_type = user_type

    def __repr__(self) -> str:
        return f"User {self.id}: {self.email}"

    @staticmethod
    def get_by_email_and_type(
        session,
        email: str,
        user_type: UserType,
    ) -> Optional[User]:
        """Get a user by their email."""
        return session.query(User).filter_by(email=email, user_type=user_type).first()

    @staticmethod
    def get_by_id_and_type(
        session,
        id: int,
        user_type: UserType,
    ) -> Optional[User]:
        """Get a user by their email."""
        return session.query(User).filter_by(id=id, user_type=user_type).first()


def generate_password_hash(password: str) -> str:
    """Bcrypts a password, returns a hash string"""
    pwd_bytes = password.encode("ascii")
    salt_bytes = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt_bytes).decode("ascii")


class Profile(Base):
    """User profile database model."""

    __tablename__ = "profiles"
    __table_args__ = {}

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(ForeignKey("users.id"), nullable=True, index=True)
    age = Column(Integer, nullable=True)
    email = Column(String, nullable=True)
    phone_number = Column(String, nullable=True)
    gender = Column(
        Enum(Gender),
        nullable=True,
        index=True,
    )
    creator_profile_category_id = Column(
        ForeignKey("creator_profile_categories.id"),
        nullable=True,
        index=True,
    )
    location = Column(String, nullable=True)
    tile_image = Column(String, nullable=True)
    tile_background_image = Column(String, nullable=True)
    expected_reach = Column(Integer, nullable=True)
    average_likes = Column(Integer, nullable=True)
    min_cost_sponsored_post = Column(Integer, nullable=True)
    max_cost_sponsored_post = Column(Integer, nullable=True)
    ready_to_use = Column(Boolean, default=False, nullable=False)
    connected_instagram_id = Column(
        ForeignKey("instagram_profiles.id"),
        nullable=True,
        index=True,
        unique=True,
    )


class CreatorProfileCategories(Base):
    """Creator profile categories database model."""

    __tablename__ = "creator_profile_categories"
    __table_args__ = {}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False, index=True, unique=True)
    description = Column(String, nullable=True)

    def __init__(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ):
        self.name = name
        self.description = description


# # Path: app/api/v1/user/models.py
