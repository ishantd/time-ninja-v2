from __future__ import annotations

from typing import Optional

from sqlalchemy import Column
from sqlalchemy.sql.sqltypes import Integer, String

from app.database import Base


class User(Base):
    """User database model."""

    __tablename__ = "users"
    __table_args__ = ()

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, index=True)
    name = Column(String, nullable=True)
    profile_image = Column(String, nullable=True)

    def __init__(
        self,
        email: str,
        email_confirmed: Optional[bool] = False,
        admin: Optional[bool] = False,
        name: Optional[str] = None,
    ):
        self.email = email
        self.email_confirmed = email_confirmed
        self.admin = admin
        self.name = name.title() if name else None

    def __repr__(self) -> str:
        return f"User {self.id}: {self.email}"


# # Path: app/api/v1/user/models.py
