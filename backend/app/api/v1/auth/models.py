"""DB Models for Auth."""

from datetime import datetime, timedelta

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, UniqueConstraint

from app.database import Base


class APIKey(Base):
    """API Key model."""

    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("key", name="key_unique"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String, nullable=False, unique=True)
    expires_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow() + timedelta(days=30),
    )
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    def __init__(self, key: str, user_id: int, expires_at: datetime = None):
        """Initialize API Key."""
        self.key = key
        self.user_id = user_id
        self.expires_at = expires_at or datetime.utcnow() + timedelta(days=30)
