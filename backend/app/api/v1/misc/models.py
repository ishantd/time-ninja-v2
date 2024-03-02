"""DB Models for misc."""

from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.sqltypes import Boolean, Integer, String

from app.database import Base


class ContactUs(Base):
    """ContactUs model."""

    __tablename__ = "contact_us"
    __table_args__ = {}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, index=True)
    message = Column(String, index=True)
    is_read = Column(Boolean, default=False)
    is_responded = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
