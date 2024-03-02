"""Schemas for misc."""

from pydantic import BaseModel


class ContactUsPayload(BaseModel):
    """ContactUs payload."""

    name: str
    email: str
    message: str
