"""API Route handlers for misc."""

from fastapi import APIRouter, Depends, Response, status

from app.api.v1.misc import services
from app.api.v1.misc.schemas import ContactUsPayload
from app.database import db

router = APIRouter()


@router.post("/contact-us", status_code=status.HTTP_201_CREATED)
async def create_contact_us(
    payload: ContactUsPayload,
    session=Depends(db),
) -> Response:
    """Create a contact us."""
    await services.create_contact_us(session, payload)
    return Response(status_code=status.HTTP_201_CREATED)
