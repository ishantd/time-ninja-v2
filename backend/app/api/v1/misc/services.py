"""Services for misc."""

from sqlalchemy.orm import Session

from app.api.v1.misc.models import ContactUs
from app.api.v1.misc.schemas import ContactUsPayload
from app.settings import settings
from app.utils.ses import send_templated_email
from app.utils.slack import post_message_to_reachhub_slack_channel


async def create_contact_us(session: Session, payload: ContactUsPayload) -> ContactUs:
    """Create a contact us."""
    contact_us = ContactUs(**payload.model_dump())
    session.add(contact_us)
    session.commit()

    await send_contact_us_response(payload)

    return contact_us


def create_contact_us_slack_message(payload: ContactUsPayload) -> str:
    """Create a contact us slack message."""
    return f"""
    *Contact Us*\n\n*Name*: {payload.name}\n*Email*: {payload.email}\n*Message*: {payload.message}
    """


async def send_contact_us_response(payload: ContactUsPayload) -> None:
    """Send a contact us response."""
    post_message_to_reachhub_slack_channel(
        channel=settings.slack_channel_contact_us_responses,
        text=create_contact_us_slack_message(payload),
    )

    await send_templated_email(
        to_email=payload.email,
        template_name="contact_us_response_email.html",
        template_data={
            "name": payload.name,
        },
        subject="Hello from Reach Hub! We Got Your Message 🚀",
    )
