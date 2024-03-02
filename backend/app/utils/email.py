import asyncio

from app.settings import settings
from app.utils import ses as ses_utils


def send_email_confirmation_email(user_name: str, user_email: str, token: str):
    """
    Send email confirmation email.

    Args:
        user (User): User to send email to.
        token (str): Token to confirm email.

    """
    body = f"""
    <html>
    <head></head>
    <body>
        <h1>Hi {user_name or "there"},</h1>
        <p>
            Please confirm your email by clicking on the link below.
        </p>
        <a href="{settings.frontend_url}/confirm-email?token={token}">Confirm Email</a>
    </body>
    </html>
    """
    asyncio.run(
        ses_utils.send_html_email(
            to_email=user_email,
            subject="[Reach Hub] Confirm your email",
            body=body,
        ),
    )


def send_welcome_email(user_name: str, user_email: str):
    """
    Send welcome email.

    Args:
        user (User): User to send email to.

    """
    body = f"""
    <html>
    <head></head>
    <body>
        <h1>Hi {user_name or "there"},</h1>
        <p>
            Welcome to Reach Hub! We are excited to have you on board.
        </p>
    </body>
    </html>
    """
    asyncio.run(
        ses_utils.send_html_email(
            to_email=user_email,
            subject="[Reach Hub] Welcome!",
            body=body,
        ),
    )


def send_forgot_password_email(user_name: str, user_email: str, token: str):
    """
    Send forgot password email.

    Args:
        user (User): User to send email to.
        token (str): Token to reset password.

    """
    body = f"""
    <html>
    <head></head>
    <body>
        <h1>Hi {user_name or "there"},</h1>
        <p>
            Please reset your password by clicking on the link below.
        </p>
        <a href="{settings.frontend_url}/reset-password?token={token}">Reset Password</a>
    </body>
    </html>
    """
    asyncio.run(
        ses_utils.send_html_email(
            to_email=user_email,
            subject="[Reach Hub] Reset your password",
            body=body,
        ),
    )
