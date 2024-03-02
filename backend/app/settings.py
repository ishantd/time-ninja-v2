import functools
import os
from functools import lru_cache

import pytz
from pydantic_settings import BaseSettings
from yarl import URL

from app import constants


class Settings(BaseSettings):
    """
    Application settings. Defaults to production.
    """

    # fastapi + uvicorn
    workers_count: int = 1  # quantity of workers for uvicorn
    reload: bool = False  # Enable uvicorn reloading
    proxy_headers: bool = True  # Enable proxy headers for uvicorn
    host: str = "0.0.0.0"
    port: int = 8000
    secret_key: str = "secret"
    # basics
    env: str = constants.DEVELOPMENT
    token_secret: str = ""
    debug: bool = False

    # database
    db_name: str
    db_user: str
    db_password: str
    db_host: str
    db_port: int
    db_echo: bool = False

    # google
    google_client_id: str
    google_client_secret: str

    # sentry
    sentry_dsn: str = ""

    # timezone
    timezone_str: str = "Asia/Kolkata"

    @property
    def db_url(self) -> URL:
        """
        Assemble database URL from settings.

        :return: database URL.
        """
        return URL.build(
            scheme="postgresql",
            path=f"/{self.db_name}",
            host=self.db_host or "localhost",
            port=self.db_port or 5432,
            user=self.db_user or "postgres",
            password=self.db_password,
        )

    @property
    def frontend_url(self):
        """
        Frontend URL for the application.
        """
        if self.env == constants.PRODUCTION:
            return "https://thetime.ninja"
        else:
            return "http://127.0.0.1:3000"

    @property
    def time_base_url(self):
        if self.env == constants.PRODUCTION:
            return "https://api.thetime.ninja"
        else:
            return "http://127.0.0.1:8000"

    @property
    def email_confirmation_required(self):
        return self.env == constants.PRODUCTION

    @property
    def send_confirmation_email_on_signup(self):
        return self.env == constants.PRODUCTION or self.env == constants.STAGING

    @property
    def timezone(self):
        return pytz.timezone(self.timezone_str)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"


def _parse_env() -> str:
    TESTING_VARS = ["TEST", "TESTING"]
    STAGING_VARS = ["STG", "STAGE", "STAGING"]
    PRODUCTION_VARS = ["PRD", "PROD", "PRODUCTION"]

    os_env = os.environ.get("ENV")

    # temp fix
    os_env = constants.PRODUCTION if os_env is None else os_env.upper()

    if os_env in PRODUCTION_VARS:
        os_env = constants.PRODUCTION
    elif os_env in STAGING_VARS:
        os_env = constants.STAGING
    elif os_env in TESTING_VARS:
        os_env = constants.TESTING
    else:
        os_env = constants.DEVELOPMENT

    return os_env


@lru_cache  # Make sure that we are reading from the env, disk only once
def _get_settings():
    os_env = _parse_env()
    settings = Settings(env=os_env)
    if settings.env == constants.TESTING:
        db_suffix = os.environ.get("PYTEST_XDIST_WORKER", "")
        settings = Settings(
            env=os_env,
            db_name="time_test" + db_suffix,
            token_secret="test",
        )
    return settings


settings = _get_settings()


def not_in_production(func):
    """
    This is a decorator that lets functions
    run when not in production environment
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not settings.env == constants.PRODUCTION:
            return func(*args, **kwargs)
        else:
            pass

    return wrapper


def only_in_prod_or_staging(func):
    """
    This is a decorator that lets functions
    run only in production OR staging environment
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if settings.env == constants.PRODUCTION or settings.env == constants.STAGING:
            return func(*args, **kwargs)
        else:
            pass

    return wrapper


def only_in_prod(func):
    """
    This is a decorator that lets functions
    run only in production environment, use cases
    might be: send an email, send slack message etc.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if settings.env == constants.PRODUCTION:
            return func(*args, **kwargs)
        else:
            pass

    return wrapper
