from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from app.api.app import get_app
from app.api.v1.auth import services as auth_services
from app.api.v1.auth.schemas import UserSignupPayload
from app.database import db
from app.settings import settings


def _create_database() -> None:
    """Create a database for tests."""
    db_url = make_url(str(settings.db_url.with_path("/postgres")))
    engine = create_engine(
        db_url,
        isolation_level="AUTOCOMMIT",
        pool_size=100,
        max_overflow=200,
    )

    with engine.connect() as conn:
        database_existance = conn.execute(
            text(f"SELECT 1 FROM pg_database WHERE datname='{settings.db_name}'"),
        )
        database_exists = database_existance.scalar() == 1

    if database_exists:
        _drop_database()

    with engine.connect() as conn:
        conn.execute(
            text(
                f'CREATE DATABASE "{settings.db_name}" ENCODING "utf8" TEMPLATE template1',
            ),
        )


def _drop_database() -> None:
    """Drop current database."""
    db_url = make_url(str(settings.db_url.with_path("/postgres")))
    engine = create_engine(db_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        disc_users = (
            "SELECT pg_terminate_backend(pg_stat_activity.pid) "
            "FROM pg_stat_activity "
            f"WHERE pg_stat_activity.datname = '{settings.db_name}' "
            "AND pid <> pg_backend_pid();"
        )
        conn.execute(text(disc_users))
        conn.execute(text(f'DROP DATABASE "{settings.db_name}"'))


@pytest.fixture(scope="session")
def _engine() -> Generator[Engine, None, None]:
    """Create engine and databases.

    :yield: new engine.
    """
    from app.database import Base

    _create_database()

    engine = create_engine(str(settings.db_url))

    Base.metadata.create_all(engine)

    try:
        yield engine
    finally:
        engine.dispose()
        _drop_database()


@pytest.fixture
def dbsession(_engine: Engine) -> Generator[Session, None, None]:
    """Get session to database.

    :param _engine: current engine.
    :yields: async session.
    """
    connection = _engine.connect()
    connection.begin()

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    session = SessionLocal()

    try:
        yield session
    finally:
        session.commit()
        session.close()
        connection.close()


@pytest.fixture
def fastapi_app(dbsession: Session) -> FastAPI:
    """Fixture for creating FastAPI app."""

    def session_gen():
        yield dbsession

    application = get_app()
    application.dependency_overrides[db] = session_gen
    return application


@pytest.fixture
def client(fastapi_app: FastAPI) -> Generator[TestClient, None, None]:
    """Fixture that creates client for requesting server."""
    with TestClient(fastapi_app) as client:
        yield client


@pytest.fixture
def auth_creator_client(
    fastapi_app: FastAPI,
    dbsession: Session,
) -> Generator[TestClient, None, None]:
    """Fixture that creates client for requesting server as an authenticated user."""
    with TestClient(fastapi_app) as authed_client:
        TEST_USER_EMAIL = "auth_creator_client@test.com"
        TEST_USER_PASSWORD = "SomeStrongPa$$w0rd"
        signup_payload = UserSignupPayload(
            provider="email",
            user_type="creator",
            email=TEST_USER_EMAIL,
            password=TEST_USER_PASSWORD,
        )
        user = auth_services.create_user(
            user_signup_payload=signup_payload,
            session=dbsession,
        )
        access_token = auth_services.create_user_access_token(
            user,
        )
        authed_client.headers = {
            **authed_client.headers,
            "Authorization": f"Bearer {access_token}",
        }
        yield authed_client


@pytest.fixture
def auth_business_client(
    fastapi_app: FastAPI,
    dbsession: Session,
) -> Generator[TestClient, None, None]:
    """Fixture that creates client for requesting server as an authenticated user."""
    with TestClient(fastapi_app) as authed_client:
        TEST_USER_EMAIL = "auth_business_client@test.com"
        TEST_USER_PASSWORD = "SomeStrongPa$$w0rd"
        signup_payload = UserSignupPayload(
            provider="email",
            user_type="business",
            email=TEST_USER_EMAIL,
            password=TEST_USER_PASSWORD,
        )
        user = auth_services.create_user(
            user_signup_payload=signup_payload,
            session=dbsession,
        )
        access_token = auth_services.create_user_access_token(
            user,
        )
        authed_client.headers = {
            **authed_client.headers,
            "Authorization": f"Bearer {access_token}",
        }
        yield authed_client


@pytest.fixture
def admin_client(
    fastapi_app: FastAPI,
    dbsession: Session,
) -> Generator[TestClient, None, None]:
    """Fixture that creates client for requesting server as an admin."""
    with TestClient(fastapi_app) as authed_client:
        TEST_USER_EMAIL = "test5@test.com"
        TEST_USER_PASSWORD = "SomeStrongPa$$w0rd"
        user = auth_services.create_user(
            dbsession,
            email=TEST_USER_EMAIL,
            password=TEST_USER_PASSWORD,
            is_admin=True,
        )
        access_token = auth_services.create_user_access_token(user)
        authed_client.headers = {
            **authed_client.headers,
            "Authorization": f"Bearer {access_token}",
        }
        yield authed_client
