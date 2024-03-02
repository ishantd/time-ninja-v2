import datetime
from pathlib import Path
from typing import Any, Generator, Tuple, Type, TypeVar

from fastapi import HTTPException
from fastapi.logger import logger
from sqlalchemy import MetaData, Table, create_engine
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import (
    Session,
    as_declarative,
    declared_attr,
    relationship,
    scoped_session,
    sessionmaker,
)
from sqlalchemy.sql.schema import Column, ForeignKey
from sqlalchemy.sql.sqltypes import Boolean, DateTime, Integer

from app import constants
from app.settings import settings

# DB CONNECTION ----------------------------------------------------------------
engine = create_engine(
    str(settings.db_url),
    pool_timeout=10,
    connect_args={
        "connect_timeout": 10,
        "options": "-c statement_timeout=1800000",  # 30 minutes = 1800000 Milliseconds
    },
    pool_size=10,
    max_overflow=80,
    echo=settings.db_echo,
    pool_pre_ping=True,  # check connection before using
)

# trace SQL queries if we're in staging or production
if settings.env == constants.PRODUCTION or settings.env == constants.STAGING:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

    SQLAlchemyInstrumentor().instrument(
        engine=engine,
    )

session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def db() -> Generator[Session, None, None]:
    """Dependency for FastAPI Routes.
    Generates a DB session to use in each request.

    Yields:
        Session: Database Session
    """
    session = scoped_session(session_factory)()
    try:
        yield session
        session.commit()
    except HTTPException:
        # This is a controlled exception. No need to log it.
        session.rollback()
        raise
    except Exception as e:
        logger.exception(f"Exception while attempting to commit session: {repr(e)}")
        session.rollback()
        raise
    finally:
        session.close()


# DB MODEL BASE CLASS ----------------------------------------------------------

convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

meta = MetaData(naming_convention=convention)


def current_ist_time():
    return datetime.datetime.now(settings.timezone)


Self = TypeVar("Self", bound="Base")


# class for views
ViewBase = declarative_base()


@as_declarative(metadata=meta)
class Base:
    """
    Base for all models.

    It has some type definitions to
    enhance autocompletion.
    """

    __tablename__: str
    __table__: Table
    __table_args__: Tuple[Any, ...]

    # Add created and updated timestamps to all tables/models
    created_at = Column(DateTime, default=current_ist_time)
    updated_at = Column(DateTime, default=current_ist_time, onupdate=current_ist_time)
    is_deleted = Column(Boolean, nullable=False, default=False)

    @classmethod
    def get(cls: Type[Self], session: Session, ident: Any) -> Self:
        """Return an instance based on the given primary key identifier,
        or ``None`` if not found.

        E.g.::

            my_user = User.get(session, 5)

            some_object = VersionedFoo.get(session, (5, 10))

            some_object = VersionedFoo.get(session, {"id": 5, "version_id": 10})

        Args:
            session (Session): DB Connection.
            ident (Any): A scalar, tuple, or dictionary representing the
         primary key.  For a composite (e.g. multiple column) primary key,
         a tuple or dictionary should be passed.

        Returns:
            Any: The object instance, or ``None``.
        """
        return session.query(cls).get(ident)

    def to_dict(self, fields=None):
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
            if not fields or column.name in fields
        }


class TrackedCreatorBase(Base):
    """Version of `Base` that adds a `created_by` field.
    created_by or created_by_user must be specified when creating an object."""

    __abstract__ = True

    @declared_attr
    def created_by(self):
        return Column(Integer, ForeignKey("users.id"), nullable=False)

    @declared_attr
    def created_by_user(self):
        return relationship("User")

    @declared_attr
    def created_by_email(self):
        return association_proxy("created_by_user", "email")


# UTILITY FUNCTIONS ------------------------------------------------------------


def load_all_models() -> None:
    """Load all models from `app.api.v1`.
    Models must be in app/api/v1/*/models.py to be imported.
    """

    # Converts absolute path of a file ending in `models.py` to an import
    def path_to_import(p):
        return p[p.find("app") :].split(".py")[0].replace("/", ".")

    # Sort to make sure we don't have random circular imports
    model_paths = Path(__file__).parent.glob("api/v1/**/models.py")
    model_paths = list(model_paths)
    model_paths.sort()

    for path in model_paths:
        module_name = path_to_import(str(path))
        __import__(module_name)
