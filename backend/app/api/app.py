import time
from typing import Awaitable, Callable
from urllib.parse import urlparse

import sentry_sdk
from fastapi import FastAPI, Request
from fastapi.responses import UJSONResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

import app.constants as constants
from app.api.v1.router import api_router
from app.database import load_all_models
from app.settings import settings


def filter_transactions(event, hint):
    url_string = event["request"]["url"]
    parsed_url = urlparse(url_string)

    if "health" in parsed_url.path:
        return None

    return event


def get_app() -> FastAPI:
    """
    Application factory.
    Get FastAPI application.

    This is the main constructor of an application.

    :return: application.
    """
    sentry_sdk.init(
        settings.sentry_dsn,
        traces_sample_rate=1.0,
        environment=settings.env,
        traces_sampler=constants.SENTRY_TRACES_SAMPLER,
        profiles_sampler=constants.SENTRY_PROFILES_SAMPLER,
        debug=settings.env in [constants.DEVELOPMENT, constants.TESTING]
        and settings.debug,
        before_send_transaction=filter_transactions,
    )

    app = FastAPI(
        title="time",
        description="The ReachHub backend app",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        default_response_class=UJSONResponse,
    )

    load_all_models()

    register_startup_event(app)
    register_shutdown_event(app)

    allowed_origins = [
        settings.frontend_url,
        "https://www.thetime.ninja",
    ]

    if settings.env in [constants.DEVELOPMENT, constants.TESTING]:
        allowed_origins.append("http://localhost:3000")

    default_headers_allowed = ["Content-Type", "Authorization", "X-Workspace-Code"]

    if settings.env in [constants.PRODUCTION]:
        default_headers_allowed.extend(["Sentry-Trace", "Baggage"])

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=default_headers_allowed,
    )

    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key)

    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        """
        Add a custom header X-Process-Time containing
        the time in seconds that it took to process
        the request and generate a response
        """
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response

    # if settings.env in [constants.STAGING, constants.PRODUCTION]:
    #     app.add_middleware(LoggingMiddleware)
    #     setup_logging()

    app.include_router(router=api_router)

    return app


def register_startup_event(app: FastAPI) -> Callable[[], Awaitable[None]]:
    """
    Actions to run on application startup.

    This function use fastAPI app to store data,
    such as db_engine.

    :param app: the fastAPI application.
    :return: function that actually performs actions.
    """

    @app.on_event("startup")
    async def _startup() -> None:  # noqa: WPS430
        # TODO: check if db session is set up and active
        try:
            pass
        except Exception:
            pass

    return _startup


def register_shutdown_event(app: FastAPI) -> Callable[[], Awaitable[None]]:
    """
    Actions to run on application's shutdown.

    :param app: fastAPI application.
    :return: function that actually performs actions.
    """

    @app.on_event("shutdown")
    def _shutdown() -> None:  # noqa: WPS430
        # TODO: finish processing all current requests
        pass  # noqa: WPS420

    return _shutdown
