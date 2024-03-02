import logging.config

from pythonjsonlogger import jsonlogger
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app import constants
from app.api.v1.auth.schemas import TokenData
from app.api.v1.auth.services import get_auth_token_from_request
from app.settings import settings

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s]: %(message)s",
        },
        "json": {
            "()": jsonlogger.JsonFormatter,
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "DEBUG",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "app_logs.json",
            "formatter": "json",
            "level": "DEBUG",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console"],
            "level": "DEBUG",
        },
    },
}


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Logging middleware to log requests and responses.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """
        Log request and response.
        """
        token_data: TokenData = get_auth_token_from_request(request)

        user_id = token_data.user_id if token_data else None

        logger = logging.getLogger("fastapi")
        logger.info(
            "Request",
            extra={
                "user_id": user_id,
                "request": {
                    "method": request.method,
                    "url": request.url,
                    "headers": dict(request.headers),
                    "body": await request.body(),
                },
            },
        )

        response = None
        try:
            response = await call_next(request)
        except Exception as error:
            if (
                str(error) == "No response returned."
                and await request.is_disconnected()
            ):
                return Response(status_code=status.HTTP_204_NO_CONTENT)

            error_prefix = "[LoggingMiddleware] Unhandled request error %s %s: %s"

            logger.exception(
                error_prefix,
                request.method,
                request.url,
                str(error),
                exc_info=True,
                stack_info=True,
            )

            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "success": False,
                    "error": "Internal Server Error",
                    "exception": str(error),
                },
            )

        return response


def setup_logging():
    """
    Configure logging based on the environment.
    """
    if settings.env in [constants.STAGING, constants.PRODUCTION]:
        LOGGING_CONFIG["loggers"][""]["handlers"] = ["file"]
    logging.config.dictConfig(LOGGING_CONFIG)
