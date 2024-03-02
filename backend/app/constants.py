"""
Constants used throughout the codebase

If your constants are highly specific and are only used in your module, please
make a `constants.py` in your module.
"""

# Environment names
import enum

PRODUCTION = "PRODUCTION"
STAGING = "STAGING"
DEVELOPMENT = "DEVELOPMENT"
TESTING = "TESTING"

SENTRY_TRACES_SAMPLER = 1.0
SENTRY_PROFILES_SAMPLER = 1.0


class RequestMethodVerbMapping(enum.Enum):
    POST = "post"
    PUT = "put"
    DELETE = "delete"
    GET = "get"
