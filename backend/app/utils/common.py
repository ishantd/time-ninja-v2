import base64
import json
import urllib.parse
from contextlib import contextmanager
from typing import Any, List, Optional

from fastapi.logger import logger
from sqlalchemy.orm import Session


def orm_object_to_dict(orm_object) -> str:
    """Returns a orm_object as a dict, removing the _sa_instance_state key."""
    if orm_object is None:
        return {}
    to_return = orm_object.__dict__.copy()
    to_return.pop("_sa_instance_state")
    # turns dates into strings
    return json.loads(json.dumps(to_return, default=str))


def as_percent(smaller_number: int, larger_number: int) -> str:
    if larger_number == 0:
        return "inf %"
    return f"{round((100.0 * smaller_number / larger_number), 1)} %"


@contextmanager
def attempt_commit_rollback_and_log_on_failure(
    session: Session,
    log_str: Optional[str] = "Exception while attempting to commit session",
):
    """Yields immediately, but attempts to commit the session on exit.
    If an exception is raised, the session is rolled back and the exception is logged.

    Args:
        session (Session): DB Session
    """
    try:
        yield
        session.commit()
    except Exception as e:
        session.rollback()
        logger.exception(f"{log_str}: {repr(e)}")


def log_or_raise(s, e=False):
    if e:
        logger.exception(s)
        raise Exception(s)
    else:
        logger.info(s)


def split_list_into_chunks(list: List[Any], chunk_size: int):
    for i in range(0, len(list), chunk_size):
        yield list[i : i + chunk_size]


def dict_to_query_params(d: dict, url_encode: bool = True) -> str:
    """Converts a dict to a url encoded query string and removes None values."""
    if url_encode:
        return urllib.parse.urlencode({k: v for k, v in d.items() if v is not None})
    else:
        return "&".join([f"{k}={v}" for k, v in d.items() if v is not None])


def query_params_to_dict(query_params: str) -> dict:
    """Converts a url encoded query string to a dict."""
    return dict(urllib.parse.parse_qsl(query_params))


def string_to_base64(s: str) -> str:
    """Converts a string to base64."""
    return base64.b64encode(s.encode("utf-8")).decode("utf-8")


def base64_to_string(s: str) -> str:
    """Converts a base64 string to a string."""
    return base64.b64decode(s).decode("utf-8")


def dict_to_base64(d: dict) -> str:
    """Converts a dict to base64."""
    return base64.b64encode(json.dumps(d).encode("utf-8")).decode("utf-8")


def base64_to_dict(s: str) -> dict:
    """Converts a base64 string to a dict."""
    return json.loads(base64.b64decode(s).decode("utf-8"))
