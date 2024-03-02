import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)


def datetime_object_to_utc_datetime_object(datetime_object: datetime) -> datetime:
    """Convert a datetime object to a UTC datetime object."""
    return datetime_object.astimezone(timezone.utc)


def str_to_datetime_object(string: str, timezone_str: str) -> datetime:
    """Convert a string to a timezone-aware datetime object."""
    format = "%Y-%m-%dT%H:%M:%S%z"
    try:
        return datetime.strptime(string, format).replace(tzinfo=ZoneInfo(timezone_str))
    except ValueError as e:
        logger.warning(f"ValueError when converting string {string}: {e}")
        return datetime.strptime(string, "%Y-%m-%dT%H:%M:%S.%f%z").replace(
            tzinfo=ZoneInfo(timezone_str),
        )
    except ZoneInfoNotFoundError as e:
        logger.error(f"Invalid timezone {timezone_str}: {e}")
        raise


def is_time_in_the_past_or_now(timestamp: datetime, past_threshold: int = 0) -> bool:
    """Check if a timestamp is in the past or now."""
    return timestamp <= datetime.now(timezone.utc) - timedelta(minutes=past_threshold)


def post_scheduling_time_is_in_the_past_or_now(
    scheduled_at: str,
    timezone_str: str,
    past_threshold: int = 0,
) -> bool:
    """Check if a post scheduling time is in the past or now."""
    try:
        scheduled_datetime = str_to_datetime_object(scheduled_at, timezone_str)
        return is_time_in_the_past_or_now(scheduled_datetime, past_threshold)
    except ZoneInfoNotFoundError:
        return False
