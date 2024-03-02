"""Generate random string."""
import math
import random
import string


def generate_random_string(length: int = 32) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def convert_bytes_to_readable(bytes: any) -> str:
    """Convert bytes to human readable."""
    if not isinstance(bytes, (int, float)):
        bytes = int(bytes)
    if bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(bytes, 1024)))
    p = math.pow(1024, i)
    s = round(bytes / p, 2)
    return f"{s}{size_name[i]}"


def randomize_filename(filename: str) -> str:
    """Randomize filename."""
    extension = filename.split(".")[-1]
    return f"{generate_random_string()}.{extension}"
