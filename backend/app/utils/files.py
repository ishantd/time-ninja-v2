import os
from io import BytesIO

import requests


def download_media(media_url: str):
    """
    Download media from url.
    """
    response = requests.get(media_url, stream=True, verify=False)
    if response.status_code != requests.codes.ok:
        return b""
    file_content = BytesIO()
    for chunk in response.iter_content(1024 * 1024):
        file_content.write(chunk)
    return file_content


def delete_temp_files(file_locations: list):
    """
    Delete temp files.
    """
    for file_location in file_locations:
        try:
            os.remove(file_location)
        except Exception:
            continue


def save_bytes_to_file(bytes: bytes, filename: str) -> str:
    if not os.path.exists("temp"):
        os.makedirs("temp")
    file_location = f"temp/{filename}"
    with open(file_location, "wb") as f:
        f.write(bytes)
    return file_location
