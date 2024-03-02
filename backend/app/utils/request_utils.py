import json
import mimetypes

from requests_toolbelt.multipart.encoder import MultipartEncoder


def create_multipart_body(
    metadata,
    file_stream,
    file_name,
    file_mime_type=None,
):
    """
    Creates a multipart/form-data body for HTTP requests, specifically tailored for uploading
    files along with metadata to the YouTube API.

    This method constructs the multipart body required for the YouTube API calls where a file
    and its associated metadata need to be uploaded simultaneously.

    Parameters:
    - metadata (dict): A dictionary containing the metadata for the file. This should include
        fields such as 'snippet' and 'status'.
    - file_stream (file-like object): The file-like object representing the file to be uploaded.
    - file_name (str): The name of the file to be uploaded.
    - file_mime_type (str, optional): The MIME type of the file. If not provided, the MIME type
        will be guessed based on the file name. Defaults to 'application/octet-stream' if MIME
        type cannot be determined.

    Returns:
    MultipartEncoder: A multipart/form-data encoded object ready to be sent in an HTTP request.
    """

    if not metadata or not isinstance(metadata, dict):
        raise ValueError("Metadata must be a non-empty dictionary.")

    if not file_stream:
        raise ValueError("File stream cannot be None or empty.")

    if not file_name or not isinstance(file_name, str):
        raise ValueError("File name must be a non-empty string.")

    if file_mime_type is not None and not isinstance(file_mime_type, str):
        raise ValueError("File MIME type must be a string.")

    if not file_mime_type:
        file_mime_type = (
            mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        )

    metadata_json = json.dumps(metadata)

    multipart_data = MultipartEncoder(
        fields={
            "part": ("metadata", metadata_json, "application/json"),
            "file": (file_name, file_stream, file_mime_type),
        },
    )

    return multipart_data
