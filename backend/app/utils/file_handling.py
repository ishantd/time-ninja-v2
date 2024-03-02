from app.utils.strings import generate_random_string


def create_bucket_file_name(user_id: int, file_name: str) -> str:
    return f"users/{user_id}/content/{generate_random_string(16)}.{file_name.split('.')[-1]}"


def create_thumbnail_bucket_file_name(user_id: int, file_name: str) -> str:
    return f"users/{user_id}/content/thumbnail/{generate_random_string(16)}.jpeg"


def get_s3_url_from_bucket_and_file_name(
    bucket_name: str,
    bucket_file_name: str,
) -> str:
    return f"https://{bucket_name}.s3.amazonaws.com/{bucket_file_name}"
