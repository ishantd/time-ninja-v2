import json


def read_json_file(file_path: str) -> dict:
    """Function to read a JSON file."""
    with open(file_path, "r") as f:
        json_data = json.load(f)
    return json_data
