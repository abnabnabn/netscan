# data.py
import json
import logging
from typing import List, Dict
from pathlib import Path

logger = logging.getLogger(__name__)

def load_device_data(json_file: Path) -> List[Dict]:
    """Loads device data from the JSON file.

    Args:
        json_file (Path): Path to the JSON file.

    Returns:
        List[Dict]: A list of dictionaries containing device data.
    """
    try:
        with json_file.open("r", encoding="utf-8") as file:
            data = json.load(file)
            return data
    except FileNotFoundError as err:
        logger.warning("JSON file not found: %s. Returning empty list.", err)
    except json.JSONDecodeError as err:
        logger.warning("Error decoding JSON data: %s. Returning empty list.", err)
    return []

def save_device_data(data: List[Dict], json_file: Path) -> None:
    """Saves device data to the JSON file.

    Args:
        data (List[Dict]): A list of dictionaries to save.
        json_file (Path): Path to the JSON file.
    """
    try:
        with json_file.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
    except OSError as err:
        logger.error("File system error while saving JSON data: %s", err)
    except Exception as err:  # pylint: disable=broad-except
        logger.error("Unexpected error while saving JSON data: %s", err)