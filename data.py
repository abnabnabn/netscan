# data.py
import json
import logging
from typing import List, Dict
from pathlib import Path

logger = logging.getLogger(__name__)
def load_device_data(json_file: Path) -> List[Dict]:
    """Loads device data from the JSON file."""
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
            # No conversion to Device objects needed
            return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning(f"Error loading JSON data: {e}. Returning empty list.")
        return []

def save_device_data(data: List[Dict], json_file: Path):
    """Saves device data to the JSON file."""
    try:
        with open(json_file, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving JSON data: {e}")