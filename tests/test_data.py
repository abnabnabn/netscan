import json
import pytest
from pathlib import Path
from data import load_device_data, save_device_data

def test_load_device_data_success(tmp_path):
    data = [{"ip": "192.168.1.1", "mac": "AA-BB"}]
    json_file = tmp_path / "devices.json"
    with open(json_file, "w") as f:
        json.dump(data, f)
    
    loaded_data = load_device_data(json_file)
    assert loaded_data == data

def test_load_device_data_file_not_found():
    assert load_device_data(Path("non_existent.json")) == []

def test_load_device_data_invalid_json(tmp_path):
    json_file = tmp_path / "invalid.json"
    json_file.write_text("invalid json")
    assert load_device_data(json_file) == []

def test_save_device_data(tmp_path):
    data = [{"ip": "192.168.1.1", "mac": "AA-BB"}]
    json_file = tmp_path / "save.json"
    save_device_data(data, json_file)
    
    with open(json_file, "r") as f:
        saved_data = json.load(f)
    assert saved_data == data

def test_save_device_data_error(tmp_path):
    # Try to save to a directory as a file to trigger an OSError
    json_file = tmp_path / "dir"
    json_file.mkdir()
    # This should not raise an exception because of the try-except in save_device_data
    save_device_data([{}], json_file)
