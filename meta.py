import json
import os

METADATA_FILE = 'device_metadata.json'

def load_metadata():
    if not os.path.exists(METADATA_FILE):
        return {}
    with open(METADATA_FILE, 'r') as f:
        return json.load(f)

def save_metadata(data):
    with open(METADATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_device_metadata(mac):
    data = load_metadata()
    return data.get(mac, {})

def set_device_metadata(mac, info):
    data = load_metadata()
    data[mac] = info
    save_metadata(data)
