import os
import re
import requests

def get_vendor(mac):
    """Fetch the vendor information for a given MAC address."""
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"

def get_connected_devices():
    """Fetch the list of connected devices on the local network using the 'arp -a' command."""
    devices = []
    try:
        # Run the 'arp -a' command to get the list of devices
        output = os.popen('arp -a').read()

        # Parse the output using a regex pattern
        pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})'
        matches = re.findall(pattern, output)

        # Build the list of devices
        for ip, mac in matches:
            devices.append({
                "IPv4": ip,
                "MAC": mac,
                "Vendor": get_vendor(mac)
            })

        return devices

    except Exception:
        return []
