import os
import re
import requests

def get_vendor(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown"
    except Exception as e:
        return f"Error: {e}"

def get_connected_devices():
    output = os.popen('arp -a').read()
    
    print("ARP Table Output:\n", output)  # Debug output

    pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})'
    matches = re.findall(pattern, output)

    devices = []
    for ip, mac in matches:
        vendor = get_vendor(mac)  # Corrected function name here!
        device_info = {
            'IPv4': ip,
            'MAC': mac,
            'Vendor': vendor
        }
        devices.append(device_info)
    return devices

if __name__ == '__main__':
    devices = get_connected_devices()
    if not devices:
        print("No devices connected.")
    else:
        print("\nConnected Devices:")
        for device in devices:
            print(f"IP: {device['IPv4']}, MAC: {device['MAC']}, Vendor: {device['Vendor']}")
