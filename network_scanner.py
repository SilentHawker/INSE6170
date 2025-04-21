import os, re, requests

def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}")
        if response.status_code == 200:
            return response.text
        return "Unknown"
    except:
        return "Unknown"

def get_connected_devices():
    output = os.popen('arp -a').read()
    pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9-]{17})'
    matches = re.findall(pattern, output)

    devices = []
    for ip, mac in matches:
        devices.append({
            'IPv4': ip,
            'MAC': mac,
            'Vendor': get_vendor(mac)
        })
    return devices
