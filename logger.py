import json
import os
from datetime import datetime

LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

def log_packet_rate(ip, packet_count, duration):
    log_entry = {'timestamp': datetime.now().isoformat(), 'packet_count': packet_count, 'duration': duration}
    logfile = os.path.join(LOG_DIR, f'{ip}.json')

    if os.path.exists(logfile):
        with open(logfile, 'r') as file:
            data = json.load(file)
    else:
        data = []

    data.append(log_entry)

    with open(logfile, 'w') as file:
        json.dump(data, file)

def load_logs(ip):
    logfile = os.path.join(LOG_DIR, f'{ip}.json')
    if os.path.exists(logfile):
        with open(logfile, 'r') as file:
            return json.load(file)
    return []
