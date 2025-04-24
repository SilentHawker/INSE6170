import json
import os
from datetime import datetime, timedelta

LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

def log_packet_rate(ip, packet_count, duration):
    """Log packet rate for a specific IP."""
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

def load_logs(ip, days=None):
    """
    Load logs for a specific IP.
    If `days` is provided, only return logs from the last `days` days.
    """
    logfile = os.path.join(LOG_DIR, f'{ip}.json')
    if not os.path.exists(logfile):
        return []

    with open(logfile, 'r') as file:
        data = json.load(file)

    if days is not None:
        cutoff_date = datetime.now() - timedelta(days=days)
        data = [entry for entry in data if datetime.fromisoformat(entry['timestamp']) >= cutoff_date]

    return data

def delete_logs(ip=None):
    """
    Delete logs for a specific IP or all logs if `ip` is None.
    """
    if ip:
        logfile = os.path.join(LOG_DIR, f'{ip}.json')
        if os.path.exists(logfile):
            os.remove(logfile)
            print(f"Deleted logs for {ip}")
        else:
            print(f"No logs found for {ip}")
    else:
        for file in os.listdir(LOG_DIR):
            os.remove(os.path.join(LOG_DIR, file))
        print("Deleted all logs")

def cleanup_logs(days):
    """
    Delete outdated logs older than `days` days.
    """
    cutoff_date = datetime.now() - timedelta(days=days)
    for file in os.listdir(LOG_DIR):
        logfile = os.path.join(LOG_DIR, file)
        with open(logfile, 'r') as f:
            data = json.load(f)

        # Filter out outdated records
        updated_data = [entry for entry in data if datetime.fromisoformat(entry['timestamp']) >= cutoff_date]

        if updated_data:
            with open(logfile, 'w') as f:
                json.dump(updated_data, f)
        else:
            os.remove(logfile)  # Delete the file if all records are outdated
            print(f"Deleted outdated log file: {file}")
