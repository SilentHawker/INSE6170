from scapy.all import sniff
import threading
import time  # Import the time module
from logger import log_packet_rate

def monitor_device(ip, threshold=100, duration=10, alert_callback=None, stop_event=None):
    print(f"Monitoring {ip} for abnormal traffic...")
    start_time = time.time()

    while time.time() - start_time < duration:
        if stop_event and stop_event.is_set():
            print(f"Stopped monitoring {ip}")
            return

        packets = sniff(filter=f"host {ip}", timeout=1)
        packet_count = len(packets)

        # Log packets after capture
        log_packet_rate(ip, packet_count, duration)

        if packet_count > threshold:
            alert_message = f"ALERT: High traffic from {ip}! ({packet_count} packets in {duration} sec)"
            print(alert_message)
            if alert_callback:
                alert_callback(alert_message)
        else:
            print(f"No anomaly detected from {ip} ({packet_count} packets).")
