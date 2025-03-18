from scapy.all import sniff
import threading
from logger import log_packet_rate

def monitor_device(ip, threshold=100, duration=10, alert_callback=None):
    print(f"Monitoring {ip} for abnormal traffic...")
    packets = sniff(filter=f"host {ip}", timeout=duration)
    packet_count = len(packets)

    # Clearly logging packets after capture
    log_packet_rate(ip, packet_count, duration)

    if packet_count > threshold:
        alert_message = f"ALERT: High traffic from {ip}! ({packet_count} packets in {duration} sec)"
        print(alert_message)
        if alert_callback:
            alert_callback(alert_message)
    else:
        print(f"No anomaly detected from {ip} ({packet_count} packets).")
