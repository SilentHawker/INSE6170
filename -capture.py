import os
from scapy.all import sniff, wrpcap

def capture_packets(ip, filename, packet_count=50, timeout=10):
    os.makedirs("captures", exist_ok=True)  # clearly ensure the captures directory exists
    filepath = f"captures/{filename}"

    print(f"Starting packet capture for IP: {ip}")
    packets = sniff(filter=f"host {ip}", count=packet_count, timeout=timeout)
    wrpcap(filepath, packets)
    print(f"Capture complete! {len(packets)} packets saved to {filepath}")
