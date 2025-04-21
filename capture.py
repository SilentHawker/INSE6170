import os
import threading
import time
from datetime import datetime
from scapy.all import sniff, wrpcap
from scapy.config import conf

class PacketCaptureManager:
    def __init__(self):
        self.captures_dir = "captures"
        self.active_captures = {}
        self.interface = "Wi-Fi"  # Your specific interface
        os.makedirs(self.captures_dir, exist_ok=True)
        
        # Configure Scapy to use your interface
        conf.iface = self.interface
        print(f"Using network interface: {self.interface}")

    def start_capture(self, device_info, packet_count=50, duration=10, filename=None):
        """Start packet capture on your specific interface"""
        try:
            ip = device_info['ipv4']
            mac = device_info['mac']
            
            if not ip:
                return {'success': False, 'error': "Device has no IP address"}
            
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"capture_{mac.replace(':', '-')}_{timestamp}.pcap"
            
            filepath = os.path.join(self.captures_dir, filename)
            stop_event = threading.Event()
            
            # Store capture info
            self.active_captures[mac] = {
                'device': device_info,
                'filepath': filepath,
                'stop_event': stop_event,
                'packets': [],
                'start_time': time.time(),
                'thread': None
            }
            
            # Start capture thread
            thread = threading.Thread(
                target=self._run_capture,
                args=(ip, mac, packet_count, duration, stop_event),
                daemon=True
            )
            self.active_captures[mac]['thread'] = thread
            thread.start()
            
            return {
                'success': True,
                'filepath': filepath,
                'message': f"Started capture for {device_info['name']} on {self.interface}"
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _run_capture(self, ip, mac, packet_count, duration, stop_event):
        """The actual capture process"""
        try:
            def packet_handler(pkt):
                self.active_captures[mac]['packets'].append(pkt)
                if packet_count and len(self.active_captures[mac]['packets']) >= packet_count:
                    stop_event.set()
            
            # Start sniffing with timeout
            sniff(
                filter=f"host {ip}",
                prn=packet_handler,
                store=False,
                timeout=duration,
                stop_filter=lambda _: stop_event.is_set()
            )
            
            # Save captured packets
            packets = self.active_captures[mac]['packets']
            if packets:
                wrpcap(self.active_captures[mac]['filepath'], packets)
                print(f"Captured {len(packets)} packets for {ip}")
            
        except Exception as e:
            print(f"Capture error: {str(e)}")
        finally:
            if mac in self.active_captures:
                self.active_captures.pop(mac)

    def is_capturing(self, mac):
        """Check if capture is active for a device"""
        return mac in self.active_captures

    def stop_capture(self, mac):
        """Stop an active capture"""
        if mac in self.active_captures:
            self.active_captures[mac]['stop_event'].set()
            self.active_captures[mac]['thread'].join(timeout=2)
            info = self.active_captures.pop(mac)
            return {
                'success': True,
                'filepath': info['filepath'],
                'packet_count': len(info['packets']),
                'message': f"Stopped capture for {info['device']['name']}"
            }
        return {'success': False, 'error': 'No active capture for this device'}

    def get_capture_status(self, mac):
        """Get capture status"""
        if mac in self.active_captures:
            elapsed = time.time() - self.active_captures[mac]['start_time']
            return {
                'device': self.active_captures[mac]['device']['name'],
                'ip': self.active_captures[mac]['device']['ipv4'],
                'packet_count': len(self.active_captures[mac]['packets']),
                'elapsed_time': elapsed,
                'is_active': True
            }
        return None