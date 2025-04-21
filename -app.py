import tkinter as tk
from monitor import get_connected_devices
from capture import capture_packets
from firewall import block_ip, unblock_ip
from ips import monitor_device
from logger import load_logs
import matplotlib.pyplot as plt
import threading
import sys

# Redirect print statements to GUI
class RedirectOutput:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)

    def flush(self):
        pass

def refresh_devices():
    devices_list.delete(0, tk.END)
    devices = get_connected_devices()
    for device in devices:
        devices_list.insert(tk.END, f"{device['IPv4']} | {device['MAC']} | {device['Vendor']}")

def capture_selected():
    selection = devices_list.curselection()
    if not selection:
        print("Please select a device first!")
        return
    device_info = devices_list.get(selection[0])
    device_ip = device_info.split("|")[0].strip()
    filename = f"capture_{device_ip.replace('.', '_')}.pcap"

    threading.Thread(target=lambda: capture_packets(device_ip, filename, 50, 10), daemon=True).start()

def block_selected_ip():
    selection = devices_list.curselection()
    if not selection:
        print("Please select a device first!")
        return
    device_info = devices_list.get(selection[0])
    device_ip = device_info.split("|")[0].strip()
    block_ip(device_ip)

def unblock_selected_ip():
    selection = devices_list.curselection()
    if not selection:
        print("Please select a device first!")
        return
    device_info = devices_list.get(selection[0])
    device_ip = device_info.split("|")[0].strip()
    unblock_ip(device_ip)

def ips_monitor_selected():
    selection = devices_list.curselection()
    if not selection:
        print("Select a device first!")
        return
    device_info = devices_list.get(selection[0])
    device_ip = device_info.split("|")[0].strip()

    threading.Thread(target=lambda: monitor_device(device_ip, threshold=50, duration=10, alert_callback=gui_alert), daemon=True).start()

def gui_alert(message):
    output_console.insert(tk.END, message + "\n")

def show_history():
    selection = devices_list.curselection()
    if not selection:
        print("Please select a device first!\n")
        return
    device_info = devices_list.get(selection[0])
    device_ip = device_info.split("|")[0].strip()

    records = load_logs(device_ip)
    if not records:
        print("No historical data available for this device.\n")
        return

    packet_counts = [record['packet_count'] for record in records]

    plt.figure(figsize=(8,4))
    plt.plot(packet_counts, marker='o')
    plt.title(f'Data Rate History for {device_ip}')
    plt.xlabel('Measurement #')
    plt.ylabel('Packet Count')
    plt.grid(True)
    plt.show()

    
window = tk.Tk()
window.title("IoT Router Manager")

devices_list = tk.Listbox(window, width=80, height=12)
devices_list.pack(padx=10, pady=5)

# Buttons frame
buttons_frame = tk.Frame(window)
buttons_frame.pack(pady=5)

refresh_button = tk.Button(buttons_frame, text="Refresh Devices", command=refresh_devices)
refresh_button.pack(side=tk.LEFT, padx=5)

capture_button = tk.Button(buttons_frame, text="Capture Packets", command=capture_selected)
capture_button.pack(side=tk.LEFT, padx=5)

block_ip_button = tk.Button(buttons_frame, text="Block Selected IP", command=block_selected_ip)
block_button = tk.Button(buttons_frame, text="Block Selected IP", command=block_selected_ip)
capture_button.pack(side=tk.LEFT, padx=5)
block_button = tk.Button(buttons_frame, text="Block Selected IP", command=block_selected_ip)
block_button.pack(side=tk.LEFT, padx=5)

unblock_button = tk.Button(buttons_frame, text="Unblock Selected IP", command=unblock_selected_ip)
unblock_button.pack(side=tk.LEFT, padx=5)

ips_button = tk.Button(buttons_frame, text="IPS Monitor Device", command=ips_monitor_selected)
ips_button.pack(side=tk.LEFT, padx=5)

history_button = tk.Button(buttons_frame, text="Show Traffic History", command=show_history)
history_button.pack(side=tk.LEFT, padx=5)


# Output console
output_console = tk.Text(window, height=10, width=80, bg='black', fg='white')
output_console.pack(padx=10, pady=5)
sys.stdout = RedirectOutput(output_console)

refresh_devices()  # initial load
window.mainloop()


