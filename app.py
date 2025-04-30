import tkinter as tk
from tkinter import ttk, messagebox
from capture import PacketCaptureManager
from network_scanner import get_connected_devices
from logger import load_logs, cleanup_logs, delete_logs
import threading
import sys
from firewall import block_ip, unblock_ip, block_port, unblock_port, block_ip_range, block_protocol, save_firewall_rules
import platform
import time
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from meta import get_device_metadata, set_device_metadata
from ips import monitor_device

class RedirectOutput:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        if message.strip():  # Avoid writing empty lines
            self.text_widget.insert(tk.END, message + "\n")
            self.text_widget.see(tk.END)  # Auto-scroll to the bottom

    def flush(self):
        pass

class IoTRouterApp:
    def block_port_from_ui(self):
        port = self.port_entry.get()
        protocol = self.protocol_var.get()
        if port.isdigit():
            block_port(port, protocol)
            print(f"Blocked {protocol} port {port}")
        else:
            print("Invalid port number")

    def unblock_port_from_ui(self):
        port = self.port_entry.get()
        protocol = self.protocol_var.get()
        if port.isdigit():
            unblock_port(port, protocol)
            print(f"Unblocked {protocol} port {port}")
        else:
            print("Invalid port number")

    def block_ip_range_from_ui(self):
        ip_range = self.ip_range_entry.get()
        if ip_range:
            if block_ip_range(ip_range):
                print(f"Successfully blocked IP range {ip_range}")
            else:
                print(f"Failed to block IP range {ip_range}")

    def block_protocol_from_ui(self):
        protocol = self.protocol_entry.get().upper()
        if protocol:
            if block_protocol(protocol):
                print(f"Successfully blocked protocol {protocol}")
            else:
                print(f"Failed to block protocol {protocol}")

    def save_firewall_rules_from_ui(self):
        if save_firewall_rules():
            print("Firewall rules saved permanently")
        else:
            print("Failed to save firewall rules")

    def __init__(self, root):
        self.root = root
        self.root.title("IoT Sentinel")
        self.root.geometry("1000x800")

        # Initialize IPS threads dictionary
        self.ips_threads = {}

        # Cleanup outdated logs (e.g., older than 30 days)
        cleanup_logs(days=30)

        # Initialize managers
        self.capture_manager = PacketCaptureManager()
        # Setup UI
        self.setup_ui()

        # Initial device refresh
        self.refresh_devices()

        # Start periodic refresh
        self.auto_refresh()

        # Cleanup on exit
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Device list section
        device_frame = ttk.LabelFrame(main_frame, text="Connected IoT Devices", padding="10")
        device_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Treeview for devices
        self.device_tree = ttk.Treeview(device_frame, columns=('IP', 'MAC', 'Vendor', 'Name'), show='headings')
        self.device_tree.heading('IP', text='IP Address')
        self.device_tree.heading('MAC', text='MAC Address')
        self.device_tree.heading('Vendor', text='Vendor')
        self.device_tree.heading('Name', text='Device Name')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(device_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Button panel
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        # Action buttons
        buttons = [
            ("Refresh", self.refresh_devices),
            ("Capture", self.capture_selected),
            ("Stop Capture", self.stop_capture),
            ("Block", self.block_selected_ip),
            ("Unblock", self.unblock_selected_ip),
            ("Edit Metadata", self.edit_selected_metadata),
            ("Start IPS", self.start_ips),
            ("Stop IPS", self.stop_ips),
        ]

        for text, command in buttons:
            ttk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)


# --- Firewall Port Controls ---
        port_frame = ttk.LabelFrame(main_frame, text="Firewall Port Control", padding="10")
        port_frame.pack(fill=tk.X, pady=5)

        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        self.port_entry = ttk.Entry(port_frame, width=10)
        self.port_entry.pack(side=tk.LEFT)

        ttk.Label(port_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_var = tk.StringVar(value="BOTH")  # Default to block both
        protocol_menu = ttk.OptionMenu(port_frame, self.protocol_var, "BOTH", "TCP", "UDP", "BOTH")
        protocol_menu.pack(side=tk.LEFT)

        ttk.Button(port_frame, text="Block Port", command=self.block_port_from_ui).pack(side=tk.LEFT, padx=5)
        ttk.Button(port_frame, text="Unblock Port", command=self.unblock_port_from_ui).pack(side=tk.LEFT, padx=5)

        # --- Advanced Firewall Controls ---
        advanced_frame = ttk.LabelFrame(main_frame, text="Advanced Firewall", padding="10")
        advanced_frame.pack(fill=tk.X, pady=5)

        # IP Range blocking
        ttk.Label(advanced_frame, text="IP Range:").pack(side=tk.LEFT, padx=5)
        self.ip_range_entry = ttk.Entry(advanced_frame, width=20)
        self.ip_range_entry.pack(side=tk.LEFT)
        ttk.Button(advanced_frame, text="Block Range", 
                  command=self.block_ip_range_from_ui).pack(side=tk.LEFT, padx=5)

        # Protocol blocking
        ttk.Label(advanced_frame, text="Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_entry = ttk.Entry(advanced_frame, width=10)
        self.protocol_entry.pack(side=tk.LEFT)
        ttk.Button(advanced_frame, text="Block Protocol", 
                  command=self.block_protocol_from_ui).pack(side=tk.LEFT, padx=5)

        # Save rules button (Linux only)
        if platform.system() == "Linux":
            ttk.Button(advanced_frame, text="Save Rules", 
                      command=self.save_firewall_rules_from_ui).pack(side=tk.LEFT, padx=5)

        # Console output
        console_frame = ttk.LabelFrame(main_frame, text="System Console", padding="10")
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.console = tk.Text(console_frame, height=10, wrap=tk.WORD, bg='black', fg='white')
        scrollbar = ttk.Scrollbar(console_frame, command=self.console.yview)
        self.console.configure(yscrollcommand=scrollbar.set)
        self.console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Redirect stdout and stderr to the console widget
        sys.stdout = RedirectOutput(self.console)
        sys.stderr = RedirectOutput(self.console)

        # Add buttons for log management
        log_frame = ttk.LabelFrame(main_frame, text="Log Management", padding="10")
        log_frame.pack(fill=tk.X, pady=5)

        ttk.Button(log_frame, text="Delete Selected Device Logs", command=self.delete_selected_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_frame, text="Delete All Logs", command=self.delete_all_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_frame, text="Show History", command=self.show_history).pack(side=tk.LEFT, padx=5)  # Added Show History button

        # Add input field for number of days
        ttk.Label(log_frame, text="Days:").pack(side=tk.LEFT, padx=5)
        self.days_entry = ttk.Entry(log_frame, width=5)
        self.days_entry.insert(0, "30")  # Default to 30 days
        self.days_entry.pack(side=tk.LEFT, padx=5)

        # Add input field for IPS duration
        ttk.Label(button_frame, text="IPS Duration (s):").pack(side=tk.LEFT, padx=5)
        self.ips_duration_entry = ttk.Entry(button_frame, width=5)
        self.ips_duration_entry.insert(0, "10")  # Default to 10 seconds
        self.ips_duration_entry.pack(side=tk.LEFT, padx=5)
    
    def refresh_devices(self):
        """Refresh the list of connected devices"""
        self.device_tree.delete(*self.device_tree.get_children())
        devices = get_connected_devices()
        
        for device in devices:
            # Retrieve metadata for the device
            metadata = get_device_metadata(device['MAC'])
            custom_name = metadata.get('name', f"Device-{device['MAC'][-6:]}")
            
            # Insert device into the treeview
            self.device_tree.insert('', tk.END, values=(
                device['IPv4'],
                device['MAC'],
                device['Vendor'],
                custom_name
            ))
        
        print(f"Device list refreshed - {len(devices)} devices found")
    
    def capture_selected(self):
        """Start packet capture for selected device"""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return
        
        item = self.device_tree.item(selection[0])
        values = item['values']
        
        device = {
            'ipv4': values[0],
            'mac': values[1],
            'name': values[3],
            'vendor': values[2]
        }
        
        result = self.capture_manager.start_capture(
            device,
            packet_count=50,
            duration=10
        )
        
        if result['success']:
            print(result['message'])
            threading.Thread(
                target=self.monitor_capture,
                args=(device['mac'],),
                daemon=True
            ).start()
        else:
            print(f"Error: {result['error']}")

    def monitor_capture(self, mac):
        """Monitor and display capture progress"""
        try:
            while self.capture_manager.is_capturing(mac):
                status = self.capture_manager.get_capture_status(mac)
                if status:
                    target = status.get('target_count', "∞")
                    msg = (f"Capturing {status['device']} - "
                          f"{status['packet_count']}/{target} packets | "
                          f"Elapsed: {status['elapsed_time']:.1f}s")
                    print(msg)
                time.sleep(1)
            
            print("Capture completed")
        except Exception as e:
            print(f"Monitoring error: {str(e)}")
    
    def stop_capture(self):
        """Stop active capture"""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return
        
        item = self.device_tree.item(selection[0])
        mac = item['values'][1]
        
        result = self.capture_manager.stop_capture(mac)
        if result['success']:
            print(f"{result['message']} - Saved {result['packet_count']} packets")
        else:
            print(result['error'])
    
    def block_selected_ip(self):
        """Block selected device's IP"""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return
        
        item = self.device_tree.item(selection[0])
        device_ip = item['values'][0]
        block_ip(device_ip)
        print(f"Blocked IP {device_ip}")
    
    def unblock_selected_ip(self):
        """Unblock selected device's IP"""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return
        
        item = self.device_tree.item(selection[0])
        device_ip = item['values'][0]
        unblock_ip(device_ip)
        print(f"Unblocked IP {device_ip}")
    
    def show_history(self):
        """Show traffic history for selected device"""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return
        
        item = self.device_tree.item(selection[0])
        device_ip = item['values'][0]

        # Get the number of days from the input field
        try:
            days = int(self.days_entry.get())
        except ValueError:
            print("Invalid number of days. Please enter a valid integer.")
            return

        # Load historical logs for the selected device
        records = load_logs(device_ip, days=days)
        if not records:
            print(f"No historical data available for this device in the last {days} days.")
            return

        # Extract packet counts from the records
        packet_counts = [record['packet_count'] for record in records]

        # Plot the data rate history
        fig = plt.figure(figsize=(8, 4))
        ax = fig.add_subplot(111)
        ax.plot(packet_counts, marker='o')
        ax.set_title(f'Traffic History for {device_ip} (Last {days} Days)')
        ax.set_xlabel('Measurement #')
        ax.set_ylabel('Packet Count')
        ax.grid(True)

        # Display in Tkinter window
        history_win = tk.Toplevel(self.root)
        history_win.title(f"Traffic History - {device_ip}")
        canvas = FigureCanvasTkAgg(fig, master=history_win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def auto_refresh(self):
        """Auto-refresh devices periodically"""
        self.refresh_devices()
        self.root.after(30000, self.auto_refresh)
    
    def on_closing(self):
        """Handle application shutdown"""
        print("Stopping all active captures...")
        
        # Access the active_captures attribute directly
        active_captures = self.capture_manager.active_captures
        
        for mac in active_captures:
            result = self.capture_manager.stop_capture(mac)
            if result['success']:
                print(f"Saved {result['packet_count']} packets for {mac}")
            else:
                print(f"Error stopping capture for {mac}: {result.get('error', 'Unknown error')}")
        
        print("All captures stopped. Closing application.")
        self.root.destroy()

    def delete_selected_logs(self):
        """Delete logs for the selected device."""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return

        item = self.device_tree.item(selection[0])
        device_ip = item['values'][0]
        delete_logs(device_ip)

    def delete_all_logs(self):
        """Delete all logs."""
        delete_logs()

    def edit_selected_metadata(self):
        """Edit metadata for the selected device."""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return

        item = self.device_tree.item(selection[0])
        mac = item['values'][1]  # MAC address

        # Load existing metadata
        existing = get_device_metadata(mac)
        popup = tk.Toplevel(self.root)
        popup.title(f"Edit Metadata for {mac}")

        fields = ['name', 'vendor', 'model', 'version', 'description']
        entries = {}

        for i, field in enumerate(fields):
            ttk.Label(popup, text=field.capitalize() + ":").grid(row=i, column=0, sticky='w', padx=10, pady=5)
            entry = ttk.Entry(popup, width=40)
            entry.grid(row=i, column=1, padx=10)
            entry.insert(0, existing.get(field, ''))
            entries[field] = entry

        def save():
            metadata = {field: entry.get() for field, entry in entries.items()}
            set_device_metadata(mac, metadata)
            print(f"Metadata saved for {mac}")
            popup.destroy()

        ttk.Button(popup, text="Save", command=save).grid(row=len(fields), column=0, columnspan=2, pady=10)

    def stop_ips(self):
        """Stop IPS monitoring for the selected device."""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return

        item = self.device_tree.item(selection[0])
        device_ip = item['values'][0]

        if device_ip in self.ips_threads:
            stop_event = self.ips_threads[device_ip]
            stop_event.set()  # Signal the thread to stop
            del self.ips_threads[device_ip]
            print(f"Stopped IPS monitoring for {device_ip}")
        else:
            print(f"No active IPS monitoring for {device_ip}")

    def start_ips(self):
        """Start monitoring the selected device for abnormal traffic."""
        selection = self.device_tree.selection()
        if not selection:
            print("Please select a device first!")
            return

        item = self.device_tree.item(selection[0])
        device_ip = item['values'][0]
        if not device_ip:
            print("Selected device does not have an IP address!")
            return

        # Get the IPS duration from the input field
        try:
            duration = int(self.ips_duration_entry.get())
        except ValueError:
            print("Invalid IPS duration. Please enter a valid integer.")
            return

        # Check if IPS is already running for this device
        if device_ip in self.ips_threads:
            print(f"IPS is already running for {device_ip}")
            return

        # Create a stop event for the thread
        stop_event = threading.Event()
        self.ips_threads[device_ip] = stop_event

        # Start monitoring in a separate thread
        def monitor_with_stop():
            try:
                monitor_device(device_ip, 100, duration, self.handle_alert, stop_event)
            except Exception as e:
                print(f"Error during IPS monitoring for {device_ip}: {str(e)}")
            finally:
                # Remove the device from active threads when monitoring stops
                if device_ip in self.ips_threads:
                    del self.ips_threads[device_ip]

        threading.Thread(target=monitor_with_stop, daemon=True).start()
        print(f"Started IPS monitoring for {device_ip} with duration {duration} seconds")

    def handle_alert(self, alert_message):
        """Handle alerts generated by the IPS."""
        print(alert_message)
        messagebox.showwarning("Intrusion Alert", alert_message)

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = IoTRouterApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        if 'root' in locals():
            root.destroy()