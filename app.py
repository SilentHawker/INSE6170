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

class RedirectOutput:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)

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
        
        # Redirect stdout to console
        sys.stdout = RedirectOutput(self.console)
        sys.stderr = RedirectOutput(self.console)

        # Add buttons for log management
        log_frame = ttk.LabelFrame(main_frame, text="Log Management", padding="10")
        log_frame.pack(fill=tk.X, pady=5)

        ttk.Button(log_frame, text="Delete Selected Device Logs", command=self.delete_selected_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_frame, text="Delete All Logs", command=self.delete_all_logs).pack(side=tk.LEFT, padx=5)

        # Add input field for number of days
        ttk.Label(log_frame, text="Days:").pack(side=tk.LEFT, padx=5)
        self.days_entry = ttk.Entry(log_frame, width=5)
        self.days_entry.insert(0, "30")  # Default to 30 days
        self.days_entry.pack(side=tk.LEFT, padx=5)

        # Add History button next to Days selector
        ttk.Button(log_frame, text="History", command=self.show_history).pack(side=tk.LEFT, padx=5)
    
    def refresh_devices(self):
        """Refresh the list of connected devices"""
        self.device_tree.delete(*self.device_tree.get_children())
        devices = get_connected_devices()
        
        for device in devices:
            self.device_tree.insert('', tk.END, values=(
                device['IPv4'],
                device['MAC'],
                device['Vendor'],
                f"Device-{device['MAC'][-6:]}"
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

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = IoTRouterApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        if 'root' in locals():
            root.destroy()