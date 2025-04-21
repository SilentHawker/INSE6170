import tkinter as tk
from tkinter import ttk, messagebox
from capture import PacketCaptureManager
from network_scanner import get_connected_devices
from firewall import block_ip, unblock_ip
import threading
import sys
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
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Sentinel")
        self.root.geometry("1000x800")
        
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
            ("History", self.show_history)
        ]
        
        for text, command in buttons:
            ttk.Button(button_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)

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
        
        # Placeholder visualization
        fig = plt.figure(figsize=(8, 4))
        ax = fig.add_subplot(111)
        
        # Sample data
        days = list(range(1, 8))
        traffic = [100, 150, 200, 180, 250, 300, 220]
        
        ax.plot(days, traffic, marker='o')
        ax.set_title(f'Traffic History for {device_ip}')
        ax.set_xlabel('Day')
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

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = IoTRouterApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        if 'root' in locals():
            root.destroy() 