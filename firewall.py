import os

def block_ip(ip):
    rule_name = f"Block_IP_{ip}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    os.system(cmd)
    print(f"Blocked IP {ip}")

def unblock_ip(ip):
    rule_name = f"Block_IP_{ip}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    os.system(cmd)
    print(f"Removed firewall rule blocking IP {ip}")

def block_port(port):
    rule_name = f"Block_Port_{port}"
    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block protocol=TCP localport={port}'
    os.system(cmd)
    print(f"Blocked port {port}")

def unblock_port(port):
    rule_name = f"Block_Port_{port}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    os.system(cmd)
    print(f"Removed block from port {port}")
