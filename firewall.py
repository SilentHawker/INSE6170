import os
import platform

def block_ip(ip):
    system = platform.system()
    if system == "Windows":
        rule_name = f"Block_IP_{ip}"
        cmd = (f'netsh advfirewall firewall add rule name="{rule_name}" '
               f'dir=in action=block remoteip={ip} protocol=any')
        result = os.system(cmd)
        if result == 0:
            print(f"[Firewall] Successfully blocked IP {ip}")
            return True
        else:
            print(f"[Firewall] Failed to block IP {ip}")
            return False
    else:  # Linux
        cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
        result = os.system(cmd)
        return result == 0

def unblock_ip(ip):
    """Unblock a specific IP address"""
    system = platform.system()
    if system == "Windows":
        rule_name = f"Block_IP_{ip}"
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    else:  # Linux
        cmd = f'sudo iptables -D INPUT -s {ip} -j DROP'
    
    result = os.system(cmd)
    if result == 0:
        print(f"[Firewall] Unblocked IP {ip}")
        return True
    else:
        print(f"[Firewall] No rule found for IP {ip}")
        return False

def block_port(port, protocol="BOTH"):  # Changed default to "BOTH"
    system = platform.system()
    if system == "Windows":
        # Block TCP
        if protocol in ("TCP", "BOTH"):
            tcp_rule = f'Block_TCP_{port}'
            os.system(f'netsh advfirewall firewall delete rule name="{tcp_rule}"')
            os.system(f'netsh advfirewall firewall add rule name="{tcp_rule}" dir=in action=block protocol=TCP localport={port} remoteip=any')
        
        # Block UDP (for QUIC/HTTP3)
        if protocol in ("UDP", "BOTH"):
            udp_rule = f'Block_UDP_{port}'
            os.system(f'netsh advfirewall firewall delete rule name="{udp_rule}"')
            os.system(f'netsh advfirewall firewall add rule name="{udp_rule}" dir=in action=block protocol=UDP localport={port} remoteip=any')
        
        print(f"[Firewall] Blocked {protocol} port {port}")
        return True
    else:  # Linux
        if protocol in ("TCP", "BOTH"):
            os.system(f'sudo iptables -A INPUT -p tcp --dport {port} -j DROP')
        if protocol in ("UDP", "BOTH"):
            os.system(f'sudo iptables -A INPUT -p udp --dport {port} -j DROP')
        return True

def unblock_port(port, protocol="TCP"):
    system = platform.system()
    if system == "Windows":
        rule_name = f"Block_Port_{protocol}_{port}"
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        result = os.system(cmd)
        if result == 0:
            print(f"[Firewall] Removed block on {protocol} port {port}")
            return True
        else:
            print(f"[Firewall] No existing block found for {protocol} port {port}")
            return False
    else:  # Linux version
        cmd = f'sudo iptables -D INPUT -p {protocol.lower()} --dport {port} -j DROP'
        return os.system(cmd) == 0
def block_ip_range(ip_range):
    """Block a range of IP addresses (e.g., 192.168.1.0/24)"""
    system = platform.system()
    if system == "Windows":
        rule_name = f"Block_IP_Range_{ip_range.replace('/', '_')}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_range}'
    else:  # Linux
        cmd = f'sudo iptables -A INPUT -s {ip_range} -j DROP'
    
    result = os.system(cmd)
    if result == 0:
        print(f"[Firewall] Blocked IP range {ip_range}")
        return True
    else:
        print(f"[Firewall] Failed to block IP range {ip_range}")
        return False

def block_protocol(protocol):
    """Block a specific protocol (e.g., ICMP)"""
    system = platform.system()
    if system == "Windows":
        rule_name = f"Block_Protocol_{protocol}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block protocol={protocol}'
    else:  # Linux
        cmd = f'sudo iptables -A INPUT -p {protocol.lower()} -j DROP'
    
    result = os.system(cmd)
    if result == 0:
        print(f"[Firewall] Blocked protocol {protocol}")
        return True
    else:
        print(f"[Firewall] Failed to block protocol {protocol}")
        return False

def save_firewall_rules():
    """Save firewall rules permanently (Linux only)"""
    if platform.system() != "Linux":
        print("[Firewall] Rule saving only available on Linux")
        return False
    
    result = os.system('sudo iptables-save > /etc/iptables/rules.v4')
    if result == 0:
        print("[Firewall] Rules saved permanently")
        return True
    else:
        print("[Firewall] Failed to save rules")
        return False

def list_firewall_rules():
    """List all firewall rules"""
    system = platform.system()
    print("[Firewall] Current rules:")
    if system == "Windows":
        os.system('netsh advfirewall firewall show rule name=all')
    else:  # Linux
        os.system('sudo iptables -L -n -v')