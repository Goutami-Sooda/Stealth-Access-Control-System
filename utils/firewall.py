import subprocess
import atexit
import signal
import sys

RESTRICTED_PORTS = [22, 443]

def open_port(ip, port):
    subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {port} -s {ip} -j ACCEPT", shell=True)

def close_port(ip, port):
    subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {port} -s {ip} -j ACCEPT", shell=True)

def ban_ip(ip):
    subprocess.call(f"sudo iptables -I INPUT -s {ip} -j DROP", shell=True)

def unban_ip(ip):
    subprocess.call(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True)
    

def block_ports_globally():
    for port in RESTRICTED_PORTS:
        print(f"[!] Blocking port {port} for all IPs...")
        subprocess.call(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP", shell=True)

def unblock_ports_globally():
    for port in RESTRICTED_PORTS:
        print(f"[+] Unblocking port {port} for all IPs...")
        subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {port} -j DROP", shell=True)

# Register cleanup to run when script exits (Ctrl+C, normal stop, etc.)
def register_cleanup():
    def cleanup_handler(*args):
        print("\n[*] Cleaning up firewall rules for 22 and 443...")
        unblock_ports_globally()
        sys.exit(0)

    atexit.register(unblock_ports_globally)         # Normal exit
    signal.signal(signal.SIGINT, cleanup_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, cleanup_handler)  # kill/terminate

# Only run these when imported by knock_listener
if __name__ == "__main__":
    block_ports_globally()
    register_cleanup()

