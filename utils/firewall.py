import subprocess
import atexit
import signal
import sys


def rule_exists(rule):
    result = subprocess.run(["sudo", "iptables", "-C"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

RESTRICTED_PORTS = [22, 443]

def open_port(ip, port):
    rule = ["INPUT", "-p", "tcp", "--dport", str(port), "-s", str(ip), "-j", "ACCEPT"]
    if not rule_exists(rule):
        subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {port} -s {ip} -j ACCEPT", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def close_port(ip, port):
    rule = ["INPUT", "-p", "tcp", "--dport", str(port), "-s", str(ip), "-j", "ACCEPT"]
    if rule_exists(rule):
        subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {port} -s {ip} -j ACCEPT", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def ban_ip(ip):
    rule = ["INPUT", "-s", str(ip), "-j", "DROP"]
    if not rule_exists(rule):
        subprocess.call(f"sudo iptables -I INPUT -s {ip} -j DROP", shell=True)

def unban_ip(ip):
    rule = ["INPUT", "-s", str(ip), "-j", "DROP"]
    if rule_exists(rule):
        subprocess.call(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True)

def ban_port(ip, port):
    rule = ["INPUT", "-p", "tcp", "--dport", str(port), "-s", str(ip), "-j", "DROP"]
    if not rule_exists(rule):
        subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {port} -s {ip} -j DROP", shell=True)

def unban_port(ip, port):
    rule = ["INPUT", "-p", "tcp", "--dport", str(port), "-s", str(ip), "-j", "DROP"]
    if rule_exists(rule):
        subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {port} -s {ip} -j DROP", shell=True)


def block_ports_globally():
    for port in RESTRICTED_PORTS:
        rule = ["INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"]
        if not rule_exists(rule):
            print(f"[!] Blocking port {port} for all IPs...")
            subprocess.call(f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP", shell=True)

def unblock_ports_globally():
    for port in RESTRICTED_PORTS:
        rule = ["INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"]
        if rule_exists(rule):
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

