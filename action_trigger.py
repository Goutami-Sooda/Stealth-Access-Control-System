import subprocess
import time
import threading
import json
from tls_monitor import monitor_tls
from utils.logger import log_access


with open("config.json") as f:
    config = json.load(f)

OPEN_PORT = config["open_port"]
ACCESS_DURATION = config["access_duration"]
TLS_ACCESS_DURATION = 90
TLS_PORT = 443

def allow_access(ip):
    print(f"[+] Allowing access to {ip} for {ACCESS_DURATION} seconds")
    subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {OPEN_PORT} -s {ip} -j ACCEPT", shell=True)

    # Start timeout thread
    threading.Thread(target=remove_access_after_timeout, args=(ip, OPEN_PORT), daemon=True).start()


def verify_tls_fingerprint(ip):
    print(f"[+] Allowing TLS port 443 access to {ip} for {TLS_ACCESS_DURATION} seconds")
    subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {TLS_PORT} -s {ip} -j ACCEPT", shell=True)

    result = monitor_tls(ip)

    subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {TLS_PORT} -s {ip} -j ACCEPT", shell=True)
    return result


def remove_access_after_timeout(ip):
        time.sleep(ACCESS_DURATION)
        subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {OPEN_PORT} -s {ip} -j ACCEPT", shell=True)
        log_access(ip, f"Access revoked for {ip} after {ACCESS_DURATION}s")
        print(f"[-] Removed port {OPEN_PORT} access for {ip}")

