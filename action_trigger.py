import subprocess
import time
import threading
import json
from tls_monitor import monitor_tls


with open("config.json") as f:
    config = json.load(f)

OPEN_PORT = config["open_port"]
ACCESS_DURATION = config["access_duration"]

'''
def allow_access(ip):
    print(f"[+] Allowing access to {ip} for {ACCESS_DURATION} seconds")
    subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {OPEN_PORT} -s {ip} -j ACCEPT", shell=True)

    # Start timeout thread
    threading.Thread(target=remove_access_after_timeout, args=(ip,), daemon=True).start()
'''

def allow_access(ip):
    print(f"[+] Allowing access to {ip} for {ACCESS_DURATION} seconds")
    subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {OPEN_PORT} -s {ip} -j ACCEPT", shell=True)

    # Start TLS fingerprint monitor
    threading.Thread(target=monitor_tls, args=(ip, OPEN_PORT), daemon=True).start()

    # Start timeout removal thread
    threading.Thread(target=remove_access_after_timeout, args=(ip,), daemon=True).start()


def remove_access_after_timeout(ip):
    time.sleep(ACCESS_DURATION)
    subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {OPEN_PORT} -s {ip} -j ACCEPT", shell=True)
    print(f"[-] Removed access for {ip}")

