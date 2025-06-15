import subprocess
import time
import threading
import json
from tls_monitor import monitor_tls
from utils.logger import log_access
from utils.console_logger import get_logger

logger = get_logger()

with open("config.json") as f:
    config = json.load(f)

OPEN_PORT = config["open_port"]
ACCESS_DURATION = config["access_duration"]
TLS_ACCESS_DURATION = 90
TLS_PORT = 443

def rule_exists(rule):
    result = subprocess.run(["sudo", "iptables", "-C"] + rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0

def allow_access(ip):
    logger.info(f"[+] Allowing access to {ip} for {ACCESS_DURATION} seconds")
    rule = ["INPUT", "-p", "tcp", "--dport", str(OPEN_PORT), "-s", str(ip), "-j", "ACCEPT"]
    if not rule_exists(rule):
        subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {OPEN_PORT} -s {ip} -j ACCEPT", shell=True)

    threading.Thread(target=remove_access_after_timeout, args=(ip,), daemon=True).start()

def verify_tls_fingerprint(ip):
    logger.info(f"[+] Allowing TLS port 443 access to {ip} for {TLS_ACCESS_DURATION} seconds")
    subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {TLS_PORT} -s {ip} -j ACCEPT", shell=True)

    logger.info("[*] Starting TLS server...")
    subprocess.Popen(["sudo", "python3", "-u", "tls_utils/tls_server.py"])

    time.sleep(3)  # Give the server time to bind to port 443

    result = monitor_tls(ip)

    #subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {TLS_PORT} -s {ip} -j ACCEPT", shell=True)
    return result

def remove_access_after_timeout(ip):
    time.sleep(ACCESS_DURATION)
    rule = ["INPUT", "-p", "tcp", "--dport", str(OPEN_PORT), "-s", str(ip), "-j", "ACCEPT"]
    if rule_exists(rule):
        subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {OPEN_PORT} -s {ip} -j ACCEPT", shell=True)
        log_access(ip, f"Access revoked for {ip} after {ACCESS_DURATION}s")
        #logger.info(f"[-] Removed port {OPEN_PORT} access for {ip}")

