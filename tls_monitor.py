import time
import ssl
import socket
import hashlib
from utils.firewall import close_port, ban_ip
from utils.logger import log_access, log_ban
import json

MONITOR_DURATION = 60
WHITELIST_PATH = "tls_whitelist.json"

def load_whitelist():
    try:
        with open(WHITELIST_PATH) as f:
            return set(json.load(f)["trusted_fingerprints"])
    except:
        return set()

def get_client_cert_fingerprint(ip, port=443):
    context = ssl.create_default_context()
    context.load_verify_locations(cafile="certs/ca_cert.pem")
    context.check_hostname = False

    try:
        with socket.create_connection((ip, port), timeout=MONITOR_DURATION) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                fingerprint = hashlib.sha256(cert_bin).hexdigest()
                print(f"[TLS MONITOR] Client cert fingerprint: {fingerprint}")
                return fingerprint
    except Exception as e:
        print(f"[TLS MONITOR] TLS error: {e}")
        return None

def monitor_tls(ip, port=443):
    print(f"[TLS MONITOR] Monitoring {ip} for client cert for {MONITOR_DURATION}s...")
    whitelist = load_whitelist()

    fingerprint = get_client_cert_fingerprint(ip, port)

    if not fingerprint:
        print(f"[TLS] No client certificate seen from {ip}. Closing access.")
        log_access(ip, "TLS FAILED - No client certificate")
        close_port(ip, port)
        return False

    if fingerprint not in whitelist:
        print(f"[TLS] Client fingerprint mismatch! Blocking {ip}")
        log_access(ip, f"TLS FAILED - Fingerprint mismatch | SHA256: {fingerprint}")
        log_ban(ip, "BANNED - TLS fingerprint mismatch")
        close_port(ip, port)
        ban_ip(ip)
        return False
    else:
        print(f"[TLS] Fingerprint matched for {ip}. Access allowed.")
        log_access(ip, f"TLS SUCCESS - Client cert matched | SHA256: {fingerprint}")
        close_port(ip, port)
        return True

