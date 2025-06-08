import time
import json
import os
from scapy.all import sniff, IP, TCP, Raw
from scapy.layers.tls.all import TLS, TLSClientHello
from utils.firewall import close_port, ban_ip
from datetime import datetime
from utils.logger import log_ban, log_access

WHITELIST_PATH = "tls_whitelist.json"
MONITOR_DURATION = 60  # seconds after granting access
TLS_PORT = 443

# Load whitelist
def load_whitelist():
    try:
        with open(WHITELIST_PATH) as f:
            return set(json.load(f)["trusted_fingerprints"])
    except:
        return set()

# Extract JA3-style fingerprint
def extract_ja3(packet):
    try:
        if not packet.haslayer(TLSClientHello):
            return None
        client_hello = packet[TLSClientHello]
        version = client_hello.version
        ciphers = "-".join(str(c) for c in client_hello.ciphers)
        exts = "-".join(str(e.ext_type) for e in client_hello.ext)
        ja3 = f"{version},{ciphers},{exts}"
        return ja3
    except Exception:
        return None

# TLS monitor function
def monitor_tls(ip, port=TLS_PORT):
    whitelist = load_whitelist()
    print(f"[TLS MONITOR] Monitoring {ip} for {MONITOR_DURATION}s...")

    captured_fingerprint = None

    def filter_tls(pkt):
        return (
            pkt.haslayer(IP)
            and pkt.haslayer(TCP)
            and pkt[IP].src == ip
            and pkt[TCP].dport == port
        )

    def check_packet(pkt):
        nonlocal captured_fingerprint
        if pkt.haslayer(TLSClientHello):
            ja3 = extract_ja3(pkt)
            print(f"[TLS] JA3 from {ip}: {ja3}")
            captured_fingerprint = ja3

    sniff(
        filter=f"tcp port {port}",
        prn=check_packet,
        timeout=MONITOR_DURATION,
        lfilter=filter_tls,
        store=False,
    )

    if not captured_fingerprint:
        print(f"[TLS] No fingerprint seen from {ip}. Closing access.")
        log_access(ip, "TLS FAILED - No ClientHello fingerprint observed")
        close_port(ip, port)
        return False

    if captured_fingerprint not in whitelist:
        print(f"[TLS] Fingerprint mismatch! Blocking {ip}")
        log_access(ip, f"TLS FAILED - JA3 mismatch | JA3: {captured_fingerprint}")
        log_ban(ip, "BANNED - TLS fingerprint mismatch")
        close_port(ip, port)
        ban_ip(ip)
        return False
    else:
        print(f"[TLS] Fingerprint matched for {ip}. Access allowed.")
        log_access(ip, f"TLS SUCCESS - JA3 matched | JA3: {captured_fingerprint}")
        close_port(ip, port)
        return True

