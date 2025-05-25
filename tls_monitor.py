import time
import json
from scapy.all import sniff, IP, TCP, Raw
from scapy.layers.tls.all import TLS, TLSClientHello
from utils.firewall import close_port, ban_ip
from datetime import datetime

WHITELIST_PATH = "tls_whitelist.json"
MONITOR_DURATION = 30  # seconds after granting access
TLS_PORT = 443

# Load whitelist
def load_whitelist():
    try:
        with open(WHITELIST_PATH) as f:
            return set(json.load(f)["trusted_fingerprints"])
    except:
        return set()

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
    except Exception as e:
        return None

def monitor_tls(ip, port=TLS_PORT):
    whitelist = load_whitelist()
    print(f"[TLS MONITOR] Monitoring {ip} for {MONITOR_DURATION}s...")

    start_time = time.time()
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
        close_port(ip, port)
        return

    if captured_fingerprint not in whitelist:
        print(f"[TLS] Fingerprint mismatch! Blocking {ip}")
        close_port(ip, port)
        ban_ip(ip)
    else:
        print(f"[TLS] Fingerprint matched for {ip}. Access allowed.")


