from scapy.all import sniff, IP, TCP
import json
import time
import os
from action_trigger import allow_access, verify_tls_fingerprint
from utils.firewall import ban_ip, unban_ip
from datetime import datetime
from utils.logger import log_ban, log_access
import threading
from utils.firewall import block_ports_globally, register_cleanup
	

# Load config
with open("config.json") as f:
    config = json.load(f)
   
# Block ports 22 and 443 until correct knock + TLS
block_ports_globally()
register_cleanup()

KNOCK_SEQUENCE = config["knock_sequence"]
MAX_FAILED_ATTEMPTS = config["max_failed_attempts"]
BAN_DURATION = config["ban_duration_minutes"] * 60

# Global state
knock_state = {}
failed_attempts = {}
banned_ips = {}

# Ports to ignore completely
NOISE_PORTS = [6633]

def process_packet(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    tcp_layer = packet[TCP]
    ip_layer = packet[IP]

    # Only handle SYN packets
    if tcp_layer.flags != 0x02:
        return

    src_ip = ip_layer.src
    dst_port = tcp_layer.dport

    # Ignore noise ports like 6633
    if dst_port in NOISE_PORTS:
        return

    print(f"[PACKET] from {src_ip} to port {dst_port}")

    # If IP is banned, ignore
    if src_ip in banned_ips:
        return

    current_sequence = knock_state.get(src_ip, [])
    
    # Avoid duplicate knocks (same port repeated)
    if current_sequence and dst_port == current_sequence[-1]:
        return

    expected_index = len(current_sequence)

    if expected_index < len(KNOCK_SEQUENCE) and dst_port == KNOCK_SEQUENCE[expected_index]:
        knock_state.setdefault(src_ip, []).append(dst_port)
            
        if knock_state[src_ip] == KNOCK_SEQUENCE:
            print(f"[✅] Correct sequence from {src_ip}")
            log_access(src_ip, "Correct knock sequence")
            result = verify_tls_fingerprint(src_ip)

            if result:
                allow_access(src_ip)
                log_access(src_ip, "Access granted after TLS fingerprint match")
            else:
                log_access(src_ip, "Access denied due to TLS fingerprint failure")

            knock_state.pop(src_ip, None)
            failed_attempts[src_ip] = 0
            
    else:
        print(f"[❌] Incorrect knock from {src_ip} on port {dst_port}")
        knock_state.pop(src_ip, None)
        failed_attempts[src_ip] = failed_attempts.get(src_ip, 0) + 1

        if failed_attempts[src_ip] >= MAX_FAILED_ATTEMPTS:
            ban_ip(src_ip)
            banned_ips[src_ip] = time.time()
            print(f"[BANNED] Too many failed knocks ({MAX_FAILED_ATTEMPTS}) from {src_ip}")
            log_ban(src_ip, f"BANNED - Too many failed knocks ({MAX_FAILED_ATTEMPTS})")
        else:
            log_access(src_ip, f"Knock failed at port {dst_port} | Attempt {failed_attempts[src_ip]}")

def cleanup_bans():
    while True:
        now = time.time()
        for ip in list(banned_ips):
            if now - banned_ips[ip] > BAN_DURATION:
                unban_ip(ip)
                print(f"[INFO] Unbanned {ip} after cooldown")
                banned_ips.pop(ip)
        time.sleep(30)

# Start background thread to cleanup expired bans
threading.Thread(target=cleanup_bans, daemon=True).start()

print("[*] Knock listener running...")
sniff(filter="tcp", prn=process_packet, iface='lo', store=0)

