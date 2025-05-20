from scapy.all import sniff, IP, TCP
import json
import time
import os
from action_trigger import allow_access
from utils.firewall import ban_ip
from datetime import datetime


with open("config.json") as f:
    config = json.load(f)

KNOCK_SEQUENCE = config["knock_sequence"]
MAX_FAILED_ATTEMPTS = config["max_failed_attempts"]
BAN_DURATION = config["ban_duration_minutes"] * 60

logs_dir = "logs"
os.makedirs(logs_dir, exist_ok=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BANNED_LOG = os.path.join(BASE_DIR, "logs/banned.txt")
ACCESS_LOG = os.path.join(BASE_DIR, "logs/access.log")

# Global state
knock_state = {}
failed_attempts = {}
banned_ips = {}

def log_access(ip, status):
     with open(ACCESS_LOG, "a") as f:
        f.write(f"[{datetime.now()}] {ip} => {status}\n")

def log_ban(ip):
    with open(BANNED_LOG, "a") as f:
        f.write(f"[{datetime.now()}] {ip} => BANNED\n")

from scapy.layers.inet import IP, TCP

def process_packet(packet):
    # Ensure the packet has both TCP and IP layers
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    tcp_layer = packet[TCP]
    ip_layer = packet[IP]

    # Only process packets with SYN flag (i.e. start of connection attempt)
    if tcp_layer.flags != 0x02:
    	return

    src_ip = ip_layer.src
    dst_port = tcp_layer.dport

    print(f"[PACKET] from {src_ip} to port {dst_port}")

    # If IP is banned, ignore
    if src_ip in banned_ips:
        return

    # Get the expected index in the knock sequence
    expected_index = len(knock_state.get(src_ip, []))

    # If the knock is in correct order
    if expected_index < len(KNOCK_SEQUENCE) and dst_port == KNOCK_SEQUENCE[expected_index]:
        knock_state.setdefault(src_ip, []).append(dst_port)

        # If full correct sequence matched
        if knock_state[src_ip] == KNOCK_SEQUENCE:
            log_access(src_ip, "Correct knock sequence")
            allow_access(src_ip)
            knock_state.pop(src_ip, None)
            failed_attempts[src_ip] = 0  # reset failed attempt counter
    else:
        # Reset state and increase failure count
        knock_state.pop(src_ip, None)
        failed_attempts[src_ip] = failed_attempts.get(src_ip, 0) + 1

        if failed_attempts[src_ip] >= MAX_FAILED_ATTEMPTS:
            ban_ip(src_ip)
            banned_ips[src_ip] = time.time()
            log_ban(src_ip)




def cleanup_bans():
    while True:
        now = time.time()
        for ip in list(banned_ips):
            if now - banned_ips[ip] > BAN_DURATION:
                from utils.firewall import unban_ip
                unban_ip(ip)
                banned_ips.pop(ip)
        time.sleep(30)

import threading
threading.Thread(target=cleanup_bans, daemon=True).start()

print("[*] Knock listener running...")
sniff(filter="tcp", prn=process_packet, iface='lo', store=0)

