import time
import json

with open("config.json") as f:
    config = json.load(f)

MAX_ATTEMPTS = config["max_failed_attempts"]
BAN_DURATION = config["ban_duration_minutes"] * 60

failed_knocks = {}
banned_ips = {}

def is_banned(ip):
    if ip in banned_ips:
        if time.time() - banned_ips[ip] > BAN_DURATION:
            del banned_ips[ip]
            return False
        return True
    return False

def register_failed_knock(ip):
    if ip not in failed_knocks:
        failed_knocks[ip] = 0
    failed_knocks[ip] += 1

    if failed_knocks[ip] >= MAX_ATTEMPTS:
        banned_ips[ip] = time.time()
        print(f"[!] IP {ip} banned for {BAN_DURATION // 60} mins")

