import os
from datetime import datetime

print("Logger loaded and log directory ensured.")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "../logs")
os.makedirs(LOGS_DIR, exist_ok=True)

ACCESS_LOG = os.path.join(LOGS_DIR, "access.log")
BANNED_LOG = os.path.join(LOGS_DIR, "banned.txt")

def log_access(ip, message):
    with open(ACCESS_LOG, "a") as f:
        f.write(f"[{datetime.now()}] {ip} => {message}\n")

def log_ban(ip, message):
    with open(BANNED_LOG, "a") as f:
        f.write(f"[{datetime.now()}] {ip} => {message}\n")

