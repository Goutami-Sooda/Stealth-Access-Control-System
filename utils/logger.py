from datetime import datetime

LOG_FILE = "logs/access.log"

def log_event(event):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {event}\n")

