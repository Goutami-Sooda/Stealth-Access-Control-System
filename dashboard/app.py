from flask import Flask, render_template, request, redirect, flash
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import firewall
import json

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Needed for flashing messages

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "../logs")
BANNED_FILE = os.path.join(LOGS_DIR, "banned.txt")
ACCESS_LOG = os.path.join(LOGS_DIR, "access.log")

@app.route("/")
def index():
    access_logs = []
    banned_logs = []

    if os.path.exists(ACCESS_LOG):
        with open(ACCESS_LOG) as f:
            access_logs = f.readlines()

    if os.path.exists(BANNED_FILE):
        with open(BANNED_FILE) as f:
            banned_logs = f.readlines()

    return render_template("index.html", access_logs=access_logs[::-1], banned_logs=banned_logs[::-1])

@app.route("/ban", methods=["POST"])
def ban():
    ip = request.form["ip"]
    firewall.ban_ip(ip)
    flash(f"✅ Successfully banned IP: {ip}", "failure")
    return redirect("/")

@app.route("/unban", methods=["POST"])
def unban():
    ip = request.form["ip"]
    firewall.unban_ip(ip)
    flash(f"🟢 Successfully unbanned IP: {ip}", "success")
    return redirect("/")
    

@app.route("/ban-port", methods=["POST"])
def ban_port():
    ip = request.form["ip"]
    port = request.form["port"]
    if ip and port.isdigit():
        firewall.ban_port(ip, int(port))
        flash(f"✅ Access to port {port} banned for IP {ip}", "failure")
    else:
        flash("🛑 Invalid IP or Port", "failure")
    return redirect("/")

@app.route("/unban-port", methods=["POST"])
def unban_port():
    ip = request.form["ip"]
    port = request.form["port"]
    if ip and port.isdigit():
        firewall.unban_port(ip, int(port))
        flash(f"🟢 Access to port {port} unbanned for IP {ip}", "success")
    else:
        flash("🛑 Invalid IP or Port", "failure")
    return redirect("/")


if __name__ == "__main__":
    app.run(host="10.0.2.15", port=5000)

