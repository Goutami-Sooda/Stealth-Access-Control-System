from flask import Flask, render_template, request, redirect
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import firewall
import json

app = Flask(__name__)

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
    return redirect("/")

@app.route("/unban", methods=["POST"])
def unban():
    ip = request.form["ip"]
    firewall.unban_ip(ip)
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

