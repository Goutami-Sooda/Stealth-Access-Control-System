import subprocess

def open_port(ip, port):
    subprocess.call(f"sudo iptables -I INPUT -p tcp --dport {port} -s {ip} -j ACCEPT", shell=True)

def close_port(ip, port):
    subprocess.call(f"sudo iptables -D INPUT -p tcp --dport {port} -s {ip} -j ACCEPT", shell=True)

def ban_ip(ip):
    subprocess.call(f"sudo iptables -I INPUT -s {ip} -j DROP", shell=True)

def unban_ip(ip):
    subprocess.call(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True)

