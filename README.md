# 🕵️‍♂️ Stealth Access Control System

A secure, covert access gateway that combines **Port Knocking**, **Firewall Manipulation**, and **Mutual TLS (mTLS)** to stealthily grant access to protected services (like SSH or HTTPS). Unauthorized users see all ports as filtered or closed — even scanning tools like `nmap` reveal nothing — until the right knock sequence and certificate are presented.

---

## 🔐 Features

- 🔒 **Stealth Firewall**: Blocks all sensitive ports by default.
- 🔑 **Port Knocking Listener**: Authenticates clients using a secret TCP SYN sequence.
- 🧾 **TLS Fingerprinting**: Only allows clients with valid mTLS certificates.
- ⏱️ **Temporary Port Access**: Grants time-bound access to specific IP:port pairs.
- 🛡️ **Ban System**: Automatically bans IPs after failed attempts.
- 🌐 **Flask Admin UI**: Web interface to manage bans, view logs, and test access.

---

## 🚀 Project Setup

```bash
git clone https://github.com/Goutami-Sooda/Stealth-Access-Control-System.git
cd Stealth-access-port-knocking-system

# (Optional) Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🖥️ Running the System

### 1️⃣ Start Knock Listener

```bash
sudo -E python3 knock_listener.py
```

> 🔐 System starts in a hardened state: all sensitive ports (e.g., 22, 443) are blocked by default for all IPs.

Check that access is denied:
```bash
nmap -p 22 localhost
# Result should show "filtered"
```

---

### 2️⃣ Send Secret Knock Sequence

Use **TCP SYN packets** to the following ports **in order**:

**Secret Sequence**:  
`[53842, 49123, 61432, 55021, 52375]`

```bash
sudo hping3 -S -p 53842 127.0.0.1 -c 1
sudo hping3 -S -p 49123 127.0.0.1 -c 1
sudo hping3 -S -p 61432 127.0.0.1 -c 1
sudo hping3 -S -p 55021 127.0.0.1 -c 1
sudo hping3 -S -p 52375 127.0.0.1 -c 1
```

> If the sequence is correct, the listener grants temporary access (e.g., 90s) to port 443 for that IP.

---

### 3️⃣ TLS Server & Fingerprint Verification

- `tls_server.py` launches HTTPS server on port 443.
- `tls_monitor.py` checks client’s certificate fingerprint.
- If the fingerprint matches a trusted one as listed in `tls_whitelist.json`, access is confirmed.

✔️ **Valid Cert Output**:
```
[TLS MONITOR] Client cert fingerprint: <SHA256>
[TLS] Fingerprint matched for 127.0.0.1. Access allowed.
```

❌ **Invalid Cert Output**:
```
[TLS] Client fingerprint mismatch! Blocking 127.0.0.1
```

---

### 4️⃣ Confirm Access is Granted

After successful knock + TLS verification:

```bash
nmap -p 22 localhost
# Port 22 should now appear as open
```

---

### 5️⃣ Access Expiry & Cleanup

After timeout (e.g., 120 seconds), access is revoked:

```
[INFO] Access expired for 127.0.0.1
[-] Removed port 443 access for 127.0.0.1
```

---

### 6️⃣ Flask Admin UI

```bash
python3 app.py
```

> Open in browser: [http://10.0.2.15:5000](http://10.0.2.15:5000)

**Features**:
- 🔘 Ban/Unban IPs
- 🔘 Ban/Unban IP:Port combinations
- 📜 View live access & ban logs

---

## 🎯 File Structure

| Path                   | Description |
|------------------------|-------------|
| `knock_listener.py`    | Listens for TCP SYN packets to detect knock sequence |
| `tls_utils/tls_server.py`        | HTTPS server for client certificate verification |
| `tls_monitor.py`       | TLS handshake monitor with fingerprint matching |
| `utils/firewall.py`          | Manages `iptables` rules (ban/unban/open/close) |
| `app.py`               | Flask UI backend |
| `templates/`           | HTML templates for UI |
| `certs/`               | TLS keys, certs, and CA trust store |
| `logs/`                | Access and ban log files |
| `requirements.txt`     | Python dependencies list |

---

## 💡 Security Highlights

- 🔐 **Passive knock detection** (via `scapy`) = zero response before full auth
- 🔒 **Firewall enforcement** using `iptables`
- ✅ **mTLS authentication** with certificate pinning (fingerprint whitelist)
- ⏱️ **Timed access** and automatic rule revocation
- 🛑 **Ban after failed attempts** to mitigate brute-force

