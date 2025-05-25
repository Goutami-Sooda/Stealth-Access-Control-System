# tls_client.py (modified)
import ssl
import socket
import hashlib

def get_tls_fingerprint(host, port=443):
    # Create an unverified SSL context for demo/testing
    context = ssl._create_unverified_context()

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher = ssock.cipher()

            fingerprint = hashlib.sha256(cert_bin).hexdigest()

            print(f"🔒 TLS Version: {tls_version}")
            print(f"🔐 Cipher: {cipher}")
            print(f"🧬 Fingerprint (SHA256): {fingerprint}")
            return fingerprint

if __name__ == "__main__":
    get_tls_fingerprint("localhost", 443)

