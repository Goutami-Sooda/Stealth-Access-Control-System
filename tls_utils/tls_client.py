import ssl
import socket

CLIENT_CERT = "certs/client_cert.pem"
CLIENT_KEY = "certs/client_key.pem"
CA_CERT = "certs/ca_cert.pem"

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

with socket.create_connection(("localhost", 443)) as sock:
    with context.wrap_socket(sock, server_hostname="localhost") as ssock:
        print("🔐 Connected to server using mTLS")
        print(f"TLS Version: {ssock.version()}")
        print(f"Cipher: {ssock.cipher()}")

