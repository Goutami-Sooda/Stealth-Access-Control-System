from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.console_logger import get_logger

logger = get_logger()

SERVER_CERT = "certs/server_cert.pem"
SERVER_KEY = "certs/server_key.pem"
CA_CERT = "certs/ca_cert.pem"

def run_tls_server():
    httpd = HTTPServer(('0.0.0.0', 443), SimpleHTTPRequestHandler)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate

    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    logger.info("🔐 mTLS HTTPS server running on https://0.0.0.0:443")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("🛑 TLS server stopped by user.")
        httpd.server_close()
        sys.exit(0)


if __name__ == "__main__":
    run_tls_server()

