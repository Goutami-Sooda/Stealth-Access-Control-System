from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

SERVER_CERT = "certs/server_cert.pem"
SERVER_KEY = "certs/server_key.pem"
CA_CERT = "certs/ca_cert.pem"

httpd = HTTPServer(('0.0.0.0', 443), SimpleHTTPRequestHandler)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
context.load_verify_locations(cafile=CA_CERT)
context.verify_mode = ssl.CERT_REQUIRED  # Require client certificate

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("🔐 mTLS HTTPS server running on https://0.0.0.0:443")
httpd.serve_forever()

