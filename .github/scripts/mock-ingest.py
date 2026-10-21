"""A stand-in for the Wedgetail ingest endpoint, for CI only.

Serves HTTPS on [::]:PORT (IPv4 and IPv6) with the given certificate and implements just
enough of the agent contract to test a real install end to end:

  POST /v1/agent/enrol   Bearer wge_... -> {host_id, credential, rotate_after_days}
  POST /v1/agent/events  Bearer <credential>, gzip NDJSON; every line is appended to OUT.
                         A repeated X-Wedgetail-Batch-Id gets the stored reply and is not
                         written again (the real server is idempotent the same way).

Usage: python mock-ingest.py PORT CERT.pem KEY.pem OUT.ndjson
"""

import gzip
import json
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST_ID = "h0st0000ci01"
CREDENTIAL = "wgh_h0st0000ci01_" + "C" * 43
MAX_BODY = 1024 * 1024

lock = threading.Lock()
batches = {}


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self.reply(413, {"error": "too large", "limit": MAX_BODY})
        body = self.rfile.read(length)
        auth = self.headers.get("Authorization", "")
        if self.path == "/v1/agent/enrol":
            if not auth.startswith("Bearer wge_"):
                return self.reply(401, {"error": "Missing or invalid credential."})
            return self.reply(
                200,
                {"host_id": HOST_ID, "credential": CREDENTIAL, "rotate_after_days": 14},
            )
        if self.path != "/v1/agent/events":
            return self.reply(404, {"error": "not found"})
        if auth != "Bearer " + CREDENTIAL:
            return self.reply(401, {"error": "Missing or invalid credential."})
        batch = self.headers.get("X-Wedgetail-Batch-Id", "")
        if not batch:
            return self.reply(400, {"error": "missing batch id"})
        with lock:
            if batch in batches:
                return self.reply(200, batches[batch])
            if self.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
            lines = [l for l in body.decode("utf-8").split("\n") if l.strip()]
            with open(OUT, "a", encoding="utf-8", newline="\n") as f:
                for line in lines:
                    json.loads(line)
                    f.write(line + "\n")
            batches[batch] = {"accepted": len(lines), "skipped": 0, "errors": []}
            return self.reply(200, batches[batch])

    def log_message(self, fmt, *args):
        sys.stderr.write("mock-ingest: " + (fmt % args) + "\n")


class DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    port, cert, key, OUT = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server = DualStackServer(("::", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    sys.stderr.write(f"mock-ingest: listening on https://localhost:{port}\n")
    server.serve_forever()
