#!/usr/bin/env python3
"""
NAT Traversal Backend Server.

Features:
  - STUN TCP hole punching to discover NAT mapping
  - HTTPS server with CORS headers (required for Service Worker forwarding)
  - Hairpin keepalive to maintain NAT mapping indefinitely
  - Cloudflare DNS HTTPS record updates (RFC 9460)

Usage:
  python3 nat_backend.py

Environment:
  CERT_DIR  - path to TLS cert/key (default: cbot/live/cicuvc.top)
  LOCAL_PORT - local port to expose (default: 8443)
"""

import socket, struct, os, time, ssl, http.server, threading, subprocess, json, sys

# ── Configuration ──────────────────────────────────────────────

CERT_DIR = os.environ.get("CERT_DIR", os.path.join(os.path.dirname(__file__), "cbot/live/cicuvc.top"))
CERT = os.path.join(CERT_DIR, "fullchain.pem")
KEY = os.path.join(CERT_DIR, "privkey.pem")
LOCAL_PORT = int(os.environ.get("LOCAL_PORT", "8443"))
DOMAIN = "test.cicuvc.top"
ZONE_ID = "ae9649f2546dcc544b0cc03801d6efef"
REC_ID = "be7a3b52e5127d796ec6edebd5773200"

STUN_SERVER = "stunserver2025.stunprotocol.org"
STUN_PORT = 3478
MAGIC = 0x2112A442

PUBLIC_IP = "120.37.185.53"

# Read CF token from file
CF_TOKEN_FILE = os.path.join(os.path.dirname(__file__), "cf_auth.txt")
CF_TOKEN = None
try:
    with open(CF_TOKEN_FILE) as f:
        for line in f:
            if line.startswith("Key:"):
                CF_TOKEN = line.split(":", 1)[1].strip()
                break
except Exception:
    pass

# ── STUN ────────────────────────────────────────────────────────

def stun_request():
    return struct.pack('!HHI', 0x0001, 0, MAGIC) + os.urandom(12)

def parse_xor_mapped(data):
    if len(data) < 20:
        return None
    _, msg_len, magic = struct.unpack('!HHI', data[:8])
    if magic != MAGIC:
        return None
    pos = 20
    while pos + 4 <= 20 + msg_len:
        attr_type, attr_len = struct.unpack('!HH', data[pos:pos+4])
        pos += 4
        if attr_type == 0x0020 and data[pos+1] == 0x01:
            x_port = struct.unpack('!H', data[pos+2:pos+4])[0]
            x_addr = struct.unpack('!I', data[pos+4:pos+8])[0]
            port = x_port ^ (MAGIC >> 16)
            ip_int = x_addr ^ MAGIC
            ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            return (ip, port)
        pos += ((attr_len + 3) // 4) * 4
    return None

def punch_hole(local_port, timeout=5):
    """Create outbound TCP connection to STUN, return (public_ip, public_port)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', local_port))
    s.settimeout(timeout)
    s.connect((STUN_SERVER, STUN_PORT))
    s.sendall(stun_request())
    data = s.recv(4096)
    s.close()
    return parse_xor_mapped(data)

# ── DNS ─────────────────────────────────────────────────────────

def update_dns_https_record(public_port):
    """Update Cloudflare HTTPS DNS record via API."""
    if not CF_TOKEN:
        return False
    val = f'alpn="http/1.1" port="{public_port}" ipv4hint="{PUBLIC_IP}"'
    body = json.dumps({
        "type": "HTTPS", "name": DOMAIN, "ttl": 60,
        "data": {"priority": 1, "target": ".", "value": val}
    })
    try:
        r = subprocess.run(
            ['curl', '-s', '-m', '8', '-X', 'PUT',
             f'https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records/{REC_ID}',
             '-H', f'Authorization: Bearer {CF_TOKEN}',
             '-H', 'Content-Type: application/json', '-d', body],
            capture_output=True, text=True, timeout=10)
        return json.loads(r.stdout).get('success', False)
    except Exception as e:
        print(f"[dns] update error: {e}", flush=True)
        return False

# ── HTTPS Server ────────────────────────────────────────────────

def cors_headers(handler):
    handler.send_header('Access-Control-Allow-Origin', '*')
    handler.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    handler.send_header('Access-Control-Allow-Headers', '*')

def make_backend_handler(port):
    html = f'<h1>NAT Backend</h1><p>Port: {port}</p><p>Time: {time.time()}</p>'.encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html)))
            cors_headers(self)
            self.end_headers()
            self.wfile.write(html)

        def do_OPTIONS(self):
            self.send_response(204)
            cors_headers(self)
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler

def start_https_server(port, handler_cls):
    server = http.server.HTTPServer(('0.0.0.0', port), handler_cls)
    server.allow_reuse_address = True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(['http/1.1', 'h2'])
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread

# ── Hairpin Keepalive ───────────────────────────────────────────

def start_hairpin_keepalive(public_port):
    def loop():
        delay = 0.3
        while True:
            try:
                s = socket.socket()
                s.settimeout(3)
                s.connect((PUBLIC_IP, public_port))
                try:
                    s.recv(4096)
                except Exception:
                    pass
                s.close()
                delay = 20  # Slow down once connected
            except Exception:
                delay = min(delay * 1.5, 5)  # Fast retry on failure
            time.sleep(delay)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

# ── Main ────────────────────────────────────────────────────────

def main():
    print(f"[1/4] Punching NAT hole via STUN (local port {LOCAL_PORT})...", flush=True)
    mapping = punch_hole(LOCAL_PORT)
    if not mapping:
        print("ERROR: Could not discover NAT mapping", flush=True)
        sys.exit(1)

    public_ip, public_port = mapping
    print(f"  Mapping: {LOCAL_PORT} -> {public_ip}:{public_port}", flush=True)

    print("[2/4] Starting HTTPS server with CORS...", flush=True)
    handler_cls = make_backend_handler(public_port)
    server, _ = start_https_server(LOCAL_PORT, handler_cls)
    print(f"  Server running on :{LOCAL_PORT} (ALPN: http/1.1, h2)", flush=True)

    print("[3/4] Starting hairpin keepalive...", flush=True)
    start_hairpin_keepalive(public_port)
    print("  Keepalive active", flush=True)

    print("[4/4] Updating DNS HTTPS record...", flush=True)
    if update_dns_https_record(public_port):
        print(f"  DNS updated: port={public_port}", flush=True)
    else:
        print(f"  DNS update skipped (no token or failed)", flush=True)

    print(f"\n{'='*55}", flush=True)
    print(f"  URL:     https://{DOMAIN}:{public_port}", flush=True)
    print(f"  Backend: {PUBLIC_IP}:{public_port} -> localhost:{LOCAL_PORT}", flush=True)
    print(f"  CORS:    enabled (Access-Control-Allow-Origin: *)", flush=True)
    print(f"  PID:     {os.getpid()}", flush=True)
    print(f"{'='*55}", flush=True)
    print("Press Ctrl+C to stop", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)

if __name__ == "__main__":
    main()
