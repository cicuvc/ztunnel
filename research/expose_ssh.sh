#!/bin/bash
# expose_ssh.sh — Expose local SSH (port 22) to the internet via NAT traversal.
#
# Usage:
#   ./expose_ssh.sh [local_port] [target_port]
#
# Default: listens on local port 2222, relays to localhost:22
#
# The script:
#   1. Punches a TCP hole via STUN to discover the public IP:port mapping
#   2. Starts a TCP relay: local_port -> localhost:22
#   3. Maintains the NAT mapping with hairpin keepalive
#   4. Prints the public address for remote SSH access
#
# Press Ctrl+C to stop.

set -e

LOCAL_PORT="${1:-2222}"
TARGET_HOST="${2:-127.0.0.1}"
TARGET_PORT="${3:-22}"

STUN_SERVER="stunserver2025.stunprotocol.org"
STUN_PORT=3478

echo "=========================================="
echo "  SSH Exposer — NAT Traversal"
echo "=========================================="
echo "  Local relay: :${LOCAL_PORT} -> ${TARGET_HOST}:${TARGET_PORT}"
echo ""

python3 -u << PYEOF
import socket, struct, os, time, threading, signal, sys

STUN = "${STUN_SERVER}"
STUN_PORT = ${STUN_PORT}
MAGIC = 0x2112A442
LOCAL_PORT = ${LOCAL_PORT}
TARGET = ("${TARGET_HOST}", ${TARGET_PORT})
PUBLIC_IP = None

# ── STUN ────────────────────────────────────────────────────────
def stun_request():
    return struct.pack('!HHI', 0x0001, 0, MAGIC) + os.urandom(12)

def parse_mapping(data):
    if len(data) < 20: return None
    _, ml, mg = struct.unpack('!HHI', data[:8])
    if mg != MAGIC: return None
    pos = 20
    while pos + 4 <= 20 + ml:
        t, l = struct.unpack('!HH', data[pos:pos+4]); pos += 4
        if t == 0x0020 and data[pos+1] == 0x01:
            xp = struct.unpack('!H', data[pos+2:pos+4])[0]
            xa = struct.unpack('!I', data[pos+4:pos+8])[0]
            port = xp ^ (MAGIC >> 16)
            ip = socket.inet_ntoa(struct.pack('!I', xa ^ MAGIC))
            return (ip, port)
        pos += ((l + 3) // 4) * 4
    return None

def punch():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', LOCAL_PORT))
    s.settimeout(5)
    s.connect((STUN, STUN_PORT))
    s.sendall(stun_request())
    data = s.recv(4096)
    s.close()
    return parse_mapping(data)

# ── Relay ───────────────────────────────────────────────────────
def relay_client(client_sock):
    try:
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.settimeout(10)
        target.connect(TARGET)

        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data: break
                    dst.sendall(data)
            except: pass

        t1 = threading.Thread(target=pipe, args=(client_sock, target), daemon=True)
        t2 = threading.Thread(target=pipe, args=(target, client_sock), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
    except Exception as e:
        pass
    finally:
        try: client_sock.close()
        except: pass
        try: target.close()
        except: pass

# ── Hairpin ─────────────────────────────────────────────────────
def hairpin(pub_port):
    delay = 0.3
    while True:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((PUBLIC_IP, pub_port))
            try: s.recv(4096)
            except: pass
            s.close()
            delay = 20
        except:
            delay = min(delay * 1.5, 5)
        time.sleep(delay)

# ── Main ────────────────────────────────────────────────────────
print("[1/3] Punching NAT hole via STUN...")
mapping = punch()
if not mapping:
    print("ERROR: Could not discover NAT mapping", flush=True)
    sys.exit(1)

PUBLIC_IP, public_port = mapping
print(f"       Mapping: :{LOCAL_PORT} -> {PUBLIC_IP}:{public_port}")
print(f"")

# Start relay server
print("[2/3] Starting TCP relay...")
relay_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
relay_sock.bind(('0.0.0.0', LOCAL_PORT))
relay_sock.listen(10)

def accept_loop():
    while True:
        try:
            client, addr = relay_sock.accept()
            print(f"       [+] Connection from {addr[0]}:{addr[1]}", flush=True)
            threading.Thread(target=relay_client, args=(client,), daemon=True).start()
        except: break

threading.Thread(target=accept_loop, daemon=True).start()
print(f"       Relaying :{LOCAL_PORT} -> {TARGET[0]}:{TARGET[1]}")
print(f"")

# Start hairpin
print("[3/3] Starting hairpin keepalive...")
threading.Thread(target=hairpin, args=(public_port,), daemon=True).start()
print(f"       Keepalive active")
print(f"")

# Print summary
print("=" * 55)
print(f"  Remote SSH access:")
print(f"")
print(f"    ssh -p {public_port} USER@{PUBLIC_IP}")
print(f"")
print(f"  From the external test machine:")
print(f"    sshpass -p 'wef8o4j%!dd' ssh -p 10002 tmpacc@82.156.246.57")
print(f"    nc {PUBLIC_IP} {public_port}")
print(f"")
print(f"  Mapping: {LOCAL_PORT} -> {PUBLIC_IP}:{public_port} -> sshd")
print(f"  PID:     {os.getpid()}")
print("=" * 55)
print("Press Ctrl+C to stop")
print("")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopped.")
PYEOF
