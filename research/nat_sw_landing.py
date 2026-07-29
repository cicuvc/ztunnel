#!/usr/bin/env python3
"""
Local Service Worker Landing Page Server (for testing).

Serves the SW landing page and sw.js locally, bypassing Cloudflare Worker.
The SW forwards requests to the NAT backend.

Usage: python3 nat_sw_landing.py [backend_port]
"""

import ssl, http.server, threading, time, sys, os

CERT_DIR = os.environ.get("CERT_DIR", os.path.join(os.path.dirname(__file__), "cbot/live/cicuvc.top"))
CERT = os.path.join(CERT_DIR, "fullchain.pem")
KEY = os.path.join(CERT_DIR, "privkey.pem")
SW_PORT = 9443
BACKEND_DOMAIN = "test.cicuvc.top"
BACKEND_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5917

BACKEND_URL = f"https://{BACKEND_DOMAIN}:{BACKEND_PORT}"

# ── HTML & SW ───────────────────────────────────────────────────

LANDING_HTML = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NAT SW</title>
<style>
body{{font-family:system-ui;max-width:640px;margin:60px auto;padding:20px;background:#111;color:#eee}}
h1{{color:#0f0}}pre{{background:#222;padding:15px;border-radius:8px}}
</style></head><body>
<h1>NAT Traversal via Service Worker</h1>
<pre id="status">Loading...</pre>
<script>
function log(m){{document.getElementById("status").innerHTML+=m+"\\n";}}
fetch("/_config").then(r=>r.text()).then(u=>{{
  log("Backend: "+u);
  if("serviceWorker" in navigator){{
    navigator.serviceWorker.register("/sw.js",{{scope:"/"}})
      .then(r=>log("SW registered"))
      .catch(e=>log("SW error: "+e));
  }}else{{log("SW not supported");}}
}});
</script></body></html>'''.encode()

SW_JS = b'''let U=null;
self.addEventListener("install",e=>{
  self.skipWaiting();
  e.waitUntil(
    fetch("/_config").then(r=>r.text()).then(u=>{U=u;})
  );
});
self.addEventListener("activate",e=>{e.waitUntil(clients.claim());});
self.addEventListener("message",e=>{
  if(e.data?.type==="update-backend")U=e.data.url;
});
self.addEventListener("fetch",e=>{
  let u=new URL(e.request.url);
  if(u.hostname!==self.location.hostname||u.pathname==="/sw.js"||u.pathname==="/_config"||!U)return;
  e.respondWith(
    fetch(U+u.pathname+u.search).catch(err=>new Response("Backend unreachable: "+err,{status:502}))
  );
});
'''

CONFIG_BODY = BACKEND_URL.encode()

# ── Handler ─────────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/sw.js':
            body = SW_JS
            content_type = 'application/javascript'
        elif self.path == '/_config':
            body = CONFIG_BODY
            content_type = 'text/plain'
        else:
            body = LANDING_HTML
            content_type = 'text/html; charset=utf-8'

        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

# ── Main ────────────────────────────────────────────────────────

def main():
    print(f"[sw-landing] Backend: {BACKEND_URL}", flush=True)
    print(f"[sw-landing] Starting on :{SW_PORT}...", flush=True)

    server = http.server.HTTPServer(('0.0.0.0', SW_PORT), Handler)
    server.allow_reuse_address = True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    ctx.set_alpn_protocols(['http/1.1'])
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"[sw-landing] Ready: https://localhost:{SW_PORT}/", flush=True)
    print(f"[sw-landing] PID: {os.getpid()}", flush=True)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)

if __name__ == "__main__":
    main()
