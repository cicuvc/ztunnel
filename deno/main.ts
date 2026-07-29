import { verify, currentWindow } from "./lib/auth.ts";

const STALE_SECS = 90;
const KV_KEY = ["zt", "endpoint"];
let _kv: Deno.Kv | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function timeAgo(ts: number): string {
  const secs = Math.floor(Date.now() / 1000) - ts;
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
}

async function getEndpoint(): Promise<Record<string, unknown> | null> {
  if (!_kv) return null;
  const result = await _kv.get<Record<string, unknown>>(KV_KEY);
  return result.value;
}

async function setEndpoint(record: Record<string, unknown>): Promise<void> {
  if (!_kv) return;
  await _kv.set(KV_KEY, record);
}

async function statusPage(): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const endpoint = await getEndpoint();
  const stale = endpoint ? (now - (endpoint.ts as number)) > STALE_SECS : true;

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>ztunnel status</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; }
  h1 { color: #333; }
  .meta { color: #666; font-size: 0.9em; }
  .status { display: inline-block; padding: 0.25em 0.75em; border-radius: 4px; font-weight: bold; }
  .active { background: #d4edda; color: #155724; }
  .down { background: #f8d7da; color: #721c24; }
  .stale { background: #fff3cd; color: #856404; }
</style>
</head>
<body>
<h1>ztunnel registry</h1>
${endpoint ? `
<p>Status: <span class="status ${endpoint.status}">${String(endpoint.status)}</span>
${stale ? ' <span class="status stale">stale</span>' : ''}</p>
<p>Endpoint: <code>${String(endpoint.ip)}:${endpoint.port}</code></p>
<p class="meta">Last heartbeat: ${timeAgo(endpoint.ts as number)}</p>
<p class="meta">nat_type_suspect: ${endpoint.nat_type_suspect ? "yes" : "no"}</p>
` : `
<p>No endpoint registered yet.</p>
`}
</body></html>`;

  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

async function handleRegister(req: Request, secret: string): Promise<Response> {
  const auth = req.headers.get("authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return json({ error: "unauthorized" }, 401);
  }

  if (!await verify(secret, "register", auth.slice(7), currentWindow())) {
    return json({ error: "unauthorized" }, 401);
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  const { ip, port, ts, host_pubkey, status } = body;
  if (!ip || !port || !ts || !host_pubkey || !status) {
    return json({ error: "missing required fields" }, 400);
  }

  const record = {
    ip,
    port,
    ts,
    host_pubkey,
    status,
    nat_type_suspect: !!body.nat_type_suspect,
  };

  await setEndpoint(record);
  return json({ ok: true });
}

async function handleEndpoint(req: Request, secret: string): Promise<Response> {
  const url = new URL(req.url);
  const w = url.searchParams.get("w");
  const t = url.searchParams.get("t");

  if (!w || !t) {
    return json({ error: "missing w or t parameter" }, 400);
  }

  const window = parseInt(w, 10);
  if (isNaN(window)) {
    return json({ error: "invalid window" }, 400);
  }

  if (!await verify(secret, "discover", t, window)) {
    return json({ error: "unauthorized" }, 401);
  }

  const endpoint = await getEndpoint();
  if (!endpoint) {
    return json({ error: "no endpoint registered" }, 404);
  }

  const now = Math.floor(Date.now() / 1000);
  const stale = (now - (endpoint.ts as number)) > STALE_SECS;

  return json({ ...endpoint, stale });
}

async function handler(req: Request): Promise<Response> {
  if (!_kv) {
    try {
      _kv = await Deno.openKv();
    } catch {
      return json({ error: "kv not available" }, 500);
    }
  }

  const secret = Deno.env.get("ZT_SECRET");
  if (!secret) {
    return json({ error: "server misconfigured" }, 500);
  }

  const url = new URL(req.url);
  const path = url.pathname;

  // POST /api → register
  if (req.method === "POST" && (path === "/api" || path === "/api/register")) {
    return handleRegister(req, secret);
  }

  // GET /api?w=&t= → endpoint lookup
  if (req.method === "GET" && (path === "/api" || path === "/api/endpoint")) {
    const w = url.searchParams.get("w");
    const t = url.searchParams.get("t");
    if (w && t) {
      return handleEndpoint(req, secret);
    }
  }

  // GET /api?cmd=time → server timestamp
  if (url.searchParams.get("cmd") === "time") {
    return json({ ts: Math.floor(Date.now() / 1000) });
  }

  // GET / or /api → status page
  return statusPage();
}

Deno.serve(handler);
