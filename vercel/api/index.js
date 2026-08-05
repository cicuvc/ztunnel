import { verify, verifySync, generate, currentWindow } from '../lib/auth.js';

const STALE_SECS = 90;
const EC_API = 'https://api.vercel.com/v1/edge-config';

// In-memory cache per service; Edge Config is the durable store.
const _endpoints = {};

// Edge Config keys allow only [A-Za-z0-9_-]; colons are rejected.
function edgeKey(service) {
  return `zt-endpoint-${service}`;
}

async function edgeGet(key) {
  const id = process.env.EDGE_CONFIG_ID;
  const token = process.env.VERCEL_API_TOKEN;
  if (!id || !token) return null;
  try {
    const resp = await fetch(`${EC_API}/${id}/items?key=${key}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) return null;
    const body = await resp.json();
    if (body.items && body.items.length > 0) {
      return body.items[0].value;
    }
    return null;
  } catch { return null; }
}

async function edgeSet(key, value) {
  const id = process.env.EDGE_CONFIG_ID;
  const token = process.env.VERCEL_API_TOKEN;
  if (!id || !token) return;
  try {
    await fetch(`${EC_API}/${id}/items`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        items: [{ operation: 'upsert', key, value }],
      }),
    });
  } catch { /* best-effort */ }
}

async function getEndpoint(service) {
  if (_endpoints[service]) return _endpoints[service];
  const stored = await edgeGet(edgeKey(service));
  if (stored) _endpoints[service] = stored;
  return _endpoints[service] || null;
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const secret = process.env.ZT_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'server misconfigured' });
  }

  if (req.method === 'POST') {
    return handleRegister(req, res, secret);
  }

  // GET /api?cmd=web-config → public SW bootstrap (url + gate token)
  if (req.query?.cmd === 'web-config') {
    return handleWebConfig(req, res, secret);
  }

  // GET /api?w=&t=[&service=] → authenticated endpoint lookup
  if (req.method === 'GET' && req.query?.w && req.query?.t) {
    return handleEndpoint(req, res, secret);
  }

  if (req.query?.cmd === 'time') {
    return res.status(200).json({ ts: Math.floor(Date.now() / 1000) });
  }

  return handleStatus(req, res);
}

async function handleRegister(req, res, secret) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  if (!verify(secret, 'register', auth.slice(7), currentWindow())) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const { ip, port, ts, host_pubkey, status, nat_type_suspect, service } = req.body || {};
  if (!ip || !port || !ts || !status) {
    return res.status(400).json({ error: 'missing required fields' });
  }

  const svc = service || 'ssh';
  const record = {
    ip, port, ts,
    host_pubkey: host_pubkey || '',
    status,
    nat_type_suspect: !!nat_type_suspect,
    service: svc,
  };
  _endpoints[svc] = record;
  await edgeSet(edgeKey(svc), record);

  return res.status(200).json({ ok: true });
}

async function handleEndpoint(req, res, secret) {
  const { w, t, service } = req.query;
  const window = parseInt(w, 10);
  if (isNaN(window)) {
    return res.status(400).json({ error: 'invalid window' });
  }

  if (!verifySync(secret, 'discover', t, window, currentWindow())) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const record = await getEndpoint(service || 'ssh');
  if (!record) {
    return res.status(404).json({ error: 'no endpoint registered' });
  }

  const now = Math.floor(Date.now() / 1000);
  const stale = (now - record.ts) > STALE_SECS;

  return res.status(200).json({ ...record, stale });
}

// Public bootstrap for the service worker.  The gate token is NOT access
// control (any visitor can fetch it) — it only keeps the punched port
// invisible to dumb scanners.  Real auth is the web app's job.
async function handleWebConfig(req, res, secret) {
  const domain = process.env.WEB_DOMAIN;
  if (!domain) {
    return res.status(500).json({ error: 'WEB_DOMAIN not configured' });
  }

  const record = await getEndpoint('web');
  if (!record) {
    return res.status(404).json({ error: 'web service not registered' });
  }

  const now = Math.floor(Date.now() / 1000);
  const stale = (now - record.ts) > STALE_SECS;
  if (stale || record.status !== 'active') {
    return res.status(503).json({ error: 'web service unavailable', stale });
  }

  const window = currentWindow();
  const gate = generate(secret, 'gate', window);

  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({
    url: `https://${domain}:${record.port}`,
    window,
    gate,
  });
}

function handleStatus(req, res) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>ztunnel status</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; }
  h1 { color: #333; }
  .meta { color: #666; font-size: 0.9em; }
</style>
</head>
<body>
<h1>ztunnel registry</h1>
<p class="meta">Endpoint info requires authentication.</p>
</body></html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(html);
}
