import { verify, verifySync, currentWindow } from '../lib/auth.js';

const STALE_SECS = 90;
const EC_API = 'https://api.vercel.com/v1/edge-config';

let _endpoint = null;

function timeAgo(ts) {
  const secs = Math.floor(Date.now() / 1000) - ts;
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
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
    // Edge Config returns { items: [{ value: ... }] }
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

async function getEndpoint() {
  if (_endpoint) return _endpoint;
  // Cold start: try to recover from Edge Config
  const stored = await edgeGet('zt:endpoint');
  if (stored) _endpoint = stored;
  return _endpoint;
}

function missing(secret) {
  return !secret ? 500 : 0;
}

export default async function handler(req, res) {
  const secret = process.env.ZT_SECRET;
  if (!secret) {
    const code = 500;
    const body = JSON.stringify({ error: 'server misconfigured' });
    res.status(code).json(JSON.parse(body));
    return;
  }

  if (req.method === 'POST') {
    return handleRegister(req, res, secret);
  }

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

  const { ip, port, ts, host_pubkey, status, nat_type_suspect } = req.body || {};
  if (!ip || !port || !ts || !host_pubkey || !status) {
    return res.status(400).json({ error: 'missing required fields' });
  }

  _endpoint = { ip, port, ts, host_pubkey, status, nat_type_suspect: !!nat_type_suspect };
  await edgeSet('zt:endpoint', _endpoint);

  return res.status(200).json({ ok: true });
}

async function handleEndpoint(req, res, secret) {
  const { w, t } = req.query;
  const clientWindow = parseInt(w, 10);
  if (isNaN(clientWindow)) {
    return res.status(400).json({ error: 'invalid window' });
  }

  const serverWindow = currentWindow();
  if (!verifySync(secret, 'discover', t, clientWindow, serverWindow)) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const record = await getEndpoint();
  if (!record) {
    return res.status(404).json({ error: 'no endpoint registered' });
  }

  const now = Math.floor(Date.now() / 1000);
  const stale = (now - record.ts) > STALE_SECS;

  return res.status(200).json({ ...record, stale });
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
  .stale { background: #fff3cd; color: #856404; padding: 0.25em 0.75em; border-radius: 4px; }
</style>
</head>
<body>
<h1>ztunnel registry</h1>
<p class="meta">Endpoint info requires authentication.</p>
</body></html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(html);
}
