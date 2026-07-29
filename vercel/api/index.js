import { verify, currentWindow } from '../lib/auth.js';

const STALE_SECS = 90;

// In-memory store: shared within the same function instance.
// Updated every 20s by heartbeat; cold-start gaps are brief and self-healing.
let _endpoint = null;

function timeAgo(ts) {
  const secs = Math.floor(Date.now() / 1000) - ts;
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  return `${Math.floor(secs / 3600)}h ago`;
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

  // POST /api → register
  if (req.method === 'POST') {
    return handleRegister(req, res, secret);
  }

  // GET /api?w=&t= → endpoint lookup
  if (req.method === 'GET' && req.query?.w && req.query?.t) {
    return handleEndpoint(req, res, secret);
  }

  // GET /api?cmd=time → server timestamp (for clock sync)
  if (req.query?.cmd === 'time') {
    return res.status(200).json({ ts: Math.floor(Date.now() / 1000) });
  }

  // GET /api (no params) → status page
  return handleStatus(req, res);
}

function handleRegister(req, res, secret) {
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

  return res.status(200).json({ ok: true });
}

function handleEndpoint(req, res, secret) {
  const { w, t } = req.query;
  const window = parseInt(w, 10);
  if (isNaN(window)) {
    return res.status(400).json({ error: 'invalid window' });
  }

  if (!verify(secret, 'discover', t, window)) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  if (!_endpoint) {
    return res.status(404).json({ error: 'no endpoint registered' });
  }

  const now = Math.floor(Date.now() / 1000);
  const stale = (now - _endpoint.ts) > STALE_SECS;

  return res.status(200).json({ ..._endpoint, stale });
}

function handleStatus(req, res) {
  const now = Math.floor(Date.now() / 1000);
  const stale = _endpoint ? (now - _endpoint.ts) > STALE_SECS : true;

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>ztunnel status</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; }
  h1 { color: #333; }
  .status { display: inline-block; padding: 0.25em 0.75em; border-radius: 4px; font-weight: bold; }
  .active { background: #d4edda; color: #155724; }
  .down { background: #f8d7da; color: #721c24; }
  .stale { background: #fff3cd; color: #856404; }
  .meta { color: #666; font-size: 0.9em; }
</style>
</head>
<body>
<h1>ztunnel registry</h1>
${_endpoint ? `
<p>Status: <span class="status ${_endpoint.status}">${_endpoint.status}</span>
${stale ? ' <span class="status stale">stale</span>' : ''}</p>
<p>Endpoint: <code>${_endpoint.ip}:${_endpoint.port}</code></p>
<p class="meta">Last heartbeat: ${timeAgo(_endpoint.ts)}</p>
<p class="meta">nat_type_suspect: ${_endpoint.nat_type_suspect ? 'yes' : 'no'}</p>
` : `
<p>No endpoint registered yet.</p>
`}
</body></html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(html);
}
