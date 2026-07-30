// ztunnel service worker: forwards same-origin requests to the punched
// NAT backend, injecting the X-ZT-Gate header so the host gate lets the
// traffic through.  The gate token is public (fetched from
// /api?cmd=web-config) — it hides the port from scanners, nothing more.

const CONFIG_URL = '/api?cmd=web-config';
const TOKEN_MAX_AGE_MS = 20000; // server token valid ~60s; refresh early

let cfg = null;        // { url, window, gate }
let cfgFetchedAt = 0;  // ms epoch

async function refreshConfig() {
  const r = await fetch(CONFIG_URL, { cache: 'no-store' });
  if (!r.ok) throw new Error('web-config: ' + r.status);
  cfg = await r.json();
  cfgFetchedAt = Date.now();
}

async function getConfig() {
  if (!cfg || Date.now() - cfgFetchedAt > TOKEN_MAX_AGE_MS) {
    await refreshConfig();
  }
  return cfg;
}

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(refreshConfig().catch(() => {}));
});

self.addEventListener('activate', e => {
  e.waitUntil(clients.claim());
});

self.addEventListener('message', e => {
  if (e.data?.type === 'refresh-config') {
    e.waitUntil(refreshConfig().catch(() => {}));
  }
});

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin) return;
  if (u.pathname === '/sw.js' || u.pathname.startsWith('/api')) return;
  if (u.search.includes('bootstrap')) return; // landing page escape hatch
  e.respondWith(proxy(e.request));
});

async function proxy(req) {
  let c;
  try {
    c = await getConfig();
  } catch (err) {
    return bootstrapPage('Backend config unavailable: ' + err.message);
  }

  const u = new URL(req.url);
  const headers = new Headers(req.headers);
  headers.set('X-ZT-Gate', c.window + ' ' + c.gate);

  try {
    return await fetch(c.url + u.pathname + u.search, {
      method: req.method,
      headers,
      body: req.body,
      duplex: 'half',
      redirect: 'manual',
      credentials: 'omit',
    });
  } catch (err) {
    // Backend moved (repunch) or token stale — drop cached config so the
    // next request re-fetches, and tell the page to retry.
    cfg = null;
    return bootstrapPage('Backend unreachable (may be re-punching). Retry in a few seconds.');
  }
}

function bootstrapPage(msg) {
  const html = '<!DOCTYPE html><html><body style="font-family:system-ui;background:#111;color:#eee;max-width:640px;margin:60px auto;padding:20px">'
    + '<h1 style="color:#f80">ztunnel</h1><p>' + msg + '</p>'
    + '<p><a style="color:#6cf" href="javascript:location.reload()">重试</a> · '
    + '<a style="color:#6cf" href="/?bootstrap=1">重新引导</a></p></body></html>';
  return new Response(html, { status: 502, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
