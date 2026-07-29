// Cloudflare Worker: NAT SW Landing
// Update BACKEND_URL and _config and redeploy when port changes
const BACKEND_URL = "https://test.cicuvc.top:5917";
const CONFIG = BACKEND_URL;

const HTML = `
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NAT SW</title>
<style>body{font-family:system-ui;max-width:640px;margin:60px auto;padding:20px;background:#111;color:#eee}h1{color:#0f0}pre{background:#222;padding:15px;border-radius:8px}</style></head><body>
<h1>NAT Traversal via Service Worker</h1>
<pre id="status">Loading...</pre>
<script>
function log(m){document.getElementById('status').innerHTML+=m+'\\n';}
fetch('/_config').then(r=>r.text()).then(u=>{
  log('Backend: '+u);
  if('serviceWorker' in navigator){
    navigator.serviceWorker.register('/sw.js',{scope:'/'})
      .then(r=>{
        log('SW registered');
        // Also send via postMessage for immediate update
        setTimeout(()=>{
          const sw=r.active||r.installing||r.waiting;
          if(sw)sw.postMessage({type:'update-backend',url:u});
        },100);
      }).catch(e=>log('SW err: '+e));
  }else{log('SW not supported');}
}).catch(e=>log('Config err: '+e));
</script></body></html>`;

const SW_JS = `
let U=null;

// Fetch backend URL from config endpoint on install
self.addEventListener('install',e=>{
  self.skipWaiting();
  e.waitUntil(
    fetch('/_config').then(r=>r.text()).then(u=>{U=u;})
  );
});

self.addEventListener('activate',e=>{e.waitUntil(clients.claim());});

self.addEventListener('message',e=>{
  if(e.data?.type==='update-backend'&&e.data.url){U=e.data.url;}
});

self.addEventListener('fetch',e=>{
  let u=new URL(e.request.url);
  if(u.hostname!==self.location.hostname)return;
  if(u.pathname==='/sw.js'||u.pathname==='/_config')return;
  if(!U){console.log('[SW] no backend yet');return;}
  let t=U+u.pathname+u.search;
  console.log('[SW] -> '+t);
  e.respondWith(fetch(t).catch(err=>new Response('Backend unreachable',{status:502})));
});
`;

addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.pathname === '/_config') {
    event.respondWith(new Response(CONFIG, {
      headers: {'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*'}
    }));
  } else if (url.pathname === '/sw.js') {
    event.respondWith(new Response(SW_JS, {
      headers: {'Content-Type': 'application/javascript'}
    }));
  } else {
    event.respondWith(new Response(HTML, {
      headers: {'Content-Type': 'text/html; charset=utf-8'}
    }));
  }
});
