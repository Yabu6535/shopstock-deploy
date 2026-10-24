// ShopStock Offline POS Service Worker
// Strategy:
// - `/api/media/*`: Cache-first (content-addressed immutable signatures & receipts)
// - `/api/*` (all other API routes): Network-only (handled by ShopCloud IndexedDB + Outbox)
// - App Shell (`/`, `/index.html`, `/manifest.webmanifest`): Network-first with Cache fallback
//   so deployments update immediately when online, yet branches can still open/reload POS offline.

const SHELL_CACHE = 'shopstock-shell-v5';
const MEDIA_CACHE = 'shopstock-media-v1';
const SHELL_ASSETS = ['/', '/index.html', '/manifest.webmanifest'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_ASSETS))
      .catch(() => {})
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k !== SHELL_CACHE && k !== MEDIA_CACHE)
            .map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Content-addressed immutable media (`/api/media/med_...`)
  if (url.pathname.startsWith('/api/media/')) {
    event.respondWith(
      caches.open(MEDIA_CACHE).then(async (cache) => {
        const hit = await cache.match(req);
        if (hit) return hit;
        const res = await fetch(req);
        if (res.ok) cache.put(req, res.clone());
        return res;
      })
    );
    return;
  }

  // Never cache dynamic API endpoints
  if (url.pathname.startsWith('/api/')) return;

  // Navigation & static shell: Network-first so deploys apply immediately, fallback to cache offline
  event.respondWith(
    (async () => {
      try {
        const res = await fetch(req);
        if (res.ok) {
          const cache = await caches.open(SHELL_CACHE);
          cache.put(req, res.clone());
          if (req.mode === 'navigate') {
            cache.put('/', res.clone());
          }
        }
        return res;
      } catch {
        const cache = await caches.open(SHELL_CACHE);
        const cached =
          (await cache.match(req)) ||
          (req.mode === 'navigate' ? (await cache.match('/')) || (await cache.match('/index.html')) : null);
        return cached || new Response('Offline — open ShopStock once online to cache POS shell.', { status: 503 });
      }
    })()
  );
});
