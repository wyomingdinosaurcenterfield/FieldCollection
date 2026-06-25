const CACHE = 'wdc-v3';

self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE).then(c => c.add('index.html'))
  );
});

self.addEventListener('activate', e => {
  // Clean up old caches if version changes
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  e.respondWith(
    caches.match(e.request).then(cached => {
      // Serve from cache immediately; also try to update cache in background
      const network = fetch(e.request).then(response => {
        if (response.ok) {
          caches.open(CACHE).then(c => c.put(e.request, response.clone()));
        }
        return response;
      }).catch(() => cached);
      return cached || network;
    })
  );
});
