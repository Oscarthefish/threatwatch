/// <reference lib="webworker" />
import { cleanupOutdatedCaches, createHandlerBoundToURL, precacheAndRoute } from 'workbox-precaching'
import { NavigationRoute, registerRoute } from 'workbox-routing'
import { NetworkFirst } from 'workbox-strategies'
import { ExpirationPlugin } from 'workbox-expiration'

declare const self: ServiceWorkerGlobalScope & { __WB_MANIFEST: Array<{ url: string; revision: string | null }> }

cleanupOutdatedCaches()
precacheAndRoute(self.__WB_MANIFEST)
registerRoute(new NavigationRoute(createHandlerBoundToURL('/index.html'), { denylist: [/^\/api\//] }))

// Offline access: authenticated GET API responses are cached on this device
// (network first, 3s timeout). The cache is wiped on logout.
const API_CACHE = 'tw-api'
registerRoute(
  ({ url, request }) => request.method === 'GET' && url.pathname.startsWith('/api/') &&
    !url.pathname.startsWith('/api/auth/') && url.pathname !== '/api/health',
  new NetworkFirst({
    cacheName: API_CACHE,
    networkTimeoutSeconds: 3,
    plugins: [new ExpirationPlugin({ maxEntries: 400, maxAgeSeconds: 30 * 24 * 3600 })],
  }),
)

self.addEventListener('message', (event) => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting()
  if (event.data?.type === 'CLEAR_API_CACHE') event.waitUntil(caches.delete(API_CACHE))
})

self.addEventListener('push', (event) => {
  let data: { title?: string; body?: string; url?: string } = {}
  try { data = event.data?.json() ?? {} } catch { data = { title: 'Threat Watch', body: event.data?.text() } }
  event.waitUntil(self.registration.showNotification(data.title || 'Threat Watch', {
    body: data.body || '', icon: '/pwa-192.png', badge: '/badge-96.png', data: { url: data.url || '/' }, tag: data.url,
  }))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const url = (event.notification.data?.url as string) || '/'
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true })
    for (const c of all) { if ('focus' in c) { await (c as WindowClient).navigate(url); return (c as WindowClient).focus() } }
    return self.clients.openWindow(url)
  })())
})
