import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { ApiError } from './api'
import App from './App'
import { ToastProvider } from './components/ui'
import { ConfirmProvider } from './components/Sheet'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      gcTime: 24 * 3600_000,
      retry: (n, err) => !(err instanceof ApiError && [401, 403, 404].includes(err.status)) && n < 2,
      refetchOnWindowFocus: true,
    },
  },
})

if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).then((reg) => {
      reg.addEventListener('updatefound', () => {
        const nw = reg.installing
        nw?.addEventListener('statechange', () => {
          if (nw.state === 'installed' && navigator.serviceWorker.controller) nw.postMessage({ type: 'SKIP_WAITING' })
        })
      })
    }).catch(() => { /* SW unavailable (e.g. http on non-localhost) */ })
    let reloaded = false
    navigator.serviceWorker.addEventListener('controllerchange', () => { if (!reloaded) { reloaded = true; window.location.reload() } })
  })
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ToastProvider>
          <ConfirmProvider>
            <App />
          </ConfirmProvider>
        </ToastProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
