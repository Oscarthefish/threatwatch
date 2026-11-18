import { useEffect, useState } from 'react'
import { usePageTitle } from './ui'

/** Shown when the server cannot be contacted at start-up. The session is kept, so nothing needs re-entering. */
export function Unreachable({ onRetry }: { onRetry: () => void }) {
  usePageTitle('Cannot reach Threat Watch')
  const [tries, setTries] = useState(0)

  useEffect(() => {
    const retry = () => { setTries((n) => n + 1); onRetry() }
    const onVisible = () => { if (document.visibilityState === 'visible') retry() }
    // Coming back to the app (for example after turning Tailscale on) or regaining a connection retries at once.
    document.addEventListener('visibilitychange', onVisible)
    window.addEventListener('online', retry)
    const t = window.setInterval(retry, 20_000)
    return () => { document.removeEventListener('visibilitychange', onVisible); window.removeEventListener('online', retry); window.clearInterval(t) }
  }, [onRetry])

  return (
    <main className="login">
      <section className="card" aria-labelledby="unreach-h">
        <div className="row nowrap mb-3"><img src="/pwa-192.png" alt="" width={32} height={32} className="logo" /><span className="auth-name">Threat Watch</span></div>
        <h1 id="unreach-h">Cannot reach Threat Watch</h1>
        <p>The app could not contact the server. Your sign-in is kept on this device, so there is nothing to re-enter.</p>
        <p className="small muted">On your phone, check that Tailscale is connected, then come back here. Threat Watch tries again by itself every 20 seconds and whenever you return to the app.</p>
        <button type="button" className="btn primary block" onClick={() => { setTries((n) => n + 1); onRetry() }}>Try again</button>
        <p className="xsmall muted mt-3 mb-0" aria-live="polite">{tries > 0 ? `Tried ${tries} ${tries === 1 ? 'time' : 'times'}; still no answer.` : ' '}</p>
      </section>
    </main>
  )
}
