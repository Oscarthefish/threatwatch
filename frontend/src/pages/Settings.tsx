import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { Source } from '../types'
import { ErrorBox, fmtDate, Loading, PageHeader, TimeAgo, useToast } from '../components/ui'
import { useTheme } from '../components/Layout'

interface Status {
  counts: Record<string, number>; db_bytes: number; last_ingest_at: string | null; worker_heartbeat: string | null
  ai: { enabled: boolean; model: string; spent_usd: number; budget_usd: number; requests: number; failures: number }
  ingest_interval_minutes: number; briefing_time: string; push_configured: boolean
  recent_jobs: { job: string; started_at: string; finished_at: string | null; status: string }[]
}

function b64ToUint8(b64: string) {
  const pad = '='.repeat((4 - (b64.length % 4)) % 4)
  const raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)))
}

export default function Settings({ onLogout }: { onLogout: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [theme, setTheme] = useTheme()
  const [pushState, setPushState] = useState<string | null>(null)
  const st = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 30_000 })
  const src = useQuery({ queryKey: ['sources'], queryFn: () => api.get<Source[]>('/api/sources') })
  const toggle = useMutation({ mutationFn: (s: Source) => api.patch(`/api/sources/${s.id}`, { enabled: !s.enabled }), onSuccess: () => qc.invalidateQueries({ queryKey: ['sources'] }) })
  const ingest = useMutation({ mutationFn: () => api.post<{ detail: string }>('/api/ingest'), onSuccess: (r) => toast(r.detail) })
  const brief = useMutation({ mutationFn: () => api.post('/api/briefing'), onSuccess: () => toast('Briefing will be regenerated within ~30 seconds') })

  async function logout() {
    try { await api.post('/api/auth/logout') } catch { /* ignore */ }
    navigator.serviceWorker?.controller?.postMessage({ type: 'CLEAR_API_CACHE' })
    qc.clear(); onLogout()
  }

  async function enablePush() {
    try {
      const k = await api.get<{ public_key: string | null; enabled: boolean }>('/api/push/key')
      if (!k.enabled || !k.public_key) { setPushState('Web push is not configured on the server (VAPID keys missing).'); return }
      if (!('serviceWorker' in navigator) || !('PushManager' in window)) { setPushState('This browser does not support web push.'); return }
      const perm = await Notification.requestPermission()
      if (perm !== 'granted') { setPushState('Notification permission was not granted.'); return }
      const reg = await navigator.serviceWorker.ready
      const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToUint8(k.public_key) })
      await api.post('/api/push/subscribe', sub.toJSON())
      setPushState('Push notifications enabled on this device.')
    } catch (e) { setPushState(`Could not enable push: ${(e as Error).message}`) }
  }

  const s = st.data
  return (
    <>
      <PageHeader title="Settings & sources" actions={<button className="btn" onClick={logout}>Sign out</button>} />
      <section className="card">
        <h2>Appearance</h2>
        <div className="chips" role="radiogroup" aria-label="Theme">{['system', 'light', 'dark'].map((t) => <button key={t} role="radio" aria-checked={theme === t} className={`chip ${theme === t ? 'on' : ''}`} onClick={() => setTheme(t)}>{t}</button>)}</div>
      </section>
      <section className="card">
        <h2>Collection & briefing</h2>
        {st.isError ? <ErrorBox error={st.error} /> : !s ? <Loading /> : <dl className="kv">
          <dt>Last collection</dt><dd><TimeAgo iso={s.last_ingest_at} /> (every {s.ingest_interval_minutes} min)</dd>
          <dt>Worker</dt><dd>{s.worker_heartbeat && Date.now() - new Date(s.worker_heartbeat).getTime() < 180_000 ? <span style={{ color: 'var(--ok)' }}>running</span> : <span className="error">not seen recently</span>} · heartbeat <TimeAgo iso={s.worker_heartbeat} /></dd>
          <dt>Daily briefing</dt><dd>{s.briefing_time}</dd>
          <dt>Data</dt><dd>{s.counts.articles} articles · {s.counts.vulnerabilities} CVEs · {s.counts.watches} watches · {s.counts.bookmarks} bookmarks · {(s.db_bytes / 1e6).toFixed(1)} MB</dd>
          <dt>AI provider</dt><dd>{s.ai.enabled ? <>{s.ai.model} · today ${s.ai.spent_usd.toFixed(3)} of ${s.ai.budget_usd.toFixed(2)} budget · {s.ai.requests} requests{s.ai.failures ? `, ${s.ai.failures} failed` : ''}</> : 'Not configured — collection, browsing, search, bookmarks and following all work without it.'}</dd>
          <dt>Web push</dt><dd>{s.push_configured ? 'Configured' : 'Not configured'}</dd>
        </dl>}
        <div className="row" style={{ marginTop: '.75rem' }}>
          <button className="btn" onClick={() => ingest.mutate()} disabled={ingest.isPending}>Refresh sources now</button>
          <button className="btn" onClick={() => brief.mutate()} disabled={brief.isPending}>Regenerate briefing</button>
          <button className="btn" onClick={enablePush}>Enable push on this device</button>
        </div>
        {pushState && <p className="small muted" style={{ marginTop: '.5rem' }}>{pushState}</p>}
      </section>
      <section className="card">
        <h2>Sources</h2>
        {src.isError ? <ErrorBox error={src.error} /> : !src.data ? <Loading /> : <div className="table-wrap"><table className="simple">
          <thead><tr><th>Source</th><th>Status</th><th>Last success</th><th>Articles</th><th>On</th></tr></thead>
          <tbody>{src.data.map((x) => <tr key={x.id}>
            <td><a href={x.homepage} target="_blank" rel="noopener noreferrer">{x.name}</a><div className="small faint">{x.kind} · every {x.interval_minutes} min{x.region !== 'GLOBAL' ? ` · ${x.region}` : ''}</div></td>
            <td>{x.last_status === 'error' ? <span className="error" title={x.last_error ?? ''}>error ({x.consecutive_failures})</span> : x.last_status ?? '—'}</td>
            <td className="small" title={fmtDate(x.last_success_at)}><TimeAgo iso={x.last_success_at} /></td>
            <td>{x.article_count || (x.kind === 'rss' || x.kind === 'ncsc_nz_html' ? 0 : '—')}</td>
            <td><input type="checkbox" aria-label={`Enable ${x.name}`} checked={x.enabled} onChange={() => toggle.mutate(x)} /></td>
          </tr>)}</tbody></table></div>}
        <p className="small faint" style={{ marginTop: '.5rem' }}>Sources are retrieved via published RSS/Atom feeds and APIs (CISA KEV JSON, FIRST EPSS API, CVE.org API). NCSC NZ publishes no feed; its public alerts page is read politely once per hour.</p>
      </section>
    </>
  )
}
