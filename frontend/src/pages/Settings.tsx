import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { Source } from '../types'
import { ErrorBox, Loading, PageHeader, TimeAgo, useToast } from '../components/ui'
import { useTheme } from '../components/Layout'
import { useStartTour } from '../components/Tour'

interface Status {
  counts: Record<string, number>; db_bytes: number; last_ingest_at: string | null; worker_heartbeat: string | null
  ai: { enabled: boolean; model: string; spent_usd: number; budget_usd: number; requests: number; failures: number }
  ingest_interval_minutes: number; briefing_time: string; push_configured: boolean; retention_days: number; timezone: string
  sources: { total: number; failing: string[] }
}

const KIND: Record<string, string> = {
  rss: 'RSS / Atom feed', ncsc_nz_html: 'Public alerts page', kev: 'CISA KEV catalogue (JSON)', epss: 'FIRST EPSS API', cve_enrich: 'CVE.org API',
}
const DATA_KINDS = new Set(['kev', 'epss', 'cve_enrich'])

function b64ToUint8(b64: string) {
  const pad = '='.repeat((4 - (b64.length % 4)) % 4)
  const raw = atob((b64 + pad).replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)))
}

function SourceRow({ x, onToggle }: { x: Source; onToggle: () => void }) {
  const bad = x.last_status === 'error'
  const state = !x.enabled ? 'off' : bad ? 'bad' : x.last_success_at ? 'ok' : 'wait'
  const label = { off: 'Paused', bad: `Failing (${x.consecutive_failures} in a row)`, ok: 'Collecting', wait: 'Waiting for first run' }[state]
  return (
    <li className={`srow ${state}`}>
      <div className="grow">
        <div className="row nowrap between top">
          <a className="strong" href={x.homepage} target="_blank" rel="noopener noreferrer">{x.name}</a>
          <label className="switch">
            <input type="checkbox" checked={x.enabled} onChange={onToggle} aria-label={`Collect from ${x.name}`} />
            <span aria-hidden="true" />
          </label>
        </div>
        <div className="xsmall muted">{KIND[x.kind] ?? x.kind} · every {x.interval_minutes} min{x.region !== 'GLOBAL' ? ` · ${x.region}` : ''}</div>
        <div className="row xsmall mt-2">
          <span className={`spill ${state}`}><i aria-hidden="true" />{label}</span>
          {x.last_success_at && <span className="muted">last success <TimeAgo iso={x.last_success_at} /></span>}
          {!DATA_KINDS.has(x.kind) && <span className="muted">{x.article_count.toLocaleString()} report{x.article_count === 1 ? '' : 's'}</span>}
        </div>
        {bad && x.last_error && <p className="xsmall error mt-2 mb-0 wrap-any">{x.last_error}</p>}
      </div>
    </li>
  )
}

export default function Settings({ onLogout }: { onLogout: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [theme, setTheme] = useTheme()
  const startTour = useStartTour()
  const [pushState, setPushState] = useState<string | null>(null)
  const me = useQuery({ queryKey: ['me'], queryFn: () => api.get<{ username: string }>('/api/auth/me') })
  const st = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 30_000 })
  const src = useQuery({ queryKey: ['sources'], queryFn: () => api.get<Source[]>('/api/sources') })
  const toggle = useMutation({
    mutationFn: (s: Source) => api.patch(`/api/sources/${s.id}`, { enabled: !s.enabled }),
    onSuccess: (_d, s) => { toast(s.enabled ? `${s.name} paused` : `${s.name} resumed`); qc.invalidateQueries({ queryKey: ['sources'] }) },
  })
  const ingest = useMutation({ mutationFn: () => api.post<{ detail: string }>('/api/ingest'), onSuccess: () => toast('Collection starts within 30 seconds.') })
  const brief = useMutation({ mutationFn: () => api.post('/api/briefing'), onSuccess: () => toast('A new briefing will be ready within a minute.') })

  async function logout() {
    try { await api.post('/api/auth/logout') } catch { /* already signed out */ }
    navigator.serviceWorker?.controller?.postMessage({ type: 'CLEAR_API_CACHE' })
    qc.clear(); onLogout()
  }

  async function enablePush() {
    try {
      const k = await api.get<{ public_key: string | null; enabled: boolean }>('/api/push/key')
      if (!k.enabled || !k.public_key) { setPushState('Push is not set up on this server yet. It needs the HTTPS deployment and VAPID keys (see the deployment guide).'); return }
      if (!('serviceWorker' in navigator) || !('PushManager' in window)) { setPushState('This browser does not support push notifications.'); return }
      const perm = await Notification.requestPermission()
      if (perm !== 'granted') { setPushState('Notifications were not allowed. You can change this in the browser’s site settings.'); return }
      const reg = await navigator.serviceWorker.ready
      const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64ToUint8(k.public_key) })
      await api.post('/api/push/subscribe', sub.toJSON())
      setPushState('Push notifications are on for this device.')
    } catch (e) { setPushState(`Push could not be enabled: ${(e as Error).message}`) }
  }

  const s = st.data
  const workerOk = !!s?.worker_heartbeat && Date.now() - new Date(s.worker_heartbeat).getTime() < 180_000
  const feeds = (src.data ?? []).filter((x) => !DATA_KINDS.has(x.kind))
  const data = (src.data ?? []).filter((x) => DATA_KINDS.has(x.kind))
  const budgetPct = s?.ai.enabled ? Math.min(100, (s.ai.spent_usd / Math.max(s.ai.budget_usd, 0.01)) * 100) : 0

  return (
    <>
      <PageHeader title="Settings" eyebrow={['Settings']} sub="Collection health, sources, AI and this device." />
      <div className="settings-grid">
        <div className="stack">
          <section className="panel" aria-labelledby="col-h">
            <header><h2 id="col-h">Collection</h2>
              <span className={`spill ${!s ? 'wait' : workerOk ? (s.sources.failing.length ? 'bad' : 'ok') : 'bad'}`}><i aria-hidden="true" />{!s ? 'Checking' : workerOk ? 'Running' : 'Collector stopped'}</span>
            </header>
            <div className="body">
              {st.isError ? <ErrorBox error={st.error} onRetry={() => st.refetch()} /> : !s ? <Loading lines={3} /> : <>
                <dl className="kv mb-3">
                  <dt>Last run</dt><dd><TimeAgo iso={s.last_ingest_at} /> <span className="muted">· every {s.ingest_interval_minutes} minutes</span></dd>
                  <dt>Sources</dt><dd>{s.sources.total - s.sources.failing.length} of {s.sources.total} healthy{s.sources.failing.length ? <span className="error">. Failing: {s.sources.failing.join(', ')}</span> : ''}</dd>
                  <dt>Daily briefing</dt><dd>{s.briefing_time.replace('Pacific/Auckland', 'NZ time')}</dd>
                  {!workerOk && <><dt>Collector</dt><dd className="error">{s.worker_heartbeat ? <>Last heartbeat <TimeAgo iso={s.worker_heartbeat} />.</> : 'No heartbeat recorded.'} Check the worker container with <code>deploy/local.sh status</code>.</dd></>}
                </dl>
                <div className="row">
                  <button type="button" className="btn" aria-busy={ingest.isPending || undefined} onClick={() => ingest.mutate()}>Collect now</button>
                  <button type="button" className="btn" aria-busy={brief.isPending || undefined} onClick={() => brief.mutate()}>Rebuild today’s briefing</button>
                </div>
              </>}
            </div>
          </section>

          <section className="panel" aria-labelledby="src-h">
            <header><h2 id="src-h">Sources</h2><span className="xsmall muted">{feeds.length} reporting · {data.length} vulnerability data</span></header>
            <div className="body">
              {src.isError ? <ErrorBox error={src.error} onRetry={() => src.refetch()} /> : !src.data ? <Loading lines={6} /> : <>
                <h3 className="day-head">Reporting</h3>
                <ul className="slist">{feeds.map((x) => <SourceRow key={x.id} x={x} onToggle={() => toggle.mutate(x)} />)}</ul>
                <h3 className="day-head">Vulnerability data</h3>
                <ul className="slist">{data.map((x) => <SourceRow key={x.id} x={x} onToggle={() => toggle.mutate(x)} />)}</ul>
                <p className="xsmall muted mt-3 mb-0">Retrieved only through published feeds and APIs. NCSC NZ has no feed, so its public alerts page is read once an hour.</p>
              </>}
            </div>
          </section>
        </div>

        <div className="stack">
          <section className="panel" aria-labelledby="acc-h">
            <header><h2 id="acc-h">Account</h2></header>
            <div className="body">
              <dl className="kv mb-3"><dt>Signed in as</dt><dd className="strong">{me.data?.username ?? '…'}</dd></dl>
              <button type="button" className="btn" onClick={logout}>Sign out</button>
              <p className="xsmall muted mt-3 mb-0">Signing out also clears pages saved on this device for offline reading. To change the password, run <code>deploy/local.sh password</code> on the host; it signs out every session.</p>
            </div>
          </section>

          <section className="panel" aria-labelledby="tour-sh">
            <header><h2 id="tour-sh">Guided tour</h2></header>
            <div className="body">
              <p className="small muted">A step-by-step walk through every section: what each part shows and how to use it. About three minutes.</p>
              <button type="button" className="btn" onClick={startTour}>Take the tour</button>
            </div>
          </section>

          <section className="panel" aria-labelledby="look-h">
            <header><h2 id="look-h">Appearance</h2></header>
            <div className="body">
              <div className="seg" role="group" aria-label="Theme">
                {[['system', 'Match device'], ['light', 'Light'], ['dark', 'Dark']].map(([t, l]) => (
                  <button key={t} type="button" aria-pressed={theme === t} onClick={() => setTheme(t)}>{l}</button>
                ))}
              </div>
            </div>
          </section>

          <section className="panel" aria-labelledby="ai-h">
            <header><h2 id="ai-h">AI summaries</h2><span className={`spill ${s?.ai.enabled ? 'ok' : 'off'}`}><i aria-hidden="true" />{s?.ai.enabled ? 'On' : 'Off'}</span></header>
            <div className="body">
              {!s ? <Loading lines={2} /> : s.ai.enabled ? <>
                <dl className="kv mb-2">
                  <dt>Model</dt><dd className="mono">{s.ai.model}</dd>
                  <dt>Today</dt><dd>${s.ai.spent_usd.toFixed(2)} of ${s.ai.budget_usd.toFixed(2)} · {s.ai.requests} request{s.ai.requests === 1 ? '' : 's'}{s.ai.failures ? `, ${s.ai.failures} failed` : ''}</dd>
                </dl>
                <div className="meter" role="meter" aria-label="Daily AI budget used" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(budgetPct)}><i style={{ width: `${budgetPct}%` }} /></div>
              </> : (
                <p className="small muted mb-0">Everything except written summaries works without AI. To turn it on, add <code>ANTHROPIC_API_KEY</code> to <code>~/.config/threatwatch/threatwatch.env</code> and run <code>deploy/local.sh up</code>.</p>
              )}
            </div>
          </section>

          <section className="panel" aria-labelledby="dev-h">
            <header><h2 id="dev-h">This device</h2></header>
            <div className="body">
              <p className="small muted">Push notifications for followed items. Requires the HTTPS deployment.</p>
              <button type="button" className="btn" onClick={enablePush}>Turn on push notifications</button>
              {pushState && <p className="small mt-2 mb-0" role="status">{pushState}</p>}
            </div>
          </section>

          <section className="panel" aria-labelledby="data-h">
            <header><h2 id="data-h">Data</h2></header>
            <div className="body">
              {!s ? <Loading lines={3} /> : (
                <dl className="kv">
                  <dt>Reports</dt><dd>{s.counts.articles.toLocaleString()}</dd>
                  <dt>CVEs</dt><dd>{s.counts.vulnerabilities.toLocaleString()}</dd>
                  <dt>Following</dt><dd>{s.counts.watches}</dd>
                  <dt>Bookmarks</dt><dd>{s.counts.bookmarks}</dd>
                  <dt>Database</dt><dd>{(s.db_bytes / 1e6).toFixed(1)} MB</dd>
                  <dt>Kept for</dt><dd>{s.retention_days} days (bookmarked and followed reports are kept)</dd>
                  <dt>Backup</dt><dd><code>deploy/local.sh backup</code></dd>
                </dl>
              )}
              <p className="xsmall faint mt-3 mb-0">Times are shown in {s?.timezone ?? 'Pacific/Auckland'}.</p>
            </div>
          </section>
        </div>
      </div>
    </>
  )
}
