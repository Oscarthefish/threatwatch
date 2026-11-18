import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { Notification } from '../types'
import { Empty, ErrorBox, Loading, PageHeader } from '../components/ui'

const KIND: Record<string, string> = {
  watch_important: 'Important update', watch_update: 'New finding', digest: 'Daily digest', briefing: 'Briefing', system: 'System', ransom_claim: 'Ransomware claim, New Zealand',
}

function dayLabel(iso: string) {
  const tz = 'Pacific/Auckland'
  const fmt = (d: Date) => d.toLocaleDateString('en-NZ', { timeZone: tz })
  const d = new Date(iso)
  if (fmt(d) === fmt(new Date())) return 'Today'
  if (fmt(d) === fmt(new Date(Date.now() - 86400_000))) return 'Yesterday'
  return d.toLocaleDateString('en-NZ', { weekday: 'long', day: 'numeric', month: 'long', timeZone: tz })
}

export default function Notifications() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['notifications'], queryFn: () => api.get<{ items: Notification[]; unread: number }>('/api/notifications') })
  const read = useMutation({
    mutationFn: (b: { ids?: number[]; all?: boolean }) => api.post('/api/notifications/read', b),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['notifications'] }); qc.invalidateQueries({ queryKey: ['me'] }) },
  })
  const groups: [string, Notification[]][] = []
  for (const n of q.data?.items ?? []) {
    const label = dayLabel(n.created_at)
    const g = groups.find(([l]) => l === label)
    if (g) g[1].push(n); else groups.push([label, [n]])
  }

  return (
    <>
      <PageHeader title="Notifications" eyebrow={['Yours']}
        sub={q.data ? (q.data.unread ? `${q.data.unread} unread.` : 'All caught up.') : undefined}
        actions={!!q.data?.unread && <button type="button" className="btn" aria-busy={read.isPending || undefined} onClick={() => read.mutate({ all: true })}>Mark all read</button>} />
      {q.isError ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Loading /> : q.data.items.length === 0 ? (
        <Empty title="No notifications">
          <p>You will be notified here about followed items, according to each one's notification setting, and when the daily briefing is ready.</p>
          <Link className="btn" to="/watch">Manage what you follow</Link>
        </Empty>
      ) : groups.map(([label, items]) => (
        <section key={label} aria-label={label}>
          <h2 className="day-head">{label}</h2>
          <ul className="nlist">
            {items.map((n) => {
              const inner = <>
                <span className="ndot" aria-hidden="true" />
                <span><span className="xsmall muted">{KIND[n.kind] ?? n.kind}{!n.read_at && <span className="sr-only">, unread</span>}</span><br /><span className="ntitle">{n.title}</span></span>
                <time dateTime={n.created_at}>{new Date(n.created_at).toLocaleTimeString('en-NZ', { hour: 'numeric', minute: '2-digit', timeZone: 'Pacific/Auckland' })}</time>
                {n.body && <span className="nmsg">{n.body}</span>}
              </>
              return (
                <li key={n.id} data-nav className={`nitem ${n.read_at ? '' : 'unread'}`}>
                  {n.link ? <Link to={n.link} onClick={() => { if (!n.read_at) read.mutate({ ids: [n.id] }) }}>{inner}</Link> : <div className="nbody">{inner}</div>}
                </li>
              )
            })}
          </ul>
        </section>
      ))}
    </>
  )
}
