import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { Notification } from '../types'
import { Empty, ErrorBox, Loading, PageHeader, TimeAgo } from '../components/ui'

export default function Notifications() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const q = useQuery({ queryKey: ['notifications'], queryFn: () => api.get<{ items: Notification[]; unread: number }>('/api/notifications') })
  const read = useMutation({ mutationFn: (b: { ids?: number[]; all?: boolean }) => api.post('/api/notifications/read', b), onSuccess: () => { qc.invalidateQueries({ queryKey: ['notifications'] }); qc.invalidateQueries({ queryKey: ['me'] }) } })
  if (q.isError) return <ErrorBox error={q.error} />
  if (!q.data) return <Loading />
  return (
    <>
      <PageHeader title="Notifications" sub={`${q.data.unread} unread`} actions={q.data.unread > 0 && <button className="btn" onClick={() => read.mutate({ all: true })}>Mark all read</button>} />
      {q.data.items.length === 0 ? <Empty title="No notifications">Followed threats notify you here according to each watch’s preference.</Empty> : (
        <div className="stack">{q.data.items.map((n) => (
          <button key={n.id} className="card" style={{ display: 'block', width: '100%', textAlign: 'left', cursor: 'pointer', opacity: n.read_at ? .7 : 1 }}
            onClick={() => { if (!n.read_at) read.mutate({ ids: [n.id] }); if (n.link) nav(n.link) }}>
            <div className="row">{!n.read_at && <span className="badge" aria-label="unread"> </span>}<span className={`sig ${n.kind === 'watch_important' ? 'important' : 'meaningful'}`}>{n.kind.replace('_', ' ')}</span>
              <strong className="grow">{n.title}</strong><span className="small faint"><TimeAgo iso={n.created_at} /></span></div>
            {n.body && <p className="small muted" style={{ whiteSpace: 'pre-wrap', margin: '.35rem 0 0' }}>{n.body}</p>}
          </button>))}</div>
      )}
    </>
  )
}
