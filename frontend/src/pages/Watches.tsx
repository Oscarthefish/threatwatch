import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { Watch } from '../types'
import { Empty, ErrorBox, Loading, PageHeader, TimeAgo } from '../components/ui'
import { FollowSheet } from '../components/FollowSheet'

const PREF: Record<string, string> = { important: 'Important only', all: 'All findings', digest: 'Daily digest', silent: 'Silent' }

export function WatchCard({ w }: { w: Watch }) {
  return (
    <Link to={`/watch/${w.id}`} className="card" style={{ display: 'block', color: 'inherit', textDecoration: 'none' }}>
      <div className="row">
        <span className="chip">{w.kind}</span>
        <strong className="grow">{w.title}</strong>
        {(w.unseen_count ?? 0) > 0 && <span className="badge" title="New evidence since you last viewed">{w.unseen_count}</span>}
      </div>
      {w.summary_excerpt && <p className="small muted" style={{ margin: '.4rem 0' }}>{w.summary_excerpt.split('\n')[0]}</p>}
      <div className="row small faint">
        <span>{w.evidence_count} report{w.evidence_count === 1 ? '' : 's'}</span>
        {(w.candidate_count ?? 0) > 0 && <span className="sig meaningful">{w.candidate_count} to review</span>}
        <span>· {PREF[w.notify_pref]}</span>
        <span>· updated <TimeAgo iso={w.last_updated_at} /></span>
        <span>· checked <TimeAgo iso={w.last_checked_at} /></span>
      </div>
    </Link>
  )
}

export default function Watches() {
  const [status, setStatus] = useState('active')
  const [create, setCreate] = useState(false)
  const q = useQuery({ queryKey: ['watches', status], queryFn: () => api.get<Watch[]>(`/api/watches?status=${status}`) })
  return (
    <>
      <PageHeader title="Following" eyebrow={['Yours']} sub="Incidents, vulnerabilities, actors and topics you track. Each keeps a versioned record that updates as new reporting arrives."
        actions={<button className="btn primary" onClick={() => setCreate(true)}>Follow something</button>} />
      <div className="tabs" role="tablist">
        {['active', 'archived'].map((s) => <button key={s} role="tab" aria-selected={status === s} className={status === s ? 'active' : ''} onClick={() => setStatus(s)}>{s === 'active' ? 'Following' : 'Archived'}</button>)}
      </div>
      {q.isError && <ErrorBox error={q.error} />}
      {!q.data ? <Loading lines={6} /> : q.data.length === 0 ? (
        <Empty title={status === 'active' ? 'You’re not following anything yet' : 'No archived watches'}>
          {status === 'active' && <p>Open any article and tap <strong>Follow</strong> to track an evolving incident, CVE, actor or malware family — or create a watch directly.</p>}
        </Empty>
      ) : <div className="stack">{q.data.map((w) => <WatchCard key={w.id} w={w} />)}</div>}
      {create && <FollowSheet onClose={() => setCreate(false)} suggestions={[{ kind: 'topic', title: '', identifiers: [], aliases: [], context_terms: [], existing_watch_id: null }]} />}
    </>
  )
}
