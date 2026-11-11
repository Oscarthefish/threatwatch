import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { Watch } from '../types'
import { Empty, ErrorBox, Loading, PageHeader, TimeAgo } from '../components/ui'
import { FollowSheet } from '../components/FollowSheet'
import { kindLabel, NOTIFY } from '../components/follow'

/** A followed subject: what it is, what is new, and whether anything needs a decision. */
export function WatchCard({ w }: { w: Watch }) {
  const fresh = w.unseen_count ?? 0
  const review = w.candidate_count ?? 0
  return (
    <Link to={`/watch/${w.id}`} className={`card watch-card ${fresh ? 'fresh' : ''}`}>
      <div className="eyebrow mb-0">{kindLabel(w.kind)}</div>
      <div className="row between top nowrap">
        <strong className="wc-title">{w.title}</strong>
        {fresh > 0 && <span className="sig meaningful nowrap">{fresh} new</span>}
      </div>
      {w.summary_excerpt && <p className="small muted clamp-2 mt-2 mb-2">{w.summary_excerpt.split('\n')[0]}</p>}
      <div className="row xsmall muted">
        <span>{w.evidence_count} report{w.evidence_count === 1 ? '' : 's'}</span>
        <span aria-hidden="true">·</span><span>updated <TimeAgo iso={w.last_updated_at} /></span>
        <span aria-hidden="true">·</span><span>notify: {NOTIFY.find(([v]) => v === w.notify_pref)?.[1].toLowerCase()}</span>
        {review > 0 && <span className="sig important">{review} to review</span>}
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
        actions={<button type="button" className="btn primary" onClick={() => setCreate(true)}>Follow something</button>} />
      <div className="seg mb-4" role="group" aria-label="Show">
        {['active', 'archived'].map((s) => <button key={s} type="button" aria-pressed={status === s} onClick={() => setStatus(s)}>{s === 'active' ? 'Active' : 'Archived'}</button>)}
      </div>
      {q.isError && <ErrorBox error={q.error} onRetry={() => q.refetch()} />}
      {!q.data ? <Loading lines={6} /> : q.data.length === 0 ? (
        <Empty title={status === 'active' ? 'You’re not following anything yet' : 'No archived watches'}>
          {status === 'active' && <>
            <p>Open any article and choose <strong>Follow</strong> to track an incident, CVE, actor or malware family as new reporting arrives.</p>
            <button type="button" className="btn primary" onClick={() => setCreate(true)}>Follow something</button>
          </>}
        </Empty>
      ) : <div className="watch-grid">{q.data.map((w) => <WatchCard key={w.id} w={w} />)}</div>}
      {create && <FollowSheet onClose={() => setCreate(false)} suggestions={[]} />}
    </>
  )
}
