import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { Today as TodayT } from '../types'
import { ArticleCard, ArticleList, Empty, ErrorBox, fmtDate, Loading, PageHeader, Severity, TimeAgo } from '../components/ui'

export default function Today() {
  const q = useQuery({ queryKey: ['today'], queryFn: () => api.get<TodayT>('/api/today'), refetchInterval: 300_000 })
  useEffect(() => {
    // Mark the visit after the user has had a chance to see "since last visit".
    const t = window.setTimeout(() => { api.post('/api/visit').catch(() => {}) }, 15_000)
    return () => window.clearTimeout(t)
  }, [])
  if (q.isError) return <ErrorBox error={q.error} />
  if (!q.data) return <Loading lines={8} />
  const d = q.data
  const b = d.briefing
  return (
    <>
      <PageHeader title="Today" sub={<>Last collection <TimeAgo iso={d.last_ingest_at} />{d.last_visit_at && <> · last visit <TimeAgo iso={d.last_visit_at} /></>}</>} />

      <section className="card" aria-labelledby="brief-h">
        <div className="row between">
          <h2 id="brief-h" style={{ margin: 0 }}>Daily briefing</h2>
          {b && <span className="small faint">{b.date} · generated {fmtDate(b.generated_at)}</span>}
        </div>
        {!b && <Empty title="No briefing yet">The first briefing is generated after initial collection, then daily at 7:00 AM NZ time.</Empty>}
        {b && <>
          <div className={`notice ${b.method === 'ai' ? 'ai' : ''}`} style={{ margin: '.6rem 0' }}>
            {b.method === 'ai'
              ? <>AI-generated synthesis ({b.model}). Every item links to its source evidence — verify before acting.</>
              : <>Ranked from source reporting (AI synthesis not configured). Summaries are the publishers’ own text{d.ai_enabled ? '' : ''}.</>}
          </div>
          {b.headline && <p style={{ fontWeight: 600 }}>{b.headline}</p>}
          {b.items.map((it, i) => (
            <div key={i} className="brief-item">
              <div className="row"><Severity level={it.priority} /><strong className="grow">{it.title}</strong></div>
              <p style={{ margin: '.35rem 0' }}>{it.summary}</p>
              {it.why_it_matters && <p className="why"><strong>Why it matters: </strong>{it.why_it_matters}</p>}
              <div className="chips">{(it.sources ?? []).map((s) => <Link key={s.id} className="cite" to={`/article/${s.id}`} title={s.title}>{s.source.name}</Link>)}</div>
            </div>
          ))}
          {b.kev_new?.length > 0 && <>
            <div className="divider" />
            <h3>New CISA KEV additions</h3>
            <ul className="claims">{b.kev_new.map((k) => <li key={k.cve_id}><Link to={`/vuln/${k.cve_id}`}><code>{k.cve_id}</code></Link> — {k.vendor} {k.product}: {k.name}</li>)}</ul>
          </>}
        </>}
      </section>

      {d.watch_updates.length > 0 && (
        <section className="section">
          <div className="section-head"><h2>Followed threats with new developments</h2><Link to="/watch" className="small">All watches</Link></div>
          <div className="stack">{d.watch_updates.map((w) => (
            <Link key={w.id} to={`/watch/${w.id}`} className="card row" style={{ color: 'inherit', textDecoration: 'none' }}>
              <span className="chip">{w.kind}</span><strong className="grow">{w.title}</strong>
              {w.important > 0 && <span className="sig important">{w.important} important</span>}
              <span className="small muted">{w.new_evidence} new</span>
            </Link>))}</div>
        </section>
      )}

      <section className="section">
        <div className="section-head"><h2>Since your last visit</h2><span className="small muted">{d.since_last_visit.count} new stor{d.since_last_visit.count === 1 ? 'y' : 'ies'}</span></div>
        <ArticleList items={d.since_last_visit.articles} empty={<Empty title="You’re up to date">Nothing new since your last visit.</Empty>} />
      </section>

      <section className="section">
        <div className="section-head"><h2>Top-priority threats (72h)</h2><Link to="/breaking" className="small">Breaking</Link></div>
        {d.top_threats.length ? <div className="alist">{d.top_threats.map((a) => <ArticleCard key={a.id} a={a} />)}</div> : <Empty title="No high-severity reporting in the last 72 hours" />}
      </section>
    </>
  )
}
