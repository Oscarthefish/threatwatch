import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief, Vuln } from '../types'
import { ArticleCard, Confidence, Empty, ErrorBox, Loading, PageHeader, TimeAgo } from '../components/ui'
import { VulnRow } from './Vulns'

interface B {
  articles: ArticleBrief[]
  kev_new: Vuln[]
  watch_alerts: { watch_id: number; watch_title: string; article_id: number; title: string; assessment: string; linked_at: string }[]
}

export default function Breaking() {
  const q = useQuery({ queryKey: ['breaking'], queryFn: () => api.get<B>('/api/breaking'), refetchInterval: 300_000 })
  return (
    <>
      <PageHeader title="Breaking" eyebrow={['Intelligence', 'Last 72 hours']}
        sub="Significant incidents and actively exploited vulnerabilities. Severity and confidence come from the source evidence; tap a severity to see why." />
      {q.isError ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Loading lines={8} /> : <Body d={q.data} />}
    </>
  )
}

function Body({ d }: { d: B }) {
  return (
    <div className="stack">
      {d.watch_alerts.length > 0 && (
        <section className="panel review" aria-labelledby="wa-h">
          <header><h2 id="wa-h">Important changes to what you follow</h2><Link to="/watch">Following</Link></header>
          <div className="body">
            {d.watch_alerts.map((w) => (
              <Link key={`${w.watch_id}-${w.article_id}`} to={`/watch/${w.watch_id}`} className="kevrow">
                <span className="dot s3" aria-hidden="true" />
                <div className="grow">
                  <div className="p">{w.watch_title}</div>
                  <div className="xsmall muted">{w.title} · <TimeAgo iso={w.linked_at} /></div>
                  {w.assessment && <div className="xsmall muted">{w.assessment}</div>}
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}

      <section aria-labelledby="kev-h">
        <div className="section-head"><h2 id="kev-h">Newly exploited: CISA KEV, last 7 days</h2><Link className="small" to="/vulns?kev=1">All KEV</Link></div>
        {d.kev_new.length === 0 ? <Empty title="No KEV additions in the last 7 days" />
          : <div className="vlist">{d.kev_new.map((v) => <VulnRow key={v.cve_id} v={v} />)}</div>}
      </section>

      <section aria-labelledby="inc-h" className="section">
        <div className="section-head"><h2 id="inc-h">Incidents and exploitation</h2><span className="xsmall muted">{d.articles.length} report{d.articles.length === 1 ? '' : 's'}</span></div>
        {d.articles.length === 0 ? <Empty title="Quiet period"><p>No high-severity incidents or exploitation reports in the last 72 hours.</p></Empty>
          : <div className="alist">{d.articles.map((a) => <ArticleCard key={a.id} a={a} extra={<div className="mt-2"><Confidence value={a.confidence} /></div>} />)}</div>}
      </section>
    </div>
  )
}
