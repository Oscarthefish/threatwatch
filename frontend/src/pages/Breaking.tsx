import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief, Vuln } from '../types'
import { ArticleCard, Confidence, Empty, ErrorBox, Loading, PageHeader, TimeAgo } from '../components/ui'

interface B { articles: ArticleBrief[]; kev_new: Vuln[]; watch_alerts: { watch_id: number; watch_title: string; article_id: number; title: string; assessment: string; linked_at: string }[] }

export default function Breaking() {
  const q = useQuery({ queryKey: ['breaking'], queryFn: () => api.get<B>('/api/breaking'), refetchInterval: 300_000 })
  if (q.isError) return <ErrorBox error={q.error} />
  if (!q.data) return <Loading lines={8} />
  const d = q.data
  return (
    <>
      <PageHeader title="Breaking" sub="Significant incidents and actively exploited vulnerabilities from the last 72 hours. Severity and confidence are derived from source evidence — hover a severity for its reasons." />
      {d.watch_alerts.length > 0 && (
        <section className="card">
          <h2>Important changes to followed items</h2>
          <ul className="claims">{d.watch_alerts.map((w) => (
            <li key={`${w.watch_id}-${w.article_id}`}><Link to={`/watch/${w.watch_id}`}><strong>{w.watch_title}</strong></Link>: <Link to={`/article/${w.article_id}`}>{w.title}</Link>
              <div className="small muted">{w.assessment} · <TimeAgo iso={w.linked_at} /></div></li>))}</ul>
        </section>
      )}
      <section className="section">
        <div className="section-head"><h2>Newly added to CISA KEV (7 days)</h2><Link className="small" to="/vulns?kev=1">All KEV</Link></div>
        {d.kev_new.length === 0 ? <Empty title="No KEV additions in the last 7 days" /> : (
          <div className="stack">{d.kev_new.map((v) => (
            <Link key={v.cve_id} to={`/vuln/${v.cve_id}`} className="card vcard" style={{ color: 'inherit', textDecoration: 'none' }}>
              <div>
                <div className="row"><code style={{ fontWeight: 700 }}>{v.cve_id}</code><span className="chip kev">KEV {v.kev_date_added}</span>
                  {v.kev_ransomware === 'Known' && <span className="chip kev">Ransomware use</span>}<Confidence value="official" /></div>
                <div style={{ fontWeight: 600, marginTop: '.2rem' }}>{v.vendor} {v.product}</div>
                <div className="small muted">{v.name}</div>
              </div>
              <div className="metric">{v.epss != null && <>EPSS<b>{(v.epss * 100).toFixed(1)}%</b></>}{v.cvss_score != null && <>CVSS<b>{v.cvss_score}</b></>}</div>
            </Link>))}</div>
        )}
      </section>
      <section className="section">
        <div className="section-head"><h2>Emerging incidents & exploitation</h2></div>
        {d.articles.length === 0 ? <Empty title="Quiet period">No high-severity incidents or exploitation reports in the last 72 hours.</Empty>
          : <div className="alist">{d.articles.map((a) => <ArticleCard key={a.id} a={a} extra={
            <div className="row small muted" style={{ marginTop: '.3rem' }}><Confidence value={a.confidence} /><span>·</span><span>{a.severity_reasons.slice(0, 2).join('; ')}</span></div>} />)}</div>}
      </section>
    </>
  )
}
