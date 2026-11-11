import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, qs } from '../api'
import type { ArticleBrief, Vuln } from '../types'
import { ArticleCard, Empty, ErrorBox, Highlight, Loading, OrderNote, PageHeader, Term, TimeAgo } from '../components/ui'
import { humanReason } from '../components/follow'
import { IconBolt, IconBug, IconEye } from '../components/icons'

interface Alert {
  watch_id: number; watch_title: string; kind: string; article_id: number; title: string; source_name: string
  assessment: string; match_reasons: string[]; linked_at: string; passages: { text: string; terms: string[] }[]
}
interface B {
  articles: ArticleBrief[]
  kev_new: Vuln[]
  kev_bulletins: { id: number; title: string; published_at: string; source: { name: string } }[]
  watch_alerts: Alert[]
  order: string
}

const KEV_PREVIEW = 5
const ALERT_PREVIEW = 3

export default function Breaking() {
  const [params, setParams] = useSearchParams()
  const order = params.get('order') === 'new' ? 'new' : 'rank'
  const q = useQuery({ queryKey: ['breaking', order], queryFn: () => api.get<B>(`/api/breaking${qs({ order })}`), refetchInterval: 300_000 })
  const setOrder = (o: string) => setParams(o === 'rank' ? {} : { order: o }, { replace: true })
  return (
    <>
      <PageHeader title="Breaking" eyebrow={['Intelligence', 'Last 72 hours']}
        sub="What needs attention now: significant incidents, newly exploited vulnerabilities and changes to what you follow."
        actions={
          <div className="seg" role="group" aria-label="Order incidents by">
            <button type="button" aria-pressed={order === 'rank'} onClick={() => setOrder('rank')}>Priority</button>
            <button type="button" aria-pressed={order === 'new'} onClick={() => setOrder('new')}>Newest</button>
          </div>
        } />
      {q.isError ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Loading lines={8} /> : <Body d={q.data} order={order} />}
    </>
  )
}

/** Why a report was linked to a followed item, and what it adds, with the matching sentence. */
function FollowUpdate({ w }: { w: Alert }) {
  const reasons = w.match_reasons.filter((r) => !r.startsWith('contextual similarity')).map(humanReason)
  const p = w.passages[0]
  return (
    <li className="fup" data-nav>
      <Link to={`/watch/${w.watch_id}`} className="fup-title" data-open>{w.watch_title}</Link>
      {w.assessment && <p className="fup-change">{w.assessment}</p>}
      {p && <blockquote className="fup-quote"><Highlight text={p.text} terms={p.terms} /></blockquote>}
      <Link className="fup-src" to={`/article/${w.article_id}`}>{w.title}</Link>
      <div className="fup-meta">
        {reasons.length > 0 && <>Matched: {reasons.slice(0, 2).join(', ')} · </>}{w.source_name} · <TimeAgo iso={w.linked_at} />
      </div>
    </li>
  )
}

function KevItem({ v }: { v: Vuln }) {
  const product = [v.vendor, v.product].filter(Boolean).join(' ')
  return (
    <li>
      <Link to={`/vuln/${v.cve_id}`} className="kevrow" data-nav>
        <div className="grow">
          <div className="p">{product || v.cve_id}</div>
          <div className="row nowrap">
            {product && <code>{v.cve_id}</code>}
            {v.kev_ransomware === 'Known' && <span className="chip kev">Ransomware use</span>}
          </div>
        </div>
        <div className="r">Added {v.kev_date_added ? new Date(`${v.kev_date_added}T00:00:00`).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short' }) : 'n/a'}<br />{v.epss != null ? `EPSS ${(v.epss * 100).toFixed(1)}%` : 'EPSS n/a'}</div>
      </Link>
    </li>
  )
}

function Body({ d, order }: { d: B; order: string }) {
  const [allKev, setAllKev] = useState(false)
  const [allAlerts, setAllAlerts] = useState(false)
  const kev = allKev ? d.kev_new : d.kev_new.slice(0, KEV_PREVIEW)
  const alerts = allAlerts ? d.watch_alerts : d.watch_alerts.slice(0, ALERT_PREVIEW)
  const ransomware = d.kev_new.filter((v) => v.kev_ransomware === 'Known').length

  return (
    <div className="bk-grid">
      {d.watch_alerts.length > 0 && (
        <section className="panel bk-follow" aria-labelledby="wa-h">
          <header>
            <h2 id="wa-h" className="kind-head follow"><IconEye aria-hidden="true" />Your followed items<span className="count">{d.watch_alerts.length}</span></h2>
            <Link to="/watch">Following</Link>
          </header>
          <div className="body">
            <p className="xsmall muted bk-intro">Important changes in the last 72 hours: what changed, and the sentence that matched.</p>
            <ul className={`fups ${allAlerts ? '' : 'collapsed'}`}>{alerts.map((w) => <FollowUpdate key={`${w.watch_id}-${w.article_id}`} w={w} />)}</ul>
            {d.watch_alerts.length > 1 && (
              <button type="button" className={`link ${d.watch_alerts.length <= ALERT_PREVIEW ? 'narrow-only' : ''}`} aria-expanded={allAlerts} onClick={() => setAllAlerts(!allAlerts)}>
                {allAlerts ? 'Show fewer' : `Show all ${d.watch_alerts.length}`}
              </button>
            )}
          </div>
        </section>
      )}

      <section className="bk-inc" aria-labelledby="inc-h">
        <div className="section-head">
          <h2 id="inc-h" className="kind-head incident"><IconBolt aria-hidden="true" />Incidents and exploitation<span className="count">{d.articles.length}</span></h2>
        </div>
        <div className="list-meta"><OrderNote order={order} /></div>
        {d.articles.length === 0 ? <Empty title="Quiet period"><p>No high-severity incidents or exploitation reports in the last 72 hours.</p></Empty>
          : <div className="alist">{d.articles.map((a) => <ArticleCard key={a.id} a={a} showConfidence />)}</div>}
      </section>

      <section className="panel bk-kev" aria-labelledby="kev-h">
        <header>
          <h2 id="kev-h" className="kind-head exploited"><IconBug aria-hidden="true" />Newly exploited<span className="count">{d.kev_new.length}</span></h2>
          <Link to="/vulns?kev=1">All KEV</Link>
        </header>
        <div className="body">
          <p className="xsmall muted">
            Added to CISA's <Term id="kev">Known Exploited Vulnerabilities</Term> catalogue in the last 7 days{ransomware ? `; ${ransomware} with known ransomware use` : ''}. Newest first, then by EPSS.
          </p>
          {d.kev_new.length === 0 ? <p className="small muted mb-0">No additions in the last 7 days.</p> : <>
            <ul className="plain">{kev.map((v) => <KevItem key={v.cve_id} v={v} />)}</ul>
            {d.kev_new.length > KEV_PREVIEW && (
              <button type="button" className="link" aria-expanded={allKev} onClick={() => setAllKev(!allKev)}>
                {allKev ? 'Show fewer' : `Show all ${d.kev_new.length}`}
              </button>
            )}
          </>}
          {d.kev_bulletins.length > 0 && (
            <div className="bk-bulletins">
              <div className="xsmall strong muted">CISA announcements</div>
              <ul className="plain">
                {d.kev_bulletins.map((b) => <li key={b.id}><Link to={`/article/${b.id}`}>{b.title}</Link> <span className="faint xsmall"><TimeAgo iso={b.published_at} /></span></li>)}
              </ul>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
