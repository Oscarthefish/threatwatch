import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, qs } from '../api'
import type { BriefingItem, Today as TodayT } from '../types'
import { ActionTags, ArticleRow, Empty, ErrorBox, Eyebrow, fmtDate, Loading, Severity, TimeAgo, usePageTitle } from '../components/ui'
import { IconRefresh } from '../components/icons'

const KEY = 'tw-visit-baseline'
const store = {
  get: () => { try { return sessionStorage.getItem(KEY) } catch { return null } },
  set: (v: string) => { try { sessionStorage.setItem(KEY, v) } catch { /* unavailable */ } },
}

function greeting() {
  const h = Number(new Intl.DateTimeFormat('en-NZ', { hour: 'numeric', hourCycle: 'h23', timeZone: 'Pacific/Auckland' }).format(new Date()))
  return h < 5 ? 'Good evening' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening'
}

function Tile({ to, n, label, sub, tone }: { to: string; n: number | string; label: string; sub?: string; tone?: string }) {
  const cls = `tile ${tone ?? ''} ${n === 0 ? 'zero' : ''}`
  const inner = <><div className="l">{label}</div><div className="n">{n}</div>{sub && <div className="s" title={sub}>{sub}</div>}</>
  return to.startsWith('#') ? <a href={to} className={cls}>{inner}</a> : <Link to={to} className={cls}>{inner}</Link>
}

function BriefItem({ it, n, open, onToggle }: { it: BriefingItem; n: number; open: boolean; onToggle: () => void }) {
  const lead = it.sources?.[0]
  return (
    <div className="bitem">
      <span className="num">{n}</span>
      <div className="grow">
        <button className="bt" aria-expanded={open} onClick={onToggle}>{it.title}</button>
        {it.summary && <p className="bs">{it.summary}</p>}
        <div className="bm">
          <Severity level={it.priority} />
          {(it.sources ?? []).slice(0, 4).map((s) => <Link key={s.id} className="cite" to={`/article/${s.id}`} title={s.title}>{s.source.name}</Link>)}
          {(it.sources?.length ?? 0) > 4 && <span className="faint">+{(it.sources?.length ?? 0) - 4}</span>}
          {lead && <span className="faint"><TimeAgo iso={lead.published_at} /></span>}
        </div>
        {!open && <ActionTags actions={lead?.actions} />}
        {open && it.why_it_matters && <p className="why"><strong>Why it matters: </strong>{it.why_it_matters}</p>}
        {open && (lead?.actions?.length ?? 0) > 0 && (
          <div className="todo-inline">
            <div className="xsmall strong muted">What to do</div>
            <ul>{lead!.actions.map((a) => <li key={a.kind + a.label}><strong>{a.label}.</strong> {a.detail} <span className="basis">{a.basis}</span></li>)}</ul>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Today() {
  const [baseline, setBaseline] = useState<string | null>(store.get)
  const [open, setOpen] = useState<Set<number>>(new Set())
  const [filter, setFilter] = useState<'all' | 'high'>('all')
  const [showAll, setShowAll] = useState(false)
  usePageTitle('Today')
  const q = useQuery({
    queryKey: ['today', baseline],
    queryFn: () => api.get<TodayT>(`/api/today${qs({ since: baseline })}`),
    refetchInterval: 300_000,
  })

  // First load this session: pin the baseline so "since last visit" stays stable while you read, then record the visit.
  useEffect(() => {
    if (q.data && !baseline) {
      store.set(q.data.baseline)
      setBaseline(q.data.baseline)
      api.post('/api/visit').catch(() => {})
    }
  }, [q.data, baseline])

  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  if (!q.data) return <Loading lines={10} />
  const d = q.data
  const st = d.stats
  const b = d.briefing
  const since = d.since_last_visit.articles.filter((a) => filter === 'all' || a.severity >= 3)
  const shown = showAll ? since : since.slice(0, 8)
  const allOpen = b ? open.size === b.items.length : false

  function markSeen() {
    const now = new Date().toISOString()
    store.set(now); setBaseline(now); setShowAll(false)
    api.post('/api/visit').catch(() => {})
  }

  return (
    <>
      <div className="today-head">
        <div>
          <Eyebrow parts={[new Date().toLocaleDateString('en-NZ', { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Pacific/Auckland' }), 'Pacific/Auckland']} />
          <h1>Today</h1>
          <div className="muted small">{greeting()}. Last collection <TimeAgo iso={d.last_ingest_at} />.</div>
        </div>
        <button className="btn" aria-label="Refresh" onClick={() => q.refetch()} disabled={q.isFetching}><IconRefresh /><span className="lbl">{q.isFetching ? 'Refreshing…' : 'Refresh'}</span></button>
      </div>

      <div className="tiles">
        <Tile to="#since" n={st.new_since_visit} label="New since visit" sub={d.last_visit_at ? `since ${timeOrDate(d.baseline)}` : 'last 24 hours'} />
        <Tile to="/breaking" n={st.critical_24h} label="Critical · 24h" tone="crit" sub={`of ${st.total_24h} stories`} />
        <Tile to="/breaking" n={st.high_24h} label="High · 24h" tone="high" />
        <Tile to="/vulns?kev=1" n={st.kev_7d} label="New KEV · 7d" tone="crit" sub="confirmed exploitation" />
        <Tile to="/watch" n={st.watch_updates} label="Following" sub={st.review_queue ? `${st.review_queue} waiting for review` : 'with new reporting'} tone={st.review_queue ? 'warn' : ''} />
        <Tile to="/settings" n={`${st.sources_ok}/${st.sources_total}`} label="Sources OK" tone={st.sources_failing.length ? 'warn' : ''}
          sub={st.sources_failing.length ? `failing: ${st.sources_failing.join(', ')}` : 'all collecting'} />
      </div>

      <div className="today-grid">
        <div>
          <section className="panel" aria-labelledby="brief-h">
            <header>
              <h2 id="brief-h">Daily briefing</h2>
              {b && <button className="link" onClick={() => setOpen(allOpen ? new Set() : new Set(b.items.map((_, i) => i)))}>{allOpen ? 'Collapse all' : 'Expand all'}</button>}
            </header>
            <div className="body">
              {!b ? <Empty title="No briefing yet">The first briefing is generated after the initial collection, then daily at 7:00 AM NZ time.</Empty> : <>
                {b.headline && <p className="strong mb-0">{b.headline}</p>}
                <p className="xsmall faint mb-2">
                  {b.date} · {fmtDate(b.generated_at)} · {b.method === 'ai' ? `AI synthesis (${b.model}), check against the sources` : 'ranked from source reporting, using the publishers’ own text'}
                </p>
                {b.items.map((it, i) => <BriefItem key={i} it={it} n={i + 1} open={open.has(i)}
                  onToggle={() => setOpen((s) => { const n = new Set(s); if (n.has(i)) n.delete(i); else n.add(i); return n })} />)}
              </>}
            </div>
          </section>

          <section className="panel" id="since" aria-labelledby="since-h">
            <header>
              <h2 id="since-h">Since your last visit <span className="muted small">({d.since_last_visit.count})</span></h2>
              <div className="row">
                <div className="seg" role="group" aria-label="Filter">
                  <button className={filter === 'all' ? 'on' : ''} aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>All</button>
                  <button className={filter === 'high' ? 'on' : ''} aria-pressed={filter === 'high'} onClick={() => setFilter('high')}>High+</button>
                </div>
                {d.since_last_visit.count > 0 && <button className="link" onClick={markSeen}>Mark all seen</button>}
              </div>
            </header>
            <div className="body">
              {since.length === 0 ? <Empty title="You’re up to date">{filter === 'high' ? 'No new high or critical stories.' : 'Nothing new since your last visit.'}</Empty> : <>
                {shown.map((a) => <ArticleRow key={a.id} a={a} />)}
                <div className="row between small mt-2">
                  {since.length > 8 ? <button className="link" onClick={() => setShowAll(!showAll)}>{showAll ? 'Show fewer' : `Show all ${since.length}`}</button> : <span />}
                  <Link to="/latest">Browse all latest →</Link>
                </div>
              </>}
            </div>
          </section>
        </div>

        <div>
          <section className="panel" aria-labelledby="watch-h">
            <header><h2 id="watch-h">Following</h2><Link to="/watch">All</Link></header>
            <div className="body">
              {d.watch_updates.length > 0 ? d.watch_updates.map((w) => (
                <Link key={w.id} to={`/watch/${w.id}`} className="kevrow">
                  <span className="chip">{w.kind}</span>
                  <span className="p grow">{w.title}</span>
                  <span className="r">{w.important > 0 && <span className="sig important">{w.important} important</span>} {w.new_evidence} new</span>
                </Link>
              )) : <p className="small muted mb-0">
                {st.watching ? `No new developments on your ${st.watching} followed item${st.watching === 1 ? '' : 's'}.` : <>Not following anything yet. Open an article and tap <strong>Follow</strong> to track an incident, CVE or actor.</>}
                {st.review_queue > 0 && <> <Link to="/watch">{st.review_queue} item{st.review_queue === 1 ? '' : 's'} awaiting review.</Link></>}
              </p>}
            </div>
          </section>

          <section className="panel" aria-labelledby="kev-h">
            <header><h2 id="kev-h">New in CISA KEV</h2><Link to="/vulns?kev=1">All KEV</Link></header>
            <div className="body">
              {d.kev_new.length === 0 ? <p className="small muted mb-0">No additions in the last 7 days.</p> : d.kev_new.map((v) => (
                <Link key={v.cve_id} to={`/vuln/${v.cve_id}`} className="kevrow">
                  <div className="grow">
                    <div className="p">{[v.vendor, v.product].filter(Boolean).join(' ')}</div>
                    <code>{v.cve_id}</code>{v.kev_ransomware === 'Known' && <span className="chip kev ml-1">ransomware</span>}
                  </div>
                  <div className="r">{v.kev_date_added}<br />{v.epss != null ? `EPSS ${(v.epss * 100).toFixed(1)}%` : ''}{v.cvss_score != null ? ` · ${v.cvss_score}` : ''}</div>
                </Link>
              ))}
            </div>
          </section>

          <section className="panel" aria-labelledby="apac-h">
            <header><h2 id="apac-h">New Zealand & APAC</h2><Link to="/apac">More</Link></header>
            <div className="body">
              {d.regional.length === 0 ? <p className="small muted mb-0">No regional reporting in the last 14 days.</p> : d.regional.map((a) => <ArticleRow key={a.id} a={a} />)}
            </div>
          </section>

          {d.top_threats.length > 0 && (
            <section className="panel" aria-labelledby="top-h">
              <header><h2 id="top-h">Also high priority (72h)</h2><Link to="/breaking">Breaking</Link></header>
              <div className="body">{d.top_threats.map((a) => <ArticleRow key={a.id} a={a} />)}</div>
            </section>
          )}
        </div>
      </div>
    </>
  )
}

function timeOrDate(iso: string) {
  const d = new Date(iso)
  const sameDay = d.toDateString() === new Date().toDateString()
  return sameDay
    ? d.toLocaleTimeString('en-NZ', { hour: 'numeric', minute: '2-digit', timeZone: 'Pacific/Auckland' })
    : d.toLocaleDateString('en-NZ', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'Pacific/Auckland' })
}
