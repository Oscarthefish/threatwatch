import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { ErrorBox, Loading, PageHeader } from '../components/ui'
import { ColumnChart, DataTable, Dumbbells, RankBars, type Column, type Series } from '../components/charts'

interface Ent { type: string; name: string; query: string | null; tag: string | null; cur: number; prev: number; share: number; weekly: number[] }
interface Move extends Ent { prev_share: number; change: number }
interface T {
  days: number; bucket_days: number; period_start: string; previous_start: string; coverage_start: string
  current_partial: boolean; comparison_indicative: boolean
  totals: { current: Record<string, number>; previous: Record<string, number> }
  volume: { start: string; end: string; critical: number; high: number; other: number; partial: boolean }[]
  weeks: { start: string; end: string }[]
  groups: Ent[]; malware: Ent[]; vendors: Ent[]; topics: Ent[]; rising: Move[]; falling: Move[]
  kev: { weekly: { start: string; count: number }[]; current: number; previous: number; ransomware: number; vendors: { name: string; cur: number; prev: number }[] }
}

const TYPE: Record<string, string> = { actor: 'Threat actor', ransomware: 'Ransomware', malware: 'Malware', vendor: 'Vendor', topic: 'Topic' }
const SEV: Series[] = [
  { key: 'other', label: 'Medium and below', color: 'var(--viz-other)' },
  { key: 'high', label: 'High', color: 'var(--viz-high)' },
  { key: 'critical', label: 'Critical', color: 'var(--viz-crit)' },
]
const KEV: Series[] = [{ key: 'count', label: 'KEV additions', color: 'var(--viz-accent)' }]

const day = (iso: string) => new Date(`${iso}T00:00:00`).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short' })
const longDay = (iso: string) => new Date(`${iso}T00:00:00`).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric' })
const pct = (n: number, d: number) => (d ? Math.round((100 * n) / d) : 0)
const href = (e: Ent) => (e.tag ? `/latest?tag=${encodeURIComponent(e.tag)}` : `/search?q=${encodeURIComponent(e.query ?? e.name)}`)

export default function Trends() {
  const [params, setParams] = useSearchParams()
  const days = params.get('days') === '90' ? 90 : 30
  const q = useQuery({ queryKey: ['trends', days], queryFn: () => api.get<T>(`/api/trends?days=${days}`), placeholderData: (p) => p })
  return (
    <>
      <PageHeader title="Trends" eyebrow={['Intelligence', 'Reporting trends']}
        sub="What the collected reporting says is most active, rising and falling. Counts are stories, so several articles about one event count once."
        actions={
          <div className="seg" role="group" aria-label="Time range">
            {[30, 90].map((d) => <button key={d} type="button" aria-pressed={days === d} onClick={() => setParams(d === 30 ? {} : { days: String(d) }, { replace: true })}>{d} days</button>)}
          </div>
        } />
      {q.isError ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Loading lines={10} />
        : <div className={q.isFetching ? 'refetching' : ''}><Body t={q.data} /></div>}
    </>
  )
}

function Body({ t }: { t: T }) {
  const c = t.totals.current, p = t.totals.previous
  const prevLabel = `previous ${t.days} days`
  const partialWeeks = t.weeks.filter((w) => w.end < t.coverage_start).length
  const cols: Column[] = t.volume.map((v) => ({
    label: day(v.start), title: t.bucket_days === 1 ? longDay(v.start) : `Week of ${longDay(v.start)}`, partial: v.partial,
    values: { critical: v.critical, high: v.high, other: v.other },
  }))
  const kevCols: Column[] = t.kev.weekly.map((w) => ({ label: day(w.start), title: `Week of ${longDay(w.start)}`, values: { count: w.count } }))
  const reliableFrom = new Date(new Date(`${t.coverage_start}T00:00:00`).getTime() + t.days * 2 * 86400000).toISOString().slice(0, 10)

  return (
    <div className="stack trends">
      {t.current_partial && (
        <p className="notice coverage" role="note">
          <strong>Coverage.</strong> Collection began on {longDay(t.coverage_start)}. Stories dated earlier come from feed backlogs, which only hold each
          source's newest items, so those periods are incomplete and shaded in the charts. Rising and falling compare each subject's
          share of all stories, which corrects for that, but treat them as indicative until {longDay(reliableFrom)}. CISA KEV figures are complete.
        </p>
      )}

      <div className="tiles trend-tiles">
        <div className="tile"><div className="l">Stories</div><div className="n">{c.reports ?? 0}</div><div className="s">since {day(t.period_start)}</div></div>
        <div className="tile"><div className="l">Critical or high</div><div className="n">{pct(c.critical_high ?? 0, c.reports ?? 0)}%</div>
          <div className="s">{c.critical_high ?? 0} stories; {p.reports ? `${pct(p.critical_high ?? 0, p.reports)}% before` : 'no earlier data'}</div></div>
        <div className="tile"><div className="l">Exploitation reported</div><div className="n">{pct(c.exploited ?? 0, c.reports ?? 0)}%</div>
          <div className="s">{c.exploited ?? 0} stories; {p.reports ? `${pct(p.exploited ?? 0, p.reports)}% before` : 'no earlier data'}</div></div>
        <div className="tile"><div className="l">KEV additions</div><div className="n">{t.kev.current}</div>
          <div className="s">{t.kev.previous} in the {prevLabel}{t.kev.ransomware ? `; ${t.kev.ransomware} ransomware` : ''}</div></div>
      </div>

      <section className="panel" aria-labelledby="vol-h">
        <header><h2 id="vol-h">Reporting volume by severity</h2><span className="xsmall muted">{t.bucket_days === 1 ? 'Stories per day' : 'Stories per week'}</span></header>
        <div className="body">
          <ColumnChart columns={cols} series={SEV} label="Stories per period by severity" partialNote="Feed backlog: incomplete" />
          <DataTable caption="Stories per period by severity" head={['Period', 'Critical', 'High', 'Medium and below', 'Complete']}
            rows={t.volume.map((v) => [cols[t.volume.indexOf(v)].title, v.critical, v.high, v.other, v.partial ? 'No' : 'Yes'])} />
        </div>
      </section>

      <div className="trend-grid">
        <section className="panel" aria-labelledby="grp-h">
          <header><h2 id="grp-h">Most active threat groups</h2><span className="xsmall muted">Stories naming them</span></header>
          <div className="body">
            <p className="xsmall muted">Actors and ransomware groups, ranked by stories in the last {t.days} days.</p>
            {t.groups.length === 0 ? <p className="small muted mb-0">No threat groups named in this period.</p> : <>
              <RankBars rows={t.groups.map((e) => ({ key: e.type + e.name, name: e.name, sub: TYPE[e.type], value: e.cur, prev: e.prev, href: href(e), weekly: e.weekly }))}
                unit="stories" partialWeeks={partialWeeks} nowLabel={`Last ${t.days} days`} prevLabel={`Previous ${t.days} days`} />
              <DataTable caption="Most active threat groups" head={['Group', 'Type', 'Stories', `Stories, ${prevLabel}`, 'Weekly']}
                rows={t.groups.map((e) => [e.name, TYPE[e.type], e.cur, e.prev, e.weekly.join(' / ')])} />
            </>}
          </div>
        </section>

        <section className="panel" aria-labelledby="mov-h">
          <header><h2 id="mov-h">Rising and falling</h2><span className="xsmall muted">Share of all stories</span></header>
          <div className="body">
            {!p.reports ? <p className="small muted mb-0">Not enough history to compare yet. The {prevLabel} have no collected reporting.</p> : <>
              <p className="xsmall muted">
                <span className="key before" aria-hidden="true" /> {prevLabel} <span className="key now" aria-hidden="true" /> last {t.days} days.
                {t.comparison_indicative && ' Indicative: the earlier period is partly from feed backlogs.'}
              </p>
              {t.rising.length > 0 && <><h3 className="mini-h">Rising</h3>
                <Dumbbells rows={t.rising.map((m) => ({ key: m.type + m.name, name: m.name, sub: TYPE[m.type], before: m.prev_share, now: m.share, href: href(m) }))} /></>}
              {t.falling.length > 0 && <><h3 className="mini-h">Falling</h3>
                <Dumbbells rows={t.falling.map((m) => ({ key: m.type + m.name, name: m.name, sub: TYPE[m.type], before: m.prev_share, now: m.share, href: href(m) }))} /></>}
              {!t.rising.length && !t.falling.length && <p className="small muted mb-0">No subject moved by a point or more.</p>}
              <DataTable caption="Rising and falling subjects" head={['Subject', 'Type', `Share, ${prevLabel}`, 'Share now', 'Change (points)', 'Stories now', 'Stories before']}
                rows={[...t.rising, ...t.falling].map((m) => [m.name, TYPE[m.type], `${m.prev_share}%`, `${m.share}%`, m.change > 0 ? `+${m.change}` : m.change, m.cur, m.prev])} />
            </>}
          </div>
        </section>

        <section className="panel" aria-labelledby="mal-h">
          <header><h2 id="mal-h">Malware and tools</h2><span className="xsmall muted">Stories naming them</span></header>
          <div className="body">
            {t.malware.length === 0 ? <p className="small muted mb-0">None named in this period.</p> : <>
              <RankBars rows={t.malware.map((e) => ({ key: e.name, name: e.name, value: e.cur, prev: e.prev, href: href(e), weekly: e.weekly }))} unit="stories" partialWeeks={partialWeeks} nowLabel={`Last ${t.days} days`} prevLabel={`Previous ${t.days} days`} />
              <DataTable caption="Malware and tools" head={['Name', 'Stories', `Stories, ${prevLabel}`]} rows={t.malware.map((e) => [e.name, e.cur, e.prev])} />
            </>}
          </div>
        </section>

        <section className="panel" aria-labelledby="ven-h">
          <header><h2 id="ven-h">Vendors in the news</h2><span className="xsmall muted">Stories naming them</span></header>
          <div className="body">
            {t.vendors.length === 0 ? <p className="small muted mb-0">None named in this period.</p> : <>
              <RankBars rows={t.vendors.map((e) => ({ key: e.name, name: e.name, value: e.cur, prev: e.prev, href: href(e), weekly: e.weekly }))} unit="stories" partialWeeks={partialWeeks} nowLabel={`Last ${t.days} days`} prevLabel={`Previous ${t.days} days`} />
              <DataTable caption="Vendors in the news" head={['Vendor', 'Stories', `Stories, ${prevLabel}`]} rows={t.vendors.map((e) => [e.name, e.cur, e.prev])} />
            </>}
          </div>
        </section>

        <section className="panel" aria-labelledby="top-h">
          <header><h2 id="top-h">Topics</h2><span className="xsmall muted">Share of all stories</span></header>
          <div className="body">
            <RankBars rows={t.topics.map((e) => ({ key: e.name, name: e.name, value: e.cur, prev: e.prev, href: href(e),
              extra: <span className="rank-share">{e.share}%</span> }))} unit="stories" nowLabel={`Last ${t.days} days`} prevLabel={`Previous ${t.days} days`} />
            <DataTable caption="Topics" head={['Topic', 'Stories', 'Share', `Stories, ${prevLabel}`]} rows={t.topics.map((e) => [e.name, e.cur, `${e.share}%`, e.prev])} />
          </div>
        </section>

        <section className="panel" aria-labelledby="kev-h">
          <header><h2 id="kev-h">Exploited vulnerabilities</h2><span className="xsmall muted">CISA KEV, complete</span></header>
          <div className="body">
            <ColumnChart columns={kevCols} series={KEV} label="CISA KEV additions per week" height={150} />
            <DataTable caption="CISA KEV additions per week" head={['Week', 'Additions']} rows={kevCols.map((k) => [k.title, k.values.count])} />
            <h3 className="mini-h">Vendors added most</h3>
            <RankBars rows={t.kev.vendors.map((v) => ({ key: v.name, name: v.name, value: v.cur, prev: v.prev, href: `/vulns?kev=1&q=${encodeURIComponent(v.name)}` }))} unit="KEV additions" nowLabel={`Last ${t.days} days`} prevLabel={`Previous ${t.days} days`} />
            <DataTable caption="Vendors added to KEV most" head={['Vendor', 'Additions', `Additions, ${prevLabel}`]} rows={t.kev.vendors.map((v) => [v.name, v.cur, v.prev])} />
          </div>
        </section>
      </div>
      <p className="xsmall faint">
        How this is counted: stories are grouped articles about the same event, by the publisher's date. Group, malware and vendor counts leave out
        roundups and podcasts, which name many unrelated subjects. Counts reflect reporting, not the number of attacks.
      </p>
    </div>
  )
}
