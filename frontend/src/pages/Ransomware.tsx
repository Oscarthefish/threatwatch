import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { ErrorBox, ExtLink, Loading, PageHeader, Term } from '../components/ui'
import { ColumnChart, DataTable, Dumbbells, RankBars, type Column } from '../components/charts'
import { day, groupPath, longDay, pct } from '../components/trendsData'
import { CLAIMS, ClaimList, countryName, type RansomData as R, type RGroup } from '../components/ransom'

export default function Ransomware() {
  const [params, setParams] = useSearchParams()
  const days = params.get('days') === '90' ? 90 : 30
  const q = useQuery({ queryKey: ['ransomware', days], queryFn: () => api.get<R>(`/api/ransomware?days=${days}`), placeholderData: (p) => p })
  return (
    <>
      <PageHeader title="Ransomware" eyebrow={['Intelligence', 'Leak-site claims']}
        sub={<>Which groups are posting the most victims on their leak sites, and who they target. These are the groups' own <Term id="leak-site-claim">claims</Term>, collected by ransomware.live, and are not verified.</>}
        actions={
          <div className="seg" role="group" aria-label="Time range">
            {[30, 90].map((d) => <button key={d} type="button" aria-pressed={days === d} onClick={() => setParams(d === 30 ? {} : { days: String(d) }, { replace: true })}>{d} days</button>)}
          </div>
        } />
      {q.isError ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : !q.data ? <Loading lines={10} />
        : <div className={q.isFetching ? 'refetching' : ''}><Body r={q.data} /></div>}
    </>
  )
}

const sub = (g: RGroup) => [g.sectors.map((s) => s.name).join(', '), g.countries.map((c) => c.code).join(', ')].filter(Boolean).join(' · ')

function Body({ r }: { r: R }) {
  const prevLabel = `previous ${r.days} days`
  if (!r.coverage_start) {
    return (
      <p className="notice coverage" role="note">
        <strong>No claims collected yet.</strong> {r.source.enabled
          ? 'The first collection also fetches the last three months, one request a minute as ransomware.live asks, so it takes about four minutes after the next scheduled run.'
          : 'The ransomware.live source is paused in Settings.'}
      </p>
    )
  }
  const cols: Column[] = r.volume.map((v) => ({
    label: day(v.start), title: r.bucket_days === 1 ? longDay(v.start) : `Week of ${longDay(v.start)}`, partial: v.partial, values: { count: v.count },
  }))
  const partialWeeks = r.weeks.filter((w) => w.end < (r.coverage_start ?? '')).length
  const topSector = r.sectors[0]
  const known = r.totals.current - r.totals.unknown_sector

  return (
    <div className="stack trends">
      {r.current_partial && (
        <p className="notice coverage" role="note">
          <strong>Coverage.</strong> Claims are complete from {longDay(r.coverage_start)}. Earlier days are missing and shaded in the charts.
        </p>
      )}

      <div className="tiles trend-tiles">
        <div className="tile"><div className="l">Claims</div><div className="n">{r.totals.current}</div>
          <div className="s">{r.totals.previous ? `${r.totals.previous} in the ${prevLabel}` : 'no earlier data'}</div></div>
        <div className="tile"><div className="l">Groups posting</div><div className="n">{r.totals.groups}</div><div className="s">since {day(r.period_start)}</div></div>
        <div className="tile"><div className="l">Most claimed sector</div><div className="n tile-text">{topSector?.name ?? 'None'}</div>
          <div className="s">{topSector ? `${pct(topSector.cur, known)}% of claims with a sector` : 'no sector data'}</div></div>
        <div className="tile"><div className="l">New Zealand and Australia</div><div className="n">{r.regional.length}</div><div className="s">claims in the last {r.regional_days} days</div></div>
      </div>

      <section className="panel" aria-labelledby="rv-h">
        <header><h2 id="rv-h">Claims over time</h2><span className="xsmall muted">{r.bucket_days === 1 ? 'Claims per day' : 'Claims per week'}</span></header>
        <div className="body">
          <ColumnChart columns={cols} series={CLAIMS} label="Leak-site claims per period" partialNote="Before collection: incomplete" />
          <DataTable caption="Leak-site claims per period" head={['Period', 'Claims', 'Complete']}
            rows={r.volume.map((v, i) => [cols[i].title, v.count, v.partial ? 'No' : 'Yes'])} />
        </div>
      </section>

      <div className="trend-grid">
        <section className="panel" aria-labelledby="rg-h">
          <header><h2 id="rg-h">Most active groups</h2><span className="xsmall muted">Claims posted</span></header>
          <div className="body">
            <p className="xsmall muted">Ranked by claims in the last {r.days} days, with each group's most claimed sectors and countries. Each name opens the group's profile.</p>
            {r.groups.length === 0 ? <p className="small muted mb-0">No claims in this period.</p> : <>
              <RankBars rows={r.groups.map((g) => ({ key: g.name, name: g.name, sub: sub(g), value: g.cur, prev: g.prev, href: groupPath('ransomware', g.name), weekly: g.weekly }))}
                unit="claims" partialWeeks={partialWeeks} nowLabel={`Last ${r.days} days`} prevLabel={`Previous ${r.days} days`} />
              <DataTable caption="Most active ransomware groups" head={['Group', 'Claims', `Claims, ${prevLabel}`, 'Share', 'Top sectors', 'Top countries']}
                rows={r.groups.map((g) => [g.name, g.cur, g.prev, `${g.share}%`, g.sectors.map((s) => `${s.name} (${s.n})`).join(', '), g.countries.map((c) => `${countryName(c.code)} (${c.n})`).join(', ')])} />
            </>}
          </div>
        </section>

        <section className="panel" aria-labelledby="rm-h">
          <header><h2 id="rm-h">Rising and falling</h2><span className="xsmall muted">Share of all claims</span></header>
          <div className="body">
            {!r.totals.previous ? <p className="small muted mb-0">Not enough history to compare yet.</p> : <>
              <p className="xsmall muted">
                <span className="key before" aria-hidden="true" /> {prevLabel} <span className="key now" aria-hidden="true" /> last {r.days} days.
                {r.comparison_indicative && ' Indicative: the earlier period is incomplete.'} Groups with fewer than 8 claims across both periods are left out.
              </p>
              {r.rising.length > 0 && <><h3 className="mini-h">Rising</h3>
                <Dumbbells rows={r.rising.map((m) => ({ key: m.name, name: m.name, sub: `${m.prev} → ${m.cur} claims`, before: m.prev_share, now: m.share, change: m.change, href: groupPath('ransomware', m.name) }))} /></>}
              {r.falling.length > 0 && <><h3 className="mini-h">Falling</h3>
                <Dumbbells rows={r.falling.map((m) => ({ key: m.name, name: m.name, sub: `${m.prev} → ${m.cur} claims`, before: m.prev_share, now: m.share, change: m.change, href: groupPath('ransomware', m.name) }))} /></>}
              {!r.rising.length && !r.falling.length && <p className="small muted mb-0">No group's share moved by a point or more.</p>}
              <DataTable caption="Rising and falling ransomware groups" head={['Group', `Share, ${prevLabel}`, 'Share now', 'Change (points)', 'Claims now', 'Claims before']}
                rows={[...r.rising, ...r.falling].map((m) => [m.name, `${m.prev_share}%`, `${m.share}%`, m.change > 0 ? `+${m.change}` : m.change, m.cur, m.prev])} />
            </>}
          </div>
        </section>

        <section className="panel" aria-labelledby="rs-h">
          <header><h2 id="rs-h">Sectors claimed</h2><span className="xsmall muted">Claims</span></header>
          <div className="body">
            <RankBars rows={r.sectors.map((s) => ({ key: s.name, name: s.name, value: s.cur, prev: s.prev }))} unit="claims" nowLabel={`Last ${r.days} days`} prevLabel={`Previous ${r.days} days`} />
            <DataTable caption="Sectors claimed" head={['Sector', 'Claims', `Claims, ${prevLabel}`]} rows={r.sectors.map((s) => [s.name, s.cur, s.prev])} />
            <p className="xsmall faint mt-3 mb-0">{r.totals.unknown_sector} claims in this period have no sector.</p>
          </div>
        </section>

        <section className="panel" aria-labelledby="rc-h">
          <header><h2 id="rc-h">Countries claimed</h2><span className="xsmall muted">Claims</span></header>
          <div className="body">
            <RankBars rows={r.countries.map((c) => ({ key: c.code, name: countryName(c.code), value: c.cur, prev: c.prev }))} unit="claims" nowLabel={`Last ${r.days} days`} prevLabel={`Previous ${r.days} days`} />
            <DataTable caption="Countries claimed" head={['Country', 'Claims', `Claims, ${prevLabel}`]} rows={r.countries.map((c) => [countryName(c.code), c.cur, c.prev])} />
            <p className="xsmall faint mt-3 mb-0">{r.totals.unknown_country} claims in this period have no country.</p>
          </div>
        </section>
      </div>

      <section className="panel" aria-labelledby="rr-h">
        <header><h2 id="rr-h">New Zealand and Australia</h2><span className="xsmall muted">Last {r.regional_days} days</span></header>
        <div className="body">
          {r.regional.length === 0 ? <p className="small muted mb-0">No claims against New Zealand or Australian organisations in the last {r.regional_days} days.</p>
            : <ClaimList claims={r.regional} />}
        </div>
      </section>

      <section className="panel" aria-labelledby="rn-h">
        <header><h2 id="rn-h">Recent claims</h2><span className="xsmall muted">Newest first</span></header>
        <div className="body"><ClaimList claims={r.recent} /></div>
      </section>

      <p className="xsmall faint">
        How this is counted: one claim is one victim posted on a ransomware leak site, dated when <ExtLink href="https://www.ransomware.live/">ransomware.live</ExtLink> first
        saw it. Claims are the groups' own statements: they exaggerate, re-post old or other groups' victims, and sometimes list organisations they never
        breached. "In the news" means a story collected by Threat Watch names the victim. Threat Watch never links to the leak sites themselves. See{' '}
        <Term id="leak-site">Leak site</Term> in the Glossary.
      </p>
    </div>
  )
}
