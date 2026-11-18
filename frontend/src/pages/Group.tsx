import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../api'
import { ArticleCard, BackLink, Empty, ErrorBox, ExtLink, Eyebrow, fmtDate, Loading, usePageTitle, useToast } from '../components/ui'
import { ColumnChart, DataTable, RankBars, type Column } from '../components/charts'
import { GroupTrendChart, groupPath, isGroupKind, useGroup } from '../components/GroupTrend'
import { day, longDay } from '../components/trendsData'
import { CLAIMS, ClaimList, countryName, type GroupClaims } from '../components/ransom'
import { IconEye } from '../components/icons'

const KIND_LABEL: Record<string, string> = { actor: 'Threat actor', ransomware: 'Ransomware group', malware: 'Malware or tool' }
const RELATED: [string, string][] = [['groups', 'Threat groups'], ['malware', 'Malware and tools'], ['cve', 'CVEs'], ['vendor', 'Vendors'], ['attack_technique', 'ATT&CK techniques']]

function relatedHref(type: string, value: string, url?: string | null) {
  if (url) return url
  if (type === 'cve') return `/vuln/${value}`
  if (isGroupKind(type)) return groupPath(type, value)
  return `/search?q=${encodeURIComponent(value)}`
}

export default function GroupPage() {
  const { kind = '', name = '' } = useParams()
  const [days, setDays] = useState(90)
  const q = useGroup(kind, name, days, isGroupKind(kind))
  const qc = useQueryClient()
  const toast = useToast()
  const nav = useNavigate()
  usePageTitle(q.data?.name ?? name)
  const follow = useMutation({
    mutationFn: () => api.post<{ id: number }>('/api/watches', {
      kind: q.data!.kind === 'malware' ? 'malware' : 'actor', title: q.data!.name, identifiers: [q.data!.name], aliases: q.data!.aliases, notify_pref: 'important',
    }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ['group'] }); qc.invalidateQueries({ queryKey: ['watches'] }); toast(`Following ${q.data!.name}`); nav(`/watch/${r.id}`) },
    onError: (e) => toast(`Could not follow: ${(e as Error).message}`, 'error'),
  })

  if (!isGroupKind(kind) || (q.error instanceof ApiError && q.error.status === 404)) {
    return (
      <>
        <BackLink fallback="/trends" />
        <header className="page-head"><Eyebrow parts={['Threat group profile']} /><h1>No profile for “{name}”</h1></header>
        <p className="muted measure">Threat Watch has no threat actor, ransomware group or malware family by that name or alias. <Link to={`/search?q=${encodeURIComponent(name)}`}>Search the reporting instead</Link>.</p>
      </>
    )
  }
  if (q.isError) return <><BackLink fallback="/trends" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  if (!q.data) return <Loading lines={10} />
  const g = q.data
  const related = RELATED.filter(([k]) => g.related[k]?.length)
  const counted = g.articles.filter((a) => !a.tags.includes('roundup'))
  const roundups = g.articles.filter((a) => a.tags.includes('roundup'))

  return (
    <div className={q.isFetching ? 'refetching' : ''}>
      <BackLink fallback="/trends" />
      <header className="page-head row between top">
        <div className="grow">
          <Eyebrow parts={[KIND_LABEL[g.kind], 'Profile from collected reporting']} />
          <h1>{g.name}</h1>
          {g.aliases.length > 0 && <p className="small muted mb-0">Also known as {g.aliases.join(', ')}</p>}
        </div>
        {g.watch
          ? <Link className="btn on" to={`/watch/${g.watch.id}`}><IconEye />Following</Link>
          : <button type="button" className="btn primary" aria-busy={follow.isPending || undefined} onClick={() => follow.mutate()}><IconEye />Follow {g.name}</button>}
      </header>

      <div className="tiles trend-tiles">
        <div className="tile"><div className="l">Stories, last {g.days} days</div><div className="n">{g.stories}</div>
          <div className="s">{g.previous ? `${g.previous} in the ${g.days} days before` : g.comparison_indicative ? 'earlier period incomplete' : 'none in the period before'}</div></div>
        <div className="tile"><div className="l">Share of all stories</div><div className="n">{g.share}%</div>
          <div className="s">{g.previous_share != null ? `${g.previous_share}% before` : 'no earlier data'}</div></div>
        <div className="tile"><div className="l">Last reported</div><div className="n">{g.last_seen ? new Date(`${g.last_seen}T00:00:00`).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short' }) : 'None'}</div>
          <div className="s">{g.first_seen ? `first seen ${longDay(g.first_seen)}` : 'not yet named in reporting'}</div></div>
        <div className="tile"><div className="l">Sources</div><div className="n">{g.sources.length}</div><div className="s">{g.sources.slice(0, 2).join(', ') || 'none yet'}</div></div>
      </div>

      <div className="doc-grid mt-4">
        <div className="doc-main">
          <GroupTrendChart g={g} days={days} onDays={setDays} />
          {g.kind === 'ransomware' && <ClaimsPanel name={g.name} days={days} c={g.claims} />}

          <section aria-labelledby="g-rep">
            <div className="section-head"><h2 id="g-rep">Reports naming {g.name}</h2><span className="xsmall muted">Newest first</span></div>
            {counted.length === 0 ? <Empty title="No reports yet">Threat Watch adds reports here as soon as a collected story names {g.name}{g.aliases.length ? ` or ${g.aliases[0]}` : ''}.</Empty>
              : <div className="alist">{counted.map((a) => <ArticleCard key={a.id} a={a} />)}</div>}
            {roundups.length > 0 && (
              <details className="disclose mt-3">
                <summary>{roundups.length} roundup and podcast mention{roundups.length === 1 ? '' : 's'} (not counted)</summary>
                <div className="alist">{roundups.map((a) => <ArticleCard key={a.id} a={a} />)}</div>
              </details>
            )}
          </section>
        </div>

        <aside className="doc-aside" aria-label="Related">
          <section className="panel" aria-labelledby="g-att">
            <header><h2 id="g-att">MITRE ATT&CK</h2>{g.attack && <ExtLink className="small" href={g.attack.url}>{g.attack.attack_id}</ExtLink>}</header>
            <div className="body">
              {g.attack ? <>
                <p className="small">{g.attack.description}</p>
                <p className="xsmall faint">MITRE's description{g.attack.modified ? `, updated ${fmtDate(g.attack.modified).split(',')[0]}` : ''}.</p>
                {g.attack.aliases.length > 0 && <p className="xsmall muted">MITRE also lists: {g.attack.aliases.join(', ')}</p>}
                <p className="mb-2"><ExtLink href={g.attack.url}>{g.attack.name} on MITRE ATT&CK</ExtLink><span className="xsmall muted"> · techniques, software and campaigns</span></p>
                {g.attack.refs.length > 0 && (
                  <details className="disclose">
                    <summary>Reports MITRE cites ({g.attack.ref_count})</summary>
                    <ul className="reflist">{g.attack.refs.map((r) => (
                      <li key={r.url}><ExtLink href={r.url}>{r.description || r.source}</ExtLink></li>
                    ))}</ul>
                    {g.attack.ref_count > g.attack.refs.length && <p className="xsmall muted mb-0">The rest are listed on the MITRE page.</p>}
                  </details>
                )}
              </> : g.attack_synced_at
                ? <p className="small muted mb-0">MITRE ATT&CK does not track {g.name} as a {g.kind === 'actor' ? 'group' : 'software entry'}. Newer and smaller groups are often missing.</p>
                : <p className="small muted mb-0">MITRE ATT&CK data has not been downloaded yet. It syncs weekly; the first sync runs on the next collection.</p>}
            </div>
          </section>

          <section className="panel" aria-labelledby="g-rel">
            <header><h2 id="g-rel">Reported alongside</h2><span className="xsmall muted">Shared stories</span></header>
            <div className="body">
              {related.length === 0 ? <p className="small muted mb-0">Nothing yet. This fills in as more reporting names {g.name}.</p>
                : related.map(([k, label]) => (
                  <div key={k}>
                    <h3 className="mini-h">{label}</h3>
                    <RankBars showPrev={false} unit="shared stories"
                      rows={g.related[k].map((r) => ({ key: r.type + r.value, name: r.value, sub: r.name ?? undefined, value: r.stories, href: relatedHref(r.type, r.value, r.url) }))} />
                  </div>
                ))}
              <p className="xsmall faint mt-3 mb-0">Named in the same stories, roundups excluded. Co-occurrence is not attribution.</p>
            </div>
          </section>
          {g.sources.length > 0 && (
            <section className="panel" aria-labelledby="g-src">
              <header><h2 id="g-src">Sources reporting</h2></header>
              <div className="body"><ul className="reflist">{g.sources.map((s) => <li key={s}>{s}</li>)}</ul></div>
            </section>
          )}
        </aside>
      </div>
    </div>
  )
}

function ClaimsPanel({ name, days, c }: { name: string; days: number; c: GroupClaims | null }) {
  if (!c) {
    return (
      <section className="panel" aria-labelledby="g-claims">
        <header><h2 id="g-claims">Leak-site claims</h2></header>
        <div className="body"><p className="small muted mb-0">No leak-site claims by {name} have been collected. Claims come from ransomware.live and cover the last three months.</p></div>
      </section>
    )
  }
  const cols: Column[] = c.weekly.map((w) => ({ label: day(w.start), title: `Week of ${longDay(w.start)}`, partial: w.partial, values: { count: w.count } }))
  return (
    <section className="panel" aria-labelledby="g-claims">
      <header><h2 id="g-claims">Leak-site claims</h2><ExtLink className="small" href={c.tracker_url}>{name} on ransomware.live</ExtLink></header>
      <div className="body">
        <p className="small">
          {c.current} claim{c.current === 1 ? '' : 's'} in the last {days} days{c.previous || !c.comparison_indicative ? `, ${c.previous} in the ${days} days before` : ''}.
          Last claim {fmtDate(c.last_seen).split(',')[0]}.
        </p>
        <ColumnChart columns={cols} series={CLAIMS} label={`${name} leak-site claims per week`} height={150} partialNote="Before collection: incomplete" />
        <DataTable caption={`${name} leak-site claims per week`} head={['Week', 'Claims', 'Complete']} rows={c.weekly.map((w, i) => [cols[i].title, w.count, w.partial ? 'No' : 'Yes'])} />
        <div className="claims-split">
          <div>
            <h3 className="mini-h">Sectors</h3>
            {c.sectors.length ? <RankBars showPrev={false} unit="claims" rows={c.sectors.map((s) => ({ key: s.name, name: s.name, value: s.n }))} />
              : <p className="xsmall muted">No sector given.</p>}
          </div>
          <div>
            <h3 className="mini-h">Countries</h3>
            {c.countries.length ? <RankBars showPrev={false} unit="claims" rows={c.countries.map((x) => ({ key: x.code, name: countryName(x.code), value: x.n }))} />
              : <p className="xsmall muted">No country given.</p>}
          </div>
        </div>
        <h3 className="mini-h">Recent claims</h3>
        <ClaimList claims={c.recent} hideGroup />
        <p className="xsmall faint mt-3 mb-0">These are {name}'s own claims, collected by ransomware.live, and are not verified. Threat Watch never links to the leak site itself.</p>
      </div>
    </section>
  )
}
