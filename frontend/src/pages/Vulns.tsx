import { useInfiniteQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { api, qs } from '../api'
import type { Vuln } from '../types'
import { ErrorBox, Highlight, LoadMore, Loading, NoResults, PageHeader } from '../components/ui'

const PAGE = 50

/** One CVE: product first (what you recognise), identifiers and exploitation signals, scores on the right. */
export function VulnRow({ v, terms }: { v: Vuln; terms?: string[] }) {
  const product = [v.vendor, v.product].filter(Boolean).join(' ')
  return (
    <Link to={`/vuln/${v.cve_id}`} className="vrow" data-nav>
      <div className="grow">
        <div className="vprod"><Highlight text={product || v.cve_id} terms={terms} /></div>
        <div className="row mt-2">
          {product && <code className="mono-id"><Highlight text={v.cve_id} terms={terms} /></code>}
          {v.kev && <span className="chip kev">Exploited · KEV {v.kev_date_added}</span>}
          {v.kev_ransomware === 'Known' && <span className="chip kev">Ransomware use</span>}
          {(v.mentions ?? 0) > 0 && <span className="chip">{v.mentions} report{v.mentions === 1 ? '' : 's'}</span>}
        </div>
        {(v.name || v.description) && <div className="vname clamp-2 mt-2"><Highlight text={(v.name || v.description)!} terms={terms} /></div>}
        {!product && !v.name && !v.description && <div className="vname mt-2">Product and description pending from the CVE record</div>}
      </div>
      <dl className="vmetrics">
        <dt>EPSS</dt><dd className="mb-0">{v.epss != null ? <b className={v.epss >= 0.1 ? 'hot' : ''}>{(v.epss * 100).toFixed(1)}%</b> : <span className="na">n/a</span>}</dd>
        <dt>CVSS</dt><dd className="mb-0">{v.cvss_score != null ? <b className={v.cvss_score >= 9 ? 'hot' : ''}>{v.cvss_score.toFixed(1)}</b> : <span className="na">n/a</span>}</dd>
      </dl>
    </Link>
  )
}

export default function Vulns() {
  const [params, setParams] = useSearchParams()
  const kev = params.get('kev') ?? ''
  const sort = params.get('sort') ?? 'recent'
  const q = params.get('q') ?? ''
  const epss = params.get('epss') ?? ''
  const filtered = !!(kev || q || epss)
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }
  const clear = () => setParams(new URLSearchParams(sort !== 'recent' ? { sort } : {}), { replace: true })
  const query = useInfiniteQuery({
    queryKey: ['vulns', kev, sort, q, epss],
    queryFn: ({ pageParam }) => api.get<{ items: Vuln[]; has_more: boolean; stats: { total: number; kev: number; with_epss: number } }>(
      `/api/vulnerabilities${qs({ kev: kev ? 'true' : undefined, sort, q, min_epss: epss, offset: pageParam, limit: PAGE })}`),
    initialPageParam: 0,
    getNextPageParam: (last, all) => (last.has_more ? all.length * PAGE : undefined),
  })
  const items = query.data?.pages.flatMap((p) => p.items)
  const stats = query.data?.pages[0]?.stats

  return (
    <>
      <PageHeader title="Vulnerabilities" eyebrow={['Intelligence', 'CVE / KEV / EPSS / CVSS']}
        sub={stats ? `${stats.total.toLocaleString()} CVEs tracked, ${stats.kev.toLocaleString()} known to be exploited (CISA KEV).` : 'CVEs from reporting and the CISA KEV catalogue, scored with FIRST EPSS and CVSS.'} />
      <div className="filters">
        <form role="search" className="row nowrap" onSubmit={(e) => { e.preventDefault(); set('q', String(new FormData(e.currentTarget).get('q') ?? '').trim()) }}>
          <label className="sr-only" htmlFor="vq">Filter by CVE, vendor or product</label>
          <input id="vq" name="q" type="search" className="input grow" defaultValue={q} key={q} placeholder="CVE ID, vendor or product" />
          <button className="btn">Filter</button>
        </form>
        <div className="row">
          <div className="chips" role="group" aria-label="Quick filters">
            <button type="button" className={`chip ${kev ? 'on' : ''}`} aria-pressed={!!kev} onClick={() => set('kev', kev ? '' : '1')}>Exploited (KEV)</button>
            <button type="button" className={`chip ${epss ? 'on' : ''}`} aria-pressed={!!epss} onClick={() => set('epss', epss ? '' : '0.1')}>EPSS 10% or more</button>
          </div>
          <div className="selects grow end">
            <label>Sort
              <select className="input" value={sort} onChange={(e) => set('sort', e.target.value)}>
                <option value="recent">Recently added</option><option value="epss">Highest EPSS</option><option value="cvss">Highest CVSS</option><option value="mentioned">Most reported</option>
              </select>
            </label>
          </div>
        </div>
      </div>
      {query.isError ? <ErrorBox error={query.error} onRetry={() => query.refetch()} />
        : !items ? <Loading lines={8} />
        : items.length === 0 ? <NoResults filtered={filtered} onClear={clear} what="vulnerabilities" />
        : <div className="vlist">{items.map((v) => <VulnRow key={v.cve_id} v={v} />)}</div>}
      <LoadMore show={!!query.hasNextPage} busy={query.isFetchingNextPage} onClick={() => query.fetchNextPage()} />
    </>
  )
}
