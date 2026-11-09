import { useInfiniteQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { api, qs } from '../api'
import type { Vuln } from '../types'
import { Empty, ErrorBox, Loading, PageHeader } from '../components/ui'

export function VulnRow({ v }: { v: Vuln }) {
  return (
    <Link to={`/vuln/${v.cve_id}`} className="card vcard" style={{ color: 'inherit', textDecoration: 'none' }}>
      <div style={{ minWidth: 0 }}>
        <div className="row">
          <code style={{ fontWeight: 700 }}>{v.cve_id}</code>
          {v.kev && <span className="chip kev" title="CISA Known Exploited Vulnerabilities: confirmed exploitation">KEV {v.kev_date_added}</span>}
          {v.kev_ransomware === 'Known' && <span className="chip kev">Ransomware use</span>}
          {(v.mentions ?? 0) > 0 && <span className="chip">{v.mentions} article{v.mentions === 1 ? '' : 's'}</span>}
        </div>
        <div style={{ fontWeight: 600, marginTop: '.2rem' }}>{[v.vendor, v.product].filter(Boolean).join(' · ') || 'Product not yet known'}</div>
        <div className="small muted" style={{ overflow: 'hidden', textOverflow: 'ellipsis', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>{v.name || v.description || 'Awaiting CVE record enrichment'}</div>
      </div>
      <div className="metric" style={{ minWidth: 72 }}>
        <span title="FIRST EPSS: probability of exploitation in the next 30 days">EPSS</span><b>{v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : '—'}</b>
        {v.epss != null && <div className="bar"><i style={{ width: `${Math.max(3, v.epss * 100)}%` }} /></div>}
        <span style={{ display: 'block', marginTop: 4 }}>CVSS</span><b>{v.cvss_score ?? '—'}</b>
      </div>
    </Link>
  )
}

export default function Vulns() {
  const [params, setParams] = useSearchParams()
  const kev = params.get('kev') ?? ''
  const sort = params.get('sort') ?? 'recent'
  const q = params.get('q') ?? ''
  const epss = params.get('epss') ?? ''
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }
  const query = useInfiniteQuery({
    queryKey: ['vulns', kev, sort, q, epss],
    queryFn: ({ pageParam }) => api.get<{ items: Vuln[]; has_more: boolean; stats: { total: number; kev: number; with_epss: number } }>(
      `/api/vulnerabilities${qs({ kev: kev ? 'true' : undefined, sort, q, min_epss: epss, offset: pageParam, limit: 50 })}`),
    initialPageParam: 0,
    getNextPageParam: (last, all) => last.has_more ? all.length * 50 : undefined,
  })
  const items = query.data?.pages.flatMap((p) => p.items)
  const stats = query.data?.pages[0]?.stats
  return (
    <>
      <PageHeader title="Vulnerabilities" sub={stats ? `${stats.total} tracked CVEs · ${stats.kev} in CISA KEV · EPSS for ${stats.with_epss}` : 'CVE, CISA KEV, FIRST EPSS and CVSS'} />
      <div className="stack" style={{ marginBottom: '1rem' }}>
        <form className="row" onSubmit={(e) => { e.preventDefault(); set('q', String(new FormData(e.currentTarget).get('q') ?? '')) }}>
          <label className="sr-only" htmlFor="vq">Filter CVEs</label>
          <input id="vq" name="q" className="input grow" defaultValue={q} placeholder="CVE ID, vendor or product" />
          <button className="btn">Filter</button>
        </form>
        <div className="row">
          <button className={`chip ${kev ? 'on' : ''}`} aria-pressed={!!kev} onClick={() => set('kev', kev ? '' : '1')}>KEV only</button>
          <button className={`chip ${epss ? 'on' : ''}`} aria-pressed={!!epss} onClick={() => set('epss', epss ? '' : '0.1')}>EPSS ≥ 10%</button>
          <label className="sr-only" htmlFor="vsort">Sort</label>
          <select id="vsort" className="input" style={{ width: 'auto' }} value={sort} onChange={(e) => set('sort', e.target.value)}>
            <option value="recent">Recently added</option><option value="epss">Highest EPSS</option><option value="cvss">Highest CVSS</option><option value="mentioned">Most reported</option></select>
        </div>
      </div>
      {query.isError && <ErrorBox error={query.error} />}
      {!items ? <Loading lines={8} /> : items.length === 0 ? <Empty title="No vulnerabilities match" /> : <div className="stack">{items.map((v) => <VulnRow key={v.cve_id} v={v} />)}</div>}
      {query.hasNextPage && <div style={{ textAlign: 'center', marginTop: '1rem' }}><button className="btn" onClick={() => query.fetchNextPage()}>Load more</button></div>}
    </>
  )
}
