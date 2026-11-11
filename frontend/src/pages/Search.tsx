import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief, Vuln, Watch } from '../types'
import { ArticleCard, Empty, ErrorBox, Loading, PageHeader } from '../components/ui'
import { kindLabel } from '../components/follow'
import { VulnRow } from './Vulns'

interface Results { articles: ArticleBrief[]; vulnerabilities: Vuln[]; watches: Watch[] }

export default function Search() {
  const [params, setParams] = useSearchParams()
  const q = (params.get('q') ?? '').trim()
  const r = useQuery({ queryKey: ['search', q], queryFn: () => api.get<Results>(`/api/search?q=${encodeURIComponent(q)}`), enabled: q.length >= 2 })
  const total = r.data ? r.data.articles.length + r.data.vulnerabilities.length + r.data.watches.length : 0

  return (
    <>
      <PageHeader title={q ? `Search: ${q}` : 'Search'} eyebrow={['Search']} sub="Searches every collected article, tracked CVE and followed item." />
      <form role="search" className="row nowrap filters" onSubmit={(e) => { e.preventDefault(); setParams({ q: String(new FormData(e.currentTarget).get('q') ?? '').trim() }) }}>
        <label className="sr-only" htmlFor="sq">Search</label>
        <input id="sq" name="q" type="search" className="input grow" defaultValue={q} key={q} placeholder="CVE-2026-1234, Akira, Citrix, ClickFix" autoFocus={!q} />
        <button className="btn primary">Search</button>
      </form>

      {q.length < 2 ? (
        <Empty title="What are you looking for?">
          <p>Try a CVE ID, a product (Citrix NetScaler), an actor (Scattered Spider), a malware family or any keyword. Words are matched in full; the last word also matches as a prefix.</p>
        </Empty>
      ) : r.isError ? <ErrorBox error={r.error} onRetry={() => r.refetch()} /> : !r.data ? <Loading lines={6} /> : total === 0 ? (
        <Empty title={`Nothing found for “${q}”`}>
          <p>Check the spelling, use fewer words, or search for the vendor or product name instead of the full headline.</p>
        </Empty>
      ) : <>
        <p className="list-meta"><span>{total} result{total === 1 ? '' : 's'}</span></p>
        {r.data.watches.length > 0 && (
          <section className="result-group" aria-labelledby="sr-w">
            <h2 id="sr-w" className="day-head">Following ({r.data.watches.length})</h2>
            <div className="vlist">{r.data.watches.map((w) => (
              <Link key={w.id} to={`/watch/${w.id}`} className="vrow"><div><div className="xsmall muted">{kindLabel(w.kind)}</div><div className="vprod">{w.title}</div></div></Link>
            ))}</div>
          </section>
        )}
        {r.data.vulnerabilities.length > 0 && (
          <section className="result-group" aria-labelledby="sr-v">
            <h2 id="sr-v" className="day-head">Vulnerabilities ({r.data.vulnerabilities.length})</h2>
            <div className="vlist">{r.data.vulnerabilities.map((v) => <VulnRow key={v.cve_id} v={v} />)}</div>
          </section>
        )}
        {r.data.articles.length > 0 && (
          <section className="result-group" aria-labelledby="sr-a">
            <h2 id="sr-a" className="day-head">Reports ({r.data.articles.length}{r.data.articles.length === 40 ? ', best 40 shown' : ''})</h2>
            <div className="alist">{r.data.articles.map((a) => <ArticleCard key={a.id} a={a} />)}</div>
          </section>
        )}
      </>}
    </>
  )
}
