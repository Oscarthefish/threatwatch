import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief, Vuln, Watch } from '../types'
import { ArticleList, Empty, ErrorBox, Loading, PageHeader } from '../components/ui'
import { VulnRow } from './Vulns'

export default function Search() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const r = useQuery({ queryKey: ['search', q], queryFn: () => api.get<{ articles: ArticleBrief[]; vulnerabilities: Vuln[]; watches: Watch[] }>(`/api/search?q=${encodeURIComponent(q)}`), enabled: q.length >= 2 })
  return (
    <>
      <PageHeader title="Search" sub="Searches every collected article, tracked CVE and followed item." />
      <form role="search" className="row" style={{ marginBottom: '1rem' }} onSubmit={(e) => { e.preventDefault(); setParams({ q: String(new FormData(e.currentTarget).get('q') ?? '') }) }}>
        <label className="sr-only" htmlFor="sq">Search</label>
        <input id="sq" name="q" className="input grow" defaultValue={q} key={q} placeholder="e.g. CVE-2026-1234, Akira, Citrix, ClickFix" autoFocus />
        <button className="btn primary">Search</button>
      </form>
      {q.length < 2 ? <Empty title="Search intelligence">Type at least two characters.</Empty> : r.isError ? <ErrorBox error={r.error} /> : !r.data ? <Loading /> : <>
        {r.data.watches.length > 0 && <section className="section"><h2>Your watches</h2><ul className="claims">{r.data.watches.map((w) => <li key={w.id}><Link to={`/watch/${w.id}`}>{w.title}</Link> <span className="chip">{w.kind}</span></li>)}</ul></section>}
        {r.data.vulnerabilities.length > 0 && <section className="section"><h2>Vulnerabilities</h2><div className="stack">{r.data.vulnerabilities.map((v) => <VulnRow key={v.cve_id} v={v} />)}</div></section>}
        <section className="section"><h2>Articles ({r.data.articles.length})</h2><ArticleList items={r.data.articles} empty={<Empty title="No matching articles" />} /></section>
      </>}
    </>
  )
}
