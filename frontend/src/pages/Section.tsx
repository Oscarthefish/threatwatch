import { useInfiniteQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { api, qs } from '../api'
import type { ArticleBrief } from '../types'
import { ArticleCard, Empty, ErrorBox, Loading, PageHeader } from '../components/ui'

interface Props { section: string; title: string; sub: string; tags?: [string, string][]; regions?: [string, string][] }

export default function Section({ section, title, sub, tags, regions }: Props) {
  const [params, setParams] = useSearchParams()
  const tag = params.get('tag') ?? ''
  const region = params.get('region') ?? ''
  const sev = params.get('sev') ?? ''
  const days = params.get('days') ?? ''
  const order = params.get('order') ?? 'rank'
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }

  const q = useInfiniteQuery({
    queryKey: ['section', section, tag, region, sev, days, order],
    queryFn: ({ pageParam }) => api.get<{ items: ArticleBrief[]; has_more: boolean }>(
      `/api/articles${qs({ section, tag, region, severity_min: sev, days, order, offset: pageParam, limit: 30 })}`),
    initialPageParam: 0,
    getNextPageParam: (last, all) => last.has_more ? all.length * 30 : undefined,
  })
  const items = q.data?.pages.flatMap((p) => p.items)

  return (
    <>
      <PageHeader title={title} sub={sub} />
      <div className="stack" style={{ marginBottom: '1rem' }}>
        {tags && <div className="chips" role="group" aria-label="Topic filter">
          <button className={`chip ${!tag ? 'on' : ''}`} onClick={() => set('tag', '')}>All</button>
          {tags.map(([v, l]) => <button key={v} className={`chip ${tag === v ? 'on' : ''}`} aria-pressed={tag === v} onClick={() => set('tag', tag === v ? '' : v)}>{l}</button>)}
        </div>}
        {regions && <div className="chips" role="group" aria-label="Region filter">
          <button className={`chip ${!region ? 'on' : ''}`} onClick={() => set('region', '')}>All regions</button>
          {regions.map(([v, l]) => <button key={v} className={`chip ${region === v ? 'on' : ''}`} aria-pressed={region === v} onClick={() => set('region', region === v ? '' : v)}>{l}</button>)}
        </div>}
        <div className="row">
          <label className="sr-only" htmlFor="f-sev">Minimum severity</label>
          <select id="f-sev" className="input" style={{ width: 'auto' }} value={sev} onChange={(e) => set('sev', e.target.value)}>
            <option value="">Any severity</option><option value="2">Medium+</option><option value="3">High+</option><option value="4">Critical</option></select>
          <label className="sr-only" htmlFor="f-days">Time range</label>
          <select id="f-days" className="input" style={{ width: 'auto' }} value={days} onChange={(e) => set('days', e.target.value)}>
            <option value="">All time</option><option value="1">24 hours</option><option value="7">7 days</option><option value="30">30 days</option></select>
          <label className="sr-only" htmlFor="f-order">Sort</label>
          <select id="f-order" className="input" style={{ width: 'auto' }} value={order} onChange={(e) => set('order', e.target.value)}>
            <option value="rank">Most important</option><option value="new">Newest</option></select>
        </div>
      </div>
      {q.isError && <ErrorBox error={q.error} />}
      {!items ? <Loading lines={8} /> : items.length === 0 ? <Empty title="No matching reporting">Try widening the filters.</Empty> : (
        <div className="alist">{items.map((a) => <ArticleCard key={a.id} a={a} />)}</div>
      )}
      {q.hasNextPage && <div style={{ textAlign: 'center', marginTop: '1rem' }}>
        <button className="btn" onClick={() => q.fetchNextPage()} disabled={q.isFetchingNextPage}>{q.isFetchingNextPage ? 'Loading…' : 'Load more'}</button></div>}
    </>
  )
}
