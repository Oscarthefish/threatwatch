import { useInfiniteQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { api, qs } from '../api'
import type { ArticleBrief } from '../types'
import { ArticleCard, ErrorBox, LoadMore, Loading, NoResults, OrderNote, PageHeader } from '../components/ui'

interface Props { section?: string; title: string; sub: string; tags?: [string, string][]; regions?: [string, string][] }

const PAGE = 30

export default function Section({ section, title, sub, tags, regions }: Props) {
  const [params, setParams] = useSearchParams()
  const tag = params.get('tag') ?? ''
  const region = params.get('region') ?? ''
  const sev = params.get('sev') ?? ''
  const days = params.get('days') ?? ''
  const order = params.get('order') ?? 'rank'
  const filtered = !!(tag || region || sev || days)
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }
  const clear = () => setParams(new URLSearchParams(order !== 'rank' ? { order } : {}), { replace: true })

  const q = useInfiniteQuery({
    queryKey: ['section', section, tag, region, sev, days, order],
    queryFn: ({ pageParam }) => api.get<{ items: ArticleBrief[]; has_more: boolean }>(
      `/api/articles${qs({ section, tag, region, severity_min: sev, days, order, offset: pageParam, limit: PAGE })}`),
    initialPageParam: 0,
    getNextPageParam: (last, all) => (last.has_more ? all.length * PAGE : undefined),
  })
  const items = q.data?.pages.flatMap((p) => p.items)

  return (
    <>
      <PageHeader title={title} sub={sub} eyebrow={['Intelligence', section ? 'Topic feed' : 'All sources']} />
      <div className="filters">
        {tags && (
          <div className="chips scroll" role="group" aria-label="Topic">
            <button type="button" className={`chip ${!tag ? 'on' : ''}`} aria-pressed={!tag} onClick={() => set('tag', '')}>All topics</button>
            {tags.map(([v, l]) => <button type="button" key={v} className={`chip ${tag === v ? 'on' : ''}`} aria-pressed={tag === v} onClick={() => set('tag', tag === v ? '' : v)}>{l}</button>)}
          </div>
        )}
        {regions && (
          <div className="chips scroll" role="group" aria-label="Region">
            <button type="button" className={`chip ${!region ? 'on' : ''}`} aria-pressed={!region} onClick={() => set('region', '')}>All regions</button>
            {regions.map(([v, l]) => <button type="button" key={v} className={`chip ${region === v ? 'on' : ''}`} aria-pressed={region === v} onClick={() => set('region', region === v ? '' : v)}>{l}</button>)}
          </div>
        )}
        <div className="selects">
          <label>Severity
            <select className="input" value={sev} onChange={(e) => set('sev', e.target.value)}>
              <option value="">Any</option><option value="2">Medium and above</option><option value="3">High and above</option><option value="4">Critical only</option>
            </select>
          </label>
          <label>Published
            <select className="input" value={days} onChange={(e) => set('days', e.target.value)}>
              <option value="">Any time</option><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option>
            </select>
          </label>
          <label>Sort
            <select className="input" value={order} onChange={(e) => set('order', e.target.value)}>
              <option value="rank">Priority</option><option value="new">Newest</option>
            </select>
          </label>
          {filtered && <button type="button" className="btn quiet" onClick={clear}>Clear filters</button>}
        </div>
      </div>
      {q.isError ? <ErrorBox error={q.error} onRetry={() => q.refetch()} />
        : !items ? <Loading lines={8} />
        : items.length === 0 ? <NoResults filtered={filtered} onClear={clear} />
        : <>
          <div className="list-meta"><span>{items.length}{q.hasNextPage ? '+' : ''} report{items.length === 1 ? '' : 's'}</span><OrderNote order={order} /></div>
          <div className="alist">{items.map((a) => <ArticleCard key={a.id} a={a} />)}</div>
        </>}
      <LoadMore show={!!q.hasNextPage} busy={q.isFetchingNextPage} onClick={() => q.fetchNextPage()} />
    </>
  )
}
