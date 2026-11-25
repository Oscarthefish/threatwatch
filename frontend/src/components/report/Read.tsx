import { useEffect, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, qs } from '../../api'
import { Highlight, Loading, MarkedText, queryTerms } from '../ui'
import { reportsPath, type Block, type FindingDraft, type ReadPage, type ReportDetail } from '../../reports'

const WINDOW = 4

/** The pages to show for a page number: its chapter (when chapters are known, up to 16 pages) or a window of four. */
function rangeFor(d: ReportDetail, page: number): { start: number; end: number; title?: string } {
  const total = d.pages.length
  const c = d.analysis?.chapters.find((x) => page >= x.start && page <= x.end)
  if (c) return { start: c.start, end: Math.min(c.end, c.start + 15), title: `${c.number} ${c.title}${c.subtitle ? ` · ${c.subtitle}` : ''}` }
  const chs = d.analysis?.chapters ?? []
  // pages before the first chapter, between chapters, or after the last one
  const before = chs.filter((x) => x.end < page).map((x) => x.end).sort((a, b) => b - a)[0] ?? 0
  const after = chs.filter((x) => x.start > page).map((x) => x.start).sort((a, b) => a - b)[0] ?? total + 1
  const start = Math.max(before + 1, page - ((page - before - 1) % WINDOW))
  return { start, end: Math.min(after - 1, start + WINDOW - 1, total) }
}

function Blocks({ blocks, terms, publisher }: { blocks: Block[]; terms: string[]; publisher: string }) {
  const out: ReactNode[] = []
  let list: Block[] = []
  const endList = (k: number) => { if (list.length) { out.push(<ul key={`l${k}`} className="rp-ul">{list.map((b, i) => <li key={i}><Highlight text={b.text} terms={terms} /></li>)}</ul>); list = [] } }
  blocks.forEach((b, i) => {
    if (b.type === 'li' && !b.vendor) { list.push(b); return }
    endList(i)
    if (b.vendor) out.push(<aside key={i} className="rp-vendor"><span className="rp-prov">Product guidance from {publisher}</span><p className="mb-0"><Highlight text={b.text} terms={terms} /></p></aside>)
    else if (b.type === 'h') out.push(<h3 key={i} className="rp-rh"><Highlight text={b.text} terms={terms} /></h3>)
    else if (b.type === 'figure') out.push(<details key={i} className="rp-figure"><summary>Text from a figure or diagram</summary><p className="small mb-0"><Highlight text={b.text} terms={terms} /></p></details>)
    else out.push(<p key={i}><Highlight text={b.text} terms={terms} /></p>)
  })
  endList(blocks.length)
  return <>{out}</>
}

export function Read({ d, onAdd }: { d: ReportDetail; onAdd: (dr: FindingDraft) => void }) {
  const id = d.report.id
  const total = d.pages.length
  const [params, setParams] = useSearchParams()
  const page = Math.min(Math.max(1, Number(params.get('page')) || 1), Math.max(1, total))
  const find = params.get('find') ?? ''
  const original = params.get('view') === 'original'
  const [text, setText] = useState(find)
  const [sel, setSel] = useState<{ page: number; text: string } | null>(null)
  // text selected inside one page of the reader can become a finding
  const readSelection = () => {
    const s = window.getSelection()
    const t = s?.toString().replace(/\s+/g, ' ').trim() ?? ''
    const node = s?.anchorNode instanceof Element ? s.anchorNode : s?.anchorNode?.parentElement
    const pg = node?.closest<HTMLElement>('[data-page]')
    setSel(t.length >= 12 && pg ? { page: Number(pg.dataset.page), text: t.slice(0, 600) } : null)
  }
  const set = (patch: Record<string, string>) => setParams((p) => { const n = new URLSearchParams(p); n.set('tab', 'read'); Object.entries(patch).forEach(([k, v]) => v ? n.set(k, v) : n.delete(k)); return n }, { replace: true })
  const r = rangeFor(d, page)
  const q = useQuery({
    queryKey: ['report-read', id, r.start, r.end, original],
    queryFn: () => api.get<{ pages: ReadPage[] }>(`${reportsPath(id)}/read${qs({ start: r.start, count: r.end - r.start + 1, raw: original || undefined })}`),
    enabled: total > 0,
  })
  const sq = useQuery({ queryKey: ['report-search', id, find], queryFn: () => api.get<{ results: { page_no: number; label: string | null; snip: string }[] }>(`${reportsPath(id)}/search${qs({ q: find })}`), enabled: !!find })
  useEffect(() => {
    if (!q.data) return
    const el = document.getElementById(`rp-p${page}`)
    if (el && page !== r.start) el.scrollIntoView({ block: 'start' })
    else if (page === r.start) document.getElementById('rp-read-top')?.scrollIntoView({ block: 'nearest' })
  }, [q.data, page, r.start])
  if (!total) return <div className="notice">No text has been extracted yet.</div>
  const terms = queryTerms(find)
  const publisher = d.report.publisher || d.analysis?.running_title?.split(' ')[0] || 'the publisher'
  const nav = d.analysis?.chapters.length ? d.analysis.chapters.map((c) => ({ key: c.number, title: `${c.number} ${c.title}`, sub: c.subtitle, page: c.start }))
    : d.sections.filter((s) => s.level === 1).map((s) => ({ key: String(s.ord), title: s.title, sub: null, page: s.page_start }))
  const prev = r.start > 1 ? rangeFor(d, r.start - 1).start : null
  const next = r.end < total ? r.end + 1 : null
  return (
    <div className="rp-pages">
      <aside className="rp-find">
        <form role="search" className="rp-search" onSubmit={(e) => { e.preventDefault(); set({ find: text.trim() }) }}>
          <label className="sr-only" htmlFor="rp-find">Search this report</label>
          <input id="rp-find" className="input" type="search" placeholder="Search this report" value={text} onChange={(e) => { setText(e.target.value); if (!e.target.value) set({ find: '' }) }} />
          <button type="submit" className="btn">Find</button>
        </form>
        {find ? (sq.isLoading ? <Loading lines={2} /> : (
          <>
            <p className="xsmall muted" role="status">{sq.data?.results.length ? `${sq.data.results.length} page${sq.data.results.length === 1 ? '' : 's'} match` : 'No pages match.'}</p>
            <ul className="rp-hits">{sq.data?.results.map((h) => (
              <li key={h.page_no}><button type="button" className={`rp-hit ${h.page_no === page ? 'on' : ''}`} aria-current={h.page_no === page || undefined} onClick={() => set({ page: String(h.page_no) })}>
                <span className="xsmall rp-hit-page">Page {h.page_no}</span><span className="small"><MarkedText text={h.snip} /></span>
              </button></li>))}
            </ul>
          </>
        )) : nav.length > 0 && (
          <nav aria-label="Chapters">
            <ol className="rp-nav">{nav.map((c) => (
              <li key={c.key}><button type="button" className={`rp-hit ${r.start <= c.page && c.page <= r.end ? 'on' : ''}`} aria-current={(r.start <= c.page && c.page <= r.end) || undefined} onClick={() => set({ page: String(c.page) })}>
                <span className="small"><strong>{c.title}</strong></span>{c.sub && <span className="xsmall muted">{c.sub}</span>}
              </button></li>))}
            </ol>
          </nav>
        )}
      </aside>
      <section className="card rp-reader" aria-labelledby="rp-read-h" id="rp-read-top" onMouseUp={readSelection} onKeyUp={readSelection} onTouchEnd={() => setTimeout(readSelection, 300)}>
        <div className="row between wrap rp-pager">
          <h2 id="rp-read-h" className="rp-h">{r.title ?? (r.start === r.end ? `Page ${r.start}` : `Pages ${r.start} to ${r.end}`)}<span className="xsmall muted"> of {total}</span></h2>
          <label className="rp-check small"><input type="checkbox" checked={original} onChange={(e) => set({ view: e.target.checked ? 'original' : '' })} /> Original text</label>
        </div>
        {q.isLoading ? <Loading /> : q.data?.pages.map((p) => (
          <div key={p.page_no} id={`rp-p${p.page_no}`} data-page={p.page_no} className={`rp-pg ${p.page_no === page && page !== r.start ? 'target' : ''}`}>
            <div className="rp-pg-mark" aria-hidden="true"><span>Page {p.page_no}{p.label ? ` (printed ${p.label})` : ''}</span></div>
            <span className="sr-only">Page {p.page_no}</span>
            {original || !p.blocks ? (
              p.text ? <div className="rp-text"><Highlight text={p.text} terms={terms} /></div> : <p className="muted small">No text on this page.</p>
            ) : p.blocks.length ? <div className="rp-body"><Blocks blocks={p.blocks} terms={terms} publisher={publisher} /></div>
              : <p className="muted small">No text on this page. It may be a full-page image or chart.</p>}
          </div>
        ))}
        <div className="row between wrap rp-pager rp-pager-end">
          <button type="button" className="btn small" disabled={!prev} onClick={() => prev && set({ page: String(prev) })}>Previous</button>
          <button type="button" className="btn small" disabled={!next} onClick={() => next && set({ page: String(next) })}>Next</button>
        </div>
        {sel && (
          <div className="rp-selbar" role="region" aria-label="Selected text">
            <span className="small">Selected text on page {sel.page}</span>
            <button type="button" className="btn small primary" onClick={() => { onAdd({ page: sel.page, quote: sel.text, origin: 'analyst' }); setSel(null) }}>Add as finding</button>
            <button type="button" className="btn small quiet" onClick={() => { window.getSelection()?.removeAllRanges(); setSel(null) }}>Dismiss</button>
          </div>
        )}
        <p className="xsmall muted mb-0">{original ? 'The text exactly as extracted from the PDF.' : 'Reflowed for reading: running headers removed, lines joined into paragraphs, figure labels folded away. Switch to Original text if something looks wrong. Select a passage to save it as a finding.'} Charts and images are not reproduced; download the PDF for those.</p>
      </section>
    </div>
  )
}
