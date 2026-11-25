import { useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, qs } from '../api'
import { BackLink, ErrorBox, ExtLink, Field, Highlight, Loading, MarkedText, PageHeader, TimeAgo, fmtDate, queryTerms, usePageTitle, useToast } from '../components/ui'
import { Sheet, useConfirm } from '../components/Sheet'
import { IconBookmark } from '../components/icons'
import {
  CONF_LABEL, FREQ_LABEL, META_SOURCE_LABEL, REGION_LABEL, fmtSize, reportsPath, useReportsMeta, type Report as R, type ReportDetail,
} from '../reports'
import { StatusPill, UploadForm } from './Reports'

const TABS = [['overview', 'Overview'], ['contents', 'Contents'], ['pages', 'Page text']] as const
type Tab = typeof TABS[number][0]

function useReport(id: string) {
  return useQuery({
    queryKey: ['report', id], queryFn: () => api.get<ReportDetail>(reportsPath(id)),
    refetchInterval: (q) => (['queued', 'processing'].includes(q.state.data?.report.status ?? '') ? 4000 : false),
  })
}

export default function Report() {
  const { id = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = (TABS.find(([k]) => k === params.get('tab'))?.[0] ?? 'overview') as Tab
  const q = useReport(id)
  usePageTitle(q.data?.report.title)
  const go = (t: Tab, extra?: Record<string, string>) => setParams(() => { const n = new URLSearchParams(); n.set('tab', t); Object.entries(extra ?? {}).forEach(([k, v]) => n.set(k, v)); return n }, { replace: true })
  if (q.isLoading) return <Loading />
  if (q.error || !q.data) return <><BackLink fallback="/reports" label="Reports library" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  const { report: r } = q.data
  return (
    <>
      <BackLink fallback="/reports" label="Reports library" />
      <PageHeader title={r.title} eyebrow={['Report', r.publisher, r.edition || r.published_on]} />
      <div className="tabs" role="tablist" aria-label="Report sections">
        {TABS.map(([k, label]) => (
          <button key={k} type="button" role="tab" id={`tab-${k}`} aria-selected={tab === k} aria-controls="rp-panel" tabIndex={tab === k ? 0 : -1}
            onClick={() => go(k)}
            onKeyDown={(e) => {
              const i = TABS.findIndex(([x]) => x === tab)
              const n = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i - 1 + TABS.length) % TABS.length : -1
              if (n >= 0) { e.preventDefault(); go(TABS[n][0]); document.getElementById(`tab-${TABS[n][0]}`)?.focus() }
            }}>{label}</button>
        ))}
      </div>
      <div id="rp-panel" role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {tab === 'overview' ? <Overview d={q.data} />
          : tab === 'contents' ? <Contents d={q.data} onPage={(p) => go('pages', { page: String(p) })} />
            : <Pages d={q.data} />}
      </div>
    </>
  )
}

function Prov({ r, k }: { r: R; k: string }) {
  const s = r.meta_source[k]
  return s ? <span className="rp-prov">{META_SOURCE_LABEL[s] ?? s}</span> : null
}

function Row({ label, children, r, k }: { label: string; children: ReactNode; r: R; k?: string }) {
  const empty = children === null || children === undefined || children === '' || (Array.isArray(children) && !children.length)
  return <><dt>{label}</dt><dd>{empty ? <span className="muted">Not recorded</span> : <>{children} {k && <Prov r={r} k={k} />}</>}</dd></>
}

function Overview({ d }: { d: ReportDetail }) {
  const r = d.report
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const confirm = useConfirm()
  const [sheet, setSheet] = useState<'edit' | 'upload' | null>(null)
  const refresh = () => { qc.invalidateQueries({ queryKey: ['report', String(r.id)] }); qc.invalidateQueries({ queryKey: ['reports'] }) }
  const act = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: unknown }) => api.post(`${reportsPath(r.id)}/${path}`, body),
    onSuccess: refresh,
    onError: (e) => toast(e instanceof ApiError ? e.message : 'That did not work', 'error'),
  })
  const link = useMutation({
    mutationFn: (sid: number) => api.patch(reportsPath(r.id), { source_id: sid }), onSuccess: refresh,
  })
  const busy = r.status === 'queued' || r.status === 'processing'
  const pm = r.pdf_meta
  return (
    <div className="stack">
      <section className="card" aria-labelledby="rp-status-h">
        <div className="row between top wrap">
          <h2 id="rp-status-h" className="rp-h">Processing</h2>
          <StatusPill status={r.status} />
        </div>
        {r.status === 'discovered' ? (
          <>
            <p className="small">This report is in the library by link only. Upload the PDF to extract its text.</p>
            <div className="row wrap">
              <button type="button" className="btn primary" onClick={() => setSheet('upload')}>Upload the PDF</button>
              {r.publication_url && <ExtLink href={r.publication_url} className="btn">Open publication page</ExtLink>}
            </div>
          </>
        ) : (
          <>
            {busy && <p className="small" role="status">Extracting text. This page updates when it finishes, usually within a minute.</p>}
            {r.status_detail && <p className={`small ${r.status === 'failed' ? 'rp-bad' : ''}`}>{r.status_detail}</p>}
            {r.extraction_confidence && !busy && (
              <p className="small mb-0">{CONF_LABEL[r.extraction_confidence]}: {r.text_pages} of {r.page_count} pages have readable text.
                {r.extraction_method && <span className="muted"> Method: {r.extraction_method}, version {r.extraction_version}.</span>}</p>
            )}
            <div className="row wrap rp-actions">
              <button type="button" className="btn small" disabled={busy} aria-busy={act.isPending} onClick={() => act.mutate({ path: 'reprocess' })}>Process again</button>
              <a className="btn small" href={`${reportsPath(r.id)}/file`} download>Download PDF</a>
              <button type="button" className="btn small" aria-pressed={r.review_status === 'reviewed'}
                onClick={() => act.mutate({ path: 'review', body: { review_status: r.review_status === 'reviewed' ? 'unreviewed' : 'reviewed' } })}>
                {r.review_status === 'reviewed' ? 'Reviewed' : 'Mark as reviewed'}</button>
              <button type="button" className={`btn small ${r.bookmarked ? 'on' : ''}`} aria-pressed={r.bookmarked}
                onClick={() => act.mutate({ path: 'bookmark', body: { on: !r.bookmarked } })}><IconBookmark filled={r.bookmarked} />{r.bookmarked ? 'Bookmarked' : 'Bookmark'}</button>
            </div>
          </>
        )}
      </section>

      {d.suggested_sources.length > 0 && (
        <div className="notice">
          <p className="mb-0">This may be an edition of a series in the registry. Linking it fills empty fields from the series and groups it with other editions.</p>
          <div className="row wrap rp-actions">
            {d.suggested_sources.map((s) => (
              <button key={s.id} type="button" className="btn small" aria-busy={link.isPending} onClick={() => link.mutate(s.id)}>Link to {s.publisher}, {s.series}</button>))}
          </div>
        </div>
      )}

      <section className="card" aria-labelledby="rp-details-h">
        <div className="row between top wrap">
          <h2 id="rp-details-h" className="rp-h">Details</h2>
          <button type="button" className="btn small" onClick={() => setSheet('edit')}>Edit details</button>
        </div>
        <dl className="kv">
          <Row label="Title" r={r} k="title">{r.title}</Row>
          <Row label="Publisher" r={r} k="publisher">{r.publisher}</Row>
          <Row label="Series" r={r} k="series">{d.source ? <Link to={`/reports/series#s-${d.source.id}`}>{d.source.publisher}, {d.source.series}</Link> : r.series}</Row>
          <Row label="Edition" r={r} k="edition">{r.edition}</Row>
          <Row label="Published" r={r} k="published_on">{r.published_on}</Row>
          <Row label="Reporting period" r={r} k="period_start">{r.period_start || r.period_end ? `${r.period_start ?? '?'} to ${r.period_end ?? '?'}` : null}</Row>
          <Row label="Frequency" r={r} k="frequency">{r.frequency ? FREQ_LABEL[r.frequency] : null}</Row>
          <Row label="Coverage" r={r} k="regions">{r.regions.map((x) => REGION_LABEL[x] ?? x).join(', ')}</Row>
          <Row label="Industries" r={r} k="industries">{r.industries.join(', ')}</Row>
          <Row label="Methodology" r={r} k="methodology">{r.methodology}</Row>
          <Row label="Sample" r={r} k="sample_size">{r.sample_size}</Row>
          <Row label="Publication page" r={r} k="publication_url">{r.publication_url && <ExtLink href={r.publication_url}>{new URL(r.publication_url).hostname}</ExtLink>}</Row>
          <Row label="Document link" r={r} k="document_url">{r.document_url && <ExtLink href={r.document_url}>{new URL(r.document_url).hostname}</ExtLink>}</Row>
          <Row label="Access and copyright" r={r} k="access_notes">{r.access_notes}</Row>
          <Row label="Notes" r={r} k="notes">{r.notes}</Row>
        </dl>
        <p className="xsmall muted mb-0 rp-gap">Fields marked "Not recorded" are unknown, not absent from the report. Methodology and sample matter when comparing statistics between reports.</p>
      </section>

      {r.has_document && (
        <section className="card" aria-labelledby="rp-doc-h">
          <h2 id="rp-doc-h" className="rp-h">Document</h2>
          <dl className="kv">
            <dt>File</dt><dd>{r.original_filename ?? 'Unnamed'} {r.file_size ? `(${fmtSize(r.file_size)})` : ''}</dd>
            <dt>Added</dt><dd>{fmtDate(r.retrieved_at)} by {r.retrieval === 'upload' ? 'upload' : r.retrieval}</dd>
            <dt>SHA-256</dt><dd className="mono">{r.sha256_prefix}…</dd>
            {pm.title && <><dt>PDF title</dt><dd>{pm.title}</dd></>}
            {pm.author && <><dt>PDF author</dt><dd>{pm.author}</dd></>}
            {pm.created && <><dt>PDF created</dt><dd>{pdfDate(pm.created)} <span className="rp-prov">Not necessarily the publication date</span></dd></>}
          </dl>
        </section>
      )}

      {d.jobs.length > 0 && (
        <section className="card" aria-labelledby="rp-jobs-h">
          <h2 id="rp-jobs-h" className="rp-h">Processing history</h2>
          <div className="table-wrap" tabIndex={0} role="region" aria-label="Processing history">
            <table className="ls-table">
              <thead><tr><th scope="col">Started</th><th scope="col">Result</th><th scope="col">Pages with text</th><th scope="col">Sections</th><th scope="col">Extractor</th></tr></thead>
              <tbody>{d.jobs.map((j) => (
                <tr key={j.id}><td><TimeAgo iso={j.started_at} /></td><td>{JOB_LABEL[j.status] ?? j.status}{j.detail && j.status === 'failed' ? `: ${j.detail}` : ''}</td>
                  <td>{j.pages != null ? `${j.text_pages} of ${j.pages}` : ''}</td><td>{j.sections ?? ''}</td><td>{j.extractor ? `${j.extractor} v${j.extractor_version}` : ''}</td></tr>))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {d.editions.length > 0 && (
        <section className="card" aria-labelledby="rp-ed-h">
          <h2 id="rp-ed-h" className="rp-h">Other editions in this series</h2>
          <ul className="rp-plain">{d.editions.map((e) => <li key={e.id}><Link to={`/reports/${e.id}`}>{e.title}</Link> <span className="xsmall muted">{e.edition ?? e.published_on}</span></li>)}</ul>
        </section>
      )}

      <div><button type="button" className="btn small danger" disabled={busy} onClick={async () => {
        if (await confirm({ title: `Delete ${r.title}?`, body: 'The stored PDF, its extracted text and its processing history are removed permanently.', confirmLabel: 'Delete report', danger: true })) {
          await api.del(reportsPath(r.id)); qc.invalidateQueries({ queryKey: ['reports'] }); nav('/reports')
        }
      }}>Delete report</button></div>

      {sheet === 'edit' && <Sheet title="Edit report details" onClose={() => setSheet(null)}><EditForm r={r} onDone={() => { setSheet(null); refresh() }} /></Sheet>}
      {sheet === 'upload' && <Sheet title="Upload the PDF" onClose={() => setSheet(null)}><UploadForm reportId={r.id} onDone={() => { setSheet(null); refresh() }} /></Sheet>}
    </div>
  )
}

const JOB_LABEL: Record<string, string> = { ok: 'Processed', needs_review: 'Needs review', failed: 'Failed', running: 'Running' }

function pdfDate(v: string) {
  const m = /^D:(\d{4})(\d{2})?(\d{2})?/.exec(v)
  return m ? [m[1], m[2], m[3]].filter(Boolean).join('-') : v
}

function EditForm({ r, onDone }: { r: R; onDone: () => void }) {
  const meta = useReportsMeta()
  const series = useQuery({ queryKey: ['report-sources'], queryFn: () => api.get<{ sources: { id: number; publisher: string; series: string }[] }>('/api/reports/sources') })
  const [v, setV] = useState({
    title: r.title, publisher: r.publisher ?? '', series: r.series ?? '', edition: r.edition ?? '', published_on: r.published_on ?? '',
    period_start: r.period_start ?? '', period_end: r.period_end ?? '', publication_url: r.publication_url ?? '', document_url: r.document_url ?? '',
    frequency: r.frequency ?? '', category: r.category ?? '', industries: r.industries.join(', '), methodology: r.methodology ?? '',
    sample_size: r.sample_size ?? '', access_notes: r.access_notes ?? '', notes: r.notes ?? '', source_id: r.source_id ? String(r.source_id) : '',
  })
  const [regions, setRegions] = useState<string[]>(r.regions)
  const [error, setError] = useState<string | null>(null)
  const s = (k: keyof typeof v) => ({ value: v[k], onChange: (e: { target: { value: string } }) => setV({ ...v, [k]: e.target.value }) })
  const save = useMutation({
    mutationFn: () => api.patch(reportsPath(r.id), {
      ...Object.fromEntries(Object.entries(v).map(([k, x]) => [k, x.trim() || null])),
      title: v.title.trim(), source_id: v.source_id ? Number(v.source_id) : null, regions,
      industries: v.industries.split(',').map((x) => x.trim()).filter(Boolean),
    }),
    onSuccess: onDone,
    onError: (e) => setError(e instanceof ApiError ? (e.status === 422 ? 'Check the dates (YYYY, YYYY-MM or YYYY-MM-DD) and links (https://…).' : e.message) : 'Could not save'),
  })
  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate() }}>
      <Field label="Title"><input className="input" required minLength={2} maxLength={200} {...s('title')} /></Field>
      <Field label="Series" hint="Groups editions of the same recurring report.">
        <select className="input" {...s('source_id')}>
          <option value="">Not linked</option>
          {series.data?.sources.map((x) => <option key={x.id} value={x.id}>{x.publisher}, {x.series}</option>)}
        </select>
      </Field>
      <div className="rp-grid">
        <Field label="Publisher"><input className="input" maxLength={120} {...s('publisher')} /></Field>
        <Field label="Series name"><input className="input" maxLength={160} {...s('series')} /></Field>
        <Field label="Edition" hint='For example "2026" or "Q3 2026".'><input className="input" maxLength={40} {...s('edition')} /></Field>
        <Field label="Published" hint="YYYY, YYYY-MM or YYYY-MM-DD"><input className="input" inputMode="numeric" {...s('published_on')} /></Field>
        <Field label="Reporting period start"><input className="input" inputMode="numeric" placeholder="YYYY-MM-DD" {...s('period_start')} /></Field>
        <Field label="Reporting period end"><input className="input" inputMode="numeric" placeholder="YYYY-MM-DD" {...s('period_end')} /></Field>
        <Field label="Frequency">
          <select className="input" {...s('frequency')}><option value="">Not set</option>{(meta.data?.frequencies ?? []).map((f) => <option key={f} value={f}>{FREQ_LABEL[f] ?? f}</option>)}</select>
        </Field>
        <Field label="Category">
          <select className="input" {...s('category')}><option value="">Not set</option>{Object.entries(meta.data?.categories ?? {}).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        </Field>
      </div>
      <fieldset className="choice-row">
        <legend className="field-label">Geographic coverage</legend>
        <div className="chips">
          {(meta.data?.regions ?? []).map((x) => (
            <button key={x} type="button" className={`chip ${regions.includes(x) ? 'on' : ''}`} aria-pressed={regions.includes(x)}
              onClick={() => setRegions(regions.includes(x) ? regions.filter((y) => y !== x) : [...regions, x])}>{REGION_LABEL[x] ?? x}</button>))}
        </div>
      </fieldset>
      <Field label="Industries" hint="Comma separated, as the report describes them."><input className="input" {...s('industries')} /></Field>
      <Field label="Methodology" hint="Where the data comes from: incident response engagements, customer telemetry, surveys, leak-site claims and so on.">
        <textarea className="input" rows={3} maxLength={4000} {...s('methodology')} />
      </Field>
      <Field label="Sample" hint='As the report states it, for example "1,100 incident response engagements".'><input className="input" maxLength={300} {...s('sample_size')} /></Field>
      <Field label="Publication page"><input className="input" type="url" inputMode="url" placeholder="https://" {...s('publication_url')} /></Field>
      <Field label="Document link"><input className="input" type="url" inputMode="url" placeholder="https://" {...s('document_url')} /></Field>
      <Field label="Access and copyright"><input className="input" maxLength={1000} placeholder="For example: registration required; no redistribution" {...s('access_notes')} /></Field>
      <Field label="Notes"><textarea className="input" rows={3} maxLength={10000} {...s('notes')} /></Field>
      {error && <p className="field-error" role="alert">{error}</p>}
      <div className="sheet-actions sheet-sticky">
        <button type="button" className="btn" onClick={onDone}>Cancel</button>
        <button type="submit" className="btn primary" aria-busy={save.isPending}>Save</button>
      </div>
    </form>
  )
}

function Contents({ d, onPage }: { d: ReportDetail; onPage: (p: number) => void }) {
  if (!d.pages.length) return <div className="notice">No text has been extracted yet.</div>
  if (!d.sections.length) return <div className="notice">This PDF has no bookmarks, so there is no table of contents. Use the page text view; every page keeps its page number.</div>
  return (
    <section className="card">
      <p className="xsmall muted">From the PDF's own bookmarks. Page numbers are physical pages in the file, which can differ from the numbers printed on the page.</p>
      <ol className="rp-toc">
        {d.sections.map((s) => (
          <li key={s.ord} style={{ paddingInlineStart: `${(s.level - 1) * 16}px` }}>
            <button type="button" className="rp-toc-item" onClick={() => onPage(s.page_start)}>
              <span>{s.title}</span><span className="xsmall muted nowrap">{s.page_start === s.page_end ? `p. ${s.page_start}` : `pp. ${s.page_start} to ${s.page_end}`}</span>
            </button>
          </li>))}
      </ol>
    </section>
  )
}

function Pages({ d }: { d: ReportDetail }) {
  const id = d.report.id
  const [params, setParams] = useSearchParams()
  const total = d.pages.length
  const page = Math.min(Math.max(1, Number(params.get('page')) || 1), Math.max(1, total))
  const find = params.get('find') ?? ''
  const [text, setText] = useState(find)
  const set = (patch: Record<string, string>) => setParams((p) => { const n = new URLSearchParams(p); n.set('tab', 'pages'); Object.entries(patch).forEach(([k, v]) => v ? n.set(k, v) : n.delete(k)); return n }, { replace: true })
  const pq = useQuery({ queryKey: ['report-page', id, page], queryFn: () => api.get<{ pages: { page_no: number; label: string | null; text: string }[] }>(`${reportsPath(id)}/pages${qs({ start: page, count: 1 })}`), enabled: total > 0 })
  const sq = useQuery({ queryKey: ['report-search', id, find], queryFn: () => api.get<{ results: { page_no: number; label: string | null; snip: string }[] }>(`${reportsPath(id)}/search${qs({ q: find })}`), enabled: !!find })
  if (!total) return <div className="notice">No text has been extracted yet.</div>
  const p = pq.data?.pages[0]
  const sec = [...d.sections].reverse().find((s) => s.page_start <= page)
  return (
    <div className="rp-pages">
      <aside className="rp-find">
        <form role="search" className="rp-search" onSubmit={(e) => { e.preventDefault(); set({ find: text.trim() }) }}>
          <label className="sr-only" htmlFor="rp-find">Search this report</label>
          <input id="rp-find" className="input" type="search" placeholder="Search this report" value={text} onChange={(e) => { setText(e.target.value); if (!e.target.value) set({ find: '' }) }} />
          <button type="submit" className="btn">Find</button>
        </form>
        {find && (sq.isLoading ? <Loading lines={2} /> : (
          <>
            <p className="xsmall muted" role="status">{sq.data?.results.length ? `${sq.data.results.length} page${sq.data.results.length === 1 ? '' : 's'} match` : 'No pages match.'}</p>
            <ul className="rp-hits">{sq.data?.results.map((h) => (
              <li key={h.page_no}><button type="button" className={`rp-hit ${h.page_no === page ? 'on' : ''}`} aria-current={h.page_no === page || undefined} onClick={() => set({ page: String(h.page_no) })}>
                <span className="xsmall rp-hit-page">Page {h.page_no}{h.label ? ` (printed ${h.label})` : ''}</span><span className="small"><MarkedText text={h.snip} /></span>
              </button></li>))}
            </ul>
          </>
        ))}
      </aside>
      <section className="card rp-page-card" aria-labelledby="rp-page-h">
        <div className="row between wrap rp-pager">
          <h2 id="rp-page-h" className="rp-h">Page {page} of {total}{p?.label ? <span className="xsmall muted"> (printed {p.label})</span> : null}</h2>
          <div className="row wrap">
            <button type="button" className="btn small" disabled={page <= 1} onClick={() => set({ page: String(page - 1) })}>Previous</button>
            <GotoPage key={page} page={page} total={total} onGo={(n) => set({ page: String(n) })} />
            <button type="button" className="btn small" disabled={page >= total} onClick={() => set({ page: String(page + 1) })}>Next</button>
          </div>
        </div>
        {sec && <p className="xsmall muted mb-0">Section: {sec.title}</p>}
        {pq.isLoading ? <Loading /> : p && p.text ? (
          <div className="rp-text" tabIndex={0} aria-label={`Text of page ${page}`}><Highlight text={p.text} terms={queryTerms(find)} /></div>
        ) : <p className="notice">No text on this page. It may be an image, chart or blank page.</p>}
        <p className="xsmall muted mb-0">Extracted text, shown as plain text. Layout, charts and images are not reproduced; check the PDF for figures.</p>
      </section>
    </div>
  )
}

/** Keyed by the current page, so it resets when the page changes. */
function GotoPage({ page, total, onGo }: { page: number; total: number; onGo: (n: number) => void }) {
  const [v, setV] = useState(String(page))
  return (
    <form className="row" onSubmit={(e) => { e.preventDefault(); const n = Number(v); if (n >= 1 && n <= total) onGo(n) }}>
      <label className="sr-only" htmlFor="rp-goto">Go to page</label>
      <input id="rp-goto" className="input rp-goto" inputMode="numeric" value={v} onChange={(e) => setV(e.target.value.replace(/\D/g, ''))} />
      <button type="submit" className="btn small">Go</button>
    </form>
  )
}
