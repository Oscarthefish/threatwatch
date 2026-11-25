import { useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, qs } from '../api'
import { Empty, ErrorBox, Field, Loading, NoResults, PageHeader, usePageTitle } from '../components/ui'
import { Sheet } from '../components/Sheet'
import {
  REGION_LABEL, STATUS_GROUPS, STATUS_LABEL, STATUS_TONE, uploadReport, useReportsMeta, type ReportRow, type ReportStatus,
} from '../reports'

export function StatusPill({ status }: { status: ReportStatus }) {
  return <span className={`rp-status ${STATUS_TONE[status]}`}>{STATUS_LABEL[status]}</span>
}

/** Choose a PDF and upload it. Used for new reports and for attaching a document to an awaiting one. */
export function UploadForm({ reportId, onDone }: { reportId?: number; onDone: (id?: number) => void }) {
  const meta = useReportsMeta()
  const qc = useQueryClient()
  const input = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dupe, setDupe] = useState<number | null>(null)
  const max = meta.data?.max_mb ?? 50
  const send = useMutation({
    mutationFn: () => uploadReport(file!, reportId),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ['reports'] }); qc.invalidateQueries({ queryKey: ['report'] }); onDone(r.id) },
    onError: (e) => {
      const msg = e instanceof ApiError ? e.message : 'The upload failed.'
      setError(msg)
      const m = /report (\d+)/.exec(msg)
      setDupe(e instanceof ApiError && e.status === 409 && m ? Number(m[1]) : null)
    },
  })
  return (
    <form className="stack" onSubmit={(e) => {
      e.preventDefault(); setError(null); setDupe(null)
      if (!file) { setError('Choose a PDF first.'); return }
      if (file.size > max * 1048576) { setError(`The file is larger than ${max} MB.`); return }
      send.mutate()
    }}>
      <Field label="PDF document" hint={`Up to ${max} MB. Threat Watch stores the file on your server and reads its text layer. It never opens links or runs anything inside the document.`}>
        <input ref={input} className="input rp-file" type="file" accept="application/pdf,.pdf" required
          onChange={(e) => { setFile(e.target.files?.[0] ?? null); setError(null); setDupe(null) }} />
      </Field>
      <p className="xsmall muted mb-0">Only upload reports you are allowed to keep. Extracted text stays private to this server; exports quote short, attributed findings rather than the whole report.</p>
      {error && <p className="field-error" role="alert">{error} {dupe && <Link to={`/reports/${dupe}`} onClick={() => onDone()}>Open the existing report</Link>}</p>}
      <div className="sheet-actions sheet-sticky">
        <button type="button" className="btn" onClick={() => onDone()}>Cancel</button>
        <button type="submit" className="btn primary" aria-busy={send.isPending} disabled={send.isPending}>{send.isPending ? 'Uploading' : 'Upload'}</button>
      </div>
    </form>
  )
}

function LinkForm({ onDone }: { onDone: (id?: number) => void }) {
  const qc = useQueryClient()
  const [title, setTitle] = useState('')
  const [publisher, setPublisher] = useState('')
  const [url, setUrl] = useState('')
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => api.post<{ id: number }>('/api/reports', { title, publisher: publisher || null, publication_url: url || null }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ['reports'] }); onDone(r.id) },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'Could not save'),
  })
  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate() }}>
      <p className="small muted mb-0">For a report you know about but have not downloaded yet, for example one behind a registration form. It waits in the library until you upload the PDF.</p>
      <Field label="Title"><input className="input" required minLength={2} maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} autoFocus /></Field>
      <Field label="Publisher (optional)"><input className="input" maxLength={120} value={publisher} onChange={(e) => setPublisher(e.target.value)} /></Field>
      <Field label="Publication page (optional)" hint="Saved as a link only. Threat Watch does not visit it.">
        <input className="input" type="url" inputMode="url" placeholder="https://" value={url} onChange={(e) => setUrl(e.target.value)} />
      </Field>
      {error && <p className="field-error" role="alert">{error}</p>}
      <div className="sheet-actions sheet-sticky">
        <button type="button" className="btn" onClick={() => onDone()}>Cancel</button>
        <button type="submit" className="btn primary" aria-busy={save.isPending}>Add report</button>
      </div>
    </form>
  )
}

export default function Reports() {
  usePageTitle('Reports library')
  const nav = useNavigate()
  const [params, setParams] = useSearchParams()
  const [sheet, setSheet] = useState<'upload' | 'link' | null>(null)
  const [text, setText] = useState(params.get('q') ?? '')
  const meta = useReportsMeta()
  const f = { q: params.get('q') ?? '', status: params.get('status') ?? '', publisher: params.get('publisher') ?? '',
    category: params.get('category') ?? '', region: params.get('region') ?? '', bookmarked: params.get('saved') === '1', sort: params.get('sort') ?? 'published' }
  const set = (k: string, v: string) => setParams((p) => { const n = new URLSearchParams(p); if (v) n.set(k, v); else n.delete(k); return n }, { replace: true })
  const q = useQuery({
    queryKey: ['reports', f],
    queryFn: () => api.get<{ reports: ReportRow[]; counts: Record<string, number>; total: number; publishers: string[] }>(
      '/api/reports' + qs({ q: f.q, status: f.status, publisher: f.publisher, category: f.category, region: f.region, bookmarked: f.bookmarked || undefined, sort: f.sort })),
    refetchInterval: (query) => (query.state.data?.reports.some((r) => r.status === 'queued' || r.status === 'processing') ? 5000 : false),
  })
  const filtered = !!(f.q || f.status || f.publisher || f.category || f.region || f.bookmarked)
  const counts = q.data?.counts
  return (
    <>
      <PageHeader title="Reports library" eyebrow={['Intelligence']}
        sub="Annual, quarterly and specialist threat reports from vendors, incident responders and government agencies, kept by edition with page-level text so findings can always be traced to the page they came from."
        actions={<>
          <Link to="/reports/series" className="btn">Report series</Link>
          <button type="button" className="btn primary" onClick={() => setSheet('upload')}>Upload report</button>
        </>} />
      <div className="filters">
        <form role="search" className="rp-search" onSubmit={(e) => { e.preventDefault(); set('q', text.trim()) }}>
          <label className="sr-only" htmlFor="rp-q">Search reports and their text</label>
          <input id="rp-q" className="input" type="search" placeholder="Search titles, publishers and report text" value={text}
            onChange={(e) => { setText(e.target.value); if (!e.target.value) set('q', '') }} />
          <button type="submit" className="btn">Search</button>
        </form>
        <div className="chips scroll" role="group" aria-label="Processing status">
          {STATUS_GROUPS.map(([v, l]) => (
            <button type="button" key={v || 'all'} className={`chip ${f.status === v ? 'on' : ''}`} aria-pressed={f.status === v} onClick={() => set('status', v)}>
              {l}{counts && v ? ` (${counts[v] ?? 0})` : counts ? ` (${q.data?.total ?? 0})` : ''}
            </button>))}
        </div>
        <div className="selects rp-selects">
          <label>Publisher
            <select className="input" value={f.publisher} onChange={(e) => set('publisher', e.target.value)}>
              <option value="">Any</option>{q.data?.publishers.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label>Category
            <select className="input" value={f.category} onChange={(e) => set('category', e.target.value)}>
              <option value="">Any</option>{Object.entries(meta.data?.categories ?? {}).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label>Coverage
            <select className="input" value={f.region} onChange={(e) => set('region', e.target.value)}>
              <option value="">Any</option>{(meta.data?.regions ?? []).map((r) => <option key={r} value={r}>{REGION_LABEL[r] ?? r}</option>)}
            </select>
          </label>
          <label>Sort
            <select className="input" value={f.sort} onChange={(e) => set('sort', e.target.value === 'published' ? '' : e.target.value)}>
              <option value="published">Publication date</option><option value="added">Date added</option><option value="title">Title</option>
            </select>
          </label>
        </div>
        <label className="rp-check"><input type="checkbox" checked={f.bookmarked} onChange={(e) => set('saved', e.target.checked ? '1' : '')} /> Bookmarked only</label>
      </div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : !q.data?.total ? (
        <Empty title="No reports yet">
          <p>Upload a threat report PDF to start the library. Threat Watch extracts its text page by page so later findings can cite the exact page.</p>
          <div className="row wrap">
            <button type="button" className="btn primary" onClick={() => setSheet('upload')}>Upload report</button>
            <button type="button" className="btn" onClick={() => setSheet('link')}>Add a report by link</button>
          </div>
        </Empty>
      ) : !q.data.reports.length ? <NoResults filtered={filtered} onClear={() => { setText(''); setParams({}, { replace: true }) }} /> : (
        <>
          <ul className="rp-list" role="list">
            {q.data.reports.map((r) => (
              <li key={r.id}>
                <Link to={`/reports/${r.id}${r.match && f.q ? `?tab=pages&page=${r.match.first_page}&find=${encodeURIComponent(f.q)}` : ''}`} className="rp-card">
                  <div className="row between top">
                    <h2 className="rp-card-title">{r.title}</h2>
                    <StatusPill status={r.status} />
                  </div>
                  <p className="xsmall muted mb-0">
                    {[r.publisher, r.series, r.edition, r.published_on, r.page_count ? `${r.page_count} pages` : null,
                      r.regions.length ? r.regions.map((x) => REGION_LABEL[x] ?? x).join(', ') : null].filter(Boolean).join(' · ') || 'No details yet'}
                    {r.bookmarked && ' · Bookmarked'}
                  </p>
                  {r.match && <p className="xsmall mb-0 rp-match">Text matches on {r.match.pages} page{r.match.pages === 1 ? '' : 's'}, first on page {r.match.first_page}</p>}
                </Link>
              </li>
            ))}
          </ul>
          <button type="button" className="btn small" onClick={() => setSheet('link')}>Add a report by link</button>
        </>
      )}
      {sheet === 'upload' && <Sheet title="Upload report" onClose={() => setSheet(null)}><UploadForm onDone={(id) => { setSheet(null); if (id) nav(`/reports/${id}`) }} /></Sheet>}
      {sheet === 'link' && <Sheet title="Add a report by link" onClose={() => setSheet(null)}><LinkForm onDone={(id) => { setSheet(null); if (id) nav(`/reports/${id}`) }} /></Sheet>}
    </>
  )
}
