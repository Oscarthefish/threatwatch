import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../api'
import { BackLink, ErrorBox, ExtLink, Field, Loading, PageHeader, fmtDate, usePageTitle } from '../components/ui'
import { Sheet, useConfirm } from '../components/Sheet'
import { FREQ_LABEL, REGION_LABEL, useReportsMeta, type Source } from '../reports'

const PRIORITY: Record<number, string> = { 1: 'Priority 1: operational and frontline', 2: 'Priority 2: threat landscape and industry', 3: 'Priority 3: specialist', 4: 'Priority 4: regional and government' }

function SourceForm({ s, onDone }: { s?: Source; onDone: () => void }) {
  const meta = useReportsMeta()
  const qc = useQueryClient()
  const [v, setV] = useState({ publisher: s?.publisher ?? '', series: s?.series ?? '', page_url: s?.page_url ?? '', frequency: s?.frequency ?? 'unknown',
    category: s?.category ?? '', region: s?.region ?? 'GLOBAL', priority: String(s?.priority ?? 2), access_notes: s?.access_notes ?? '', notes: s?.notes ?? '' })
  const [verified, setVerified] = useState(!!s?.verified_at)
  const [error, setError] = useState<string | null>(null)
  const f = (k: keyof typeof v) => ({ value: v[k], onChange: (e: { target: { value: string } }) => setV({ ...v, [k]: e.target.value }) })
  const save = useMutation({
    mutationFn: () => {
      const body = { ...v, page_url: v.page_url.trim() || null, category: v.category || null, priority: Number(v.priority),
        access_notes: v.access_notes.trim() || null, notes: v.notes.trim() || null, verified }
      return s ? api.patch(`/api/reports/sources/${s.id}`, body) : api.post('/api/reports/sources', body)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['report-sources'] }); onDone() },
    onError: (e) => setError(e instanceof ApiError ? (e.status === 422 ? 'Check the page link (https://…).' : e.message) : 'Could not save'),
  })
  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate() }}>
      <div className="rp-grid">
        <Field label="Publisher"><input className="input" required minLength={2} maxLength={120} {...f('publisher')} autoFocus /></Field>
        <Field label="Series"><input className="input" required minLength={2} maxLength={160} {...f('series')} /></Field>
      </div>
      <Field label="Official publication page" hint="The publisher's own page for this report series. Saved as a link; nothing is fetched yet.">
        <input className="input" type="url" inputMode="url" placeholder="https://" {...f('page_url')} />
      </Field>
      <div className="rp-grid">
        <Field label="Expected frequency">
          <select className="input" {...f('frequency')}>{(meta.data?.frequencies ?? ['unknown']).map((x) => <option key={x} value={x}>{FREQ_LABEL[x] ?? x}</option>)}</select>
        </Field>
        <Field label="Category">
          <select className="input" {...f('category')}><option value="">Not set</option>{Object.entries(meta.data?.categories ?? {}).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        </Field>
        <Field label="Region">
          <select className="input" {...f('region')}>{(meta.data?.regions ?? ['GLOBAL']).map((x) => <option key={x} value={x}>{REGION_LABEL[x] ?? x}</option>)}</select>
        </Field>
        <Field label="Priority">
          <select className="input" {...f('priority')}>{[1, 2, 3, 4].map((n) => <option key={n} value={n}>{n}</option>)}</select>
        </Field>
      </div>
      <Field label="Access restrictions" hint="For example a registration form, or terms that forbid redistribution."><input className="input" maxLength={1000} {...f('access_notes')} /></Field>
      <Field label="Notes"><textarea className="input" rows={2} maxLength={4000} {...f('notes')} /></Field>
      <label className="rp-check"><input type="checkbox" checked={verified} onChange={(e) => setVerified(e.target.checked)} /> I have checked the publication page, report name and frequency</label>
      {error && <p className="field-error" role="alert">{error}</p>}
      <div className="sheet-actions sheet-sticky">
        <button type="button" className="btn" onClick={onDone}>Cancel</button>
        <button type="submit" className="btn primary" aria-busy={save.isPending}>{s ? 'Save' : 'Add series'}</button>
      </div>
    </form>
  )
}

export default function ReportSources() {
  usePageTitle('Report series')
  const qc = useQueryClient()
  const confirm = useConfirm()
  const [edit, setEdit] = useState<Source | 'new' | null>(null)
  const q = useQuery({ queryKey: ['report-sources'], queryFn: () => api.get<{ sources: Source[] }>('/api/reports/sources') })
  const del = useMutation({ mutationFn: (id: number) => api.del(`/api/reports/sources/${id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['report-sources'] }) })
  const groups = [1, 2, 3, 4].map((p) => [p, (q.data?.sources ?? []).filter((s) => s.priority === p)] as const).filter(([, l]) => l.length)
  return (
    <>
      <BackLink fallback="/reports" label="Reports library" />
      <PageHeader title="Report series" eyebrow={['Intelligence', 'Reports library']}
        sub="Recurring reports worth keeping, by publisher. The built-in list is a starting point: names, frequencies and pages are unverified until you check them."
        actions={<button type="button" className="btn primary" onClick={() => setEdit('new')}>Add series</button>} />
      <div className="notice">Automatic discovery of new editions is not switched on yet. For now, download a report from the publisher and upload it, or add it by link and upload it later.</div>
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : groups.map(([p, list]) => (
        <section key={p} aria-labelledby={`rs-${p}`} className="rp-section">
          <h2 id={`rs-${p}`} className="rp-h">{PRIORITY[p] ?? `Priority ${p}`}</h2>
          <ul className="rp-series" role="list">
            {list.map((s) => (
              <li key={s.id} id={`s-${s.id}`} className="rp-series-row">
                <div className="grow">
                  <p className="mb-0"><strong>{s.publisher}</strong>, {s.series}</p>
                  <p className="xsmall muted mb-0">
                    {FREQ_LABEL[s.frequency] ?? s.frequency}{s.verified_at ? '' : ' (unverified)'} · {REGION_LABEL[s.region] ?? s.region}
                    {s.reports ? ` · ${s.reports} report${s.reports === 1 ? '' : 's'}, latest ${s.latest}` : ' · No reports yet'}
                    {s.verified_at && ` · Checked ${fmtDate(s.verified_at)}`}
                  </p>
                  {s.page_url && <p className="xsmall mb-0"><ExtLink href={s.page_url}>{new URL(s.page_url).hostname}</ExtLink></p>}
                  {s.notes && <p className="xsmall muted mb-0">{s.notes}</p>}
                  {s.access_notes && <p className="xsmall muted mb-0">Access: {s.access_notes}</p>}
                </div>
                <div className="row wrap rp-series-actions">
                  <button type="button" className="btn small" onClick={() => setEdit(s)} aria-label={`Edit ${s.publisher}, ${s.series}`}>Edit</button>
                  <button type="button" className="btn small quiet" aria-label={`Remove ${s.publisher}, ${s.series}`} onClick={async () => {
                    if (await confirm({ title: `Remove ${s.series}?`, body: 'Reports already in the library keep their details; they are no longer grouped under this series.', confirmLabel: 'Remove series', danger: true })) del.mutate(s.id)
                  }}>Remove</button>
                </div>
              </li>))}
          </ul>
        </section>
      ))}
      {edit && <Sheet title={edit === 'new' ? 'Add report series' : 'Edit report series'} onClose={() => setEdit(null)}>
        <SourceForm s={edit === 'new' ? undefined : edit} onDone={() => setEdit(null)} /></Sheet>}
    </>
  )
}
