import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api'
import { ErrorBox, ExtLink, Field, Loading, TimeAgo, techniqueUrl, useToast } from '../ui'
import { useConfirm } from '../Sheet'
import { PageLink } from './Summary'
import {
  EVIDENCE_HELP, ORIGIN_LABEL, REGION_LABEL, findingsPath, useFindings, RUN_ACTIVE, type Finding, type FindingDraft, type FindingsResponse,
} from '../../reports'

const usd = (n: number | null | undefined) => `US$${(n ?? 0).toFixed(2)}`

const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

/** Add or edit a finding. The quote is checked against the page by the server; nothing is saved otherwise. */
export function FindingForm({ reportId, draft, existing, onDone }: { reportId: number; draft?: FindingDraft; existing?: Finding; onDone: () => void }) {
  const qc = useQueryClient()
  const meta = useFindings(reportId)
  const cats = meta.data?.categories ?? {}
  const evid = meta.data?.evidence ?? {}
  const [v, setV] = useState({
    page: String(existing?.page_no ?? draft?.page ?? 1), quote: existing?.quote ?? draft?.quote ?? '', title: existing?.title ?? draft?.title ?? '',
    summary: existing?.summary ?? '', category: existing?.category ?? draft?.category ?? '', evidence_type: existing?.evidence_type ?? draft?.evidence_type ?? '',
    techniques: (existing?.techniques ?? []).map((t) => t.id).join(', '), cves: (existing?.cves ?? []).join(', '),
    actors: (existing?.actors ?? []).join(', '), technologies: (existing?.technologies ?? []).join(', '), sectors: (existing?.sectors ?? []).join(', '),
    confidence: existing?.confidence ?? '', notes: existing?.notes ?? '',
    s_value: existing?.statistic?.value ?? '', s_population: existing?.statistic?.population ?? '', s_period: existing?.statistic?.period ?? '', s_definition: existing?.statistic?.definition ?? '',
  })
  const [regions, setRegions] = useState<string[]>(existing?.regions ?? [])
  const [error, setError] = useState<string | null>(null)
  const [onPage, setOnPage] = useState<boolean | null>(null)
  const f = (k: keyof typeof v) => ({ value: v[k], onChange: (e: { target: { value: string } }) => setV((o) => ({ ...o, [k]: e.target.value })) })
  // prefill what the rules can see in a new passage (IDs, CVEs, names); never overwrite what is already typed
  useEffect(() => {
    if (existing || !draft?.quote) return
    let live = true
    api.post<{ on_page: boolean; techniques: { id: string }[]; cves: string[]; actors: string[]; technologies: string[]; statistic: boolean }>(
      `${findingsPath(reportId)}/suggest`, { page: draft.page, quote: draft.quote }).then((s) => {
      if (!live) return
      setOnPage(s.on_page)
      setV((o) => ({
        ...o, techniques: o.techniques || s.techniques.map((t) => t.id).join(', '), cves: o.cves || s.cves.join(', '),
        actors: o.actors || s.actors.join(', '), technologies: o.technologies || s.technologies.join(', '),
        category: o.category || (s.statistic ? 'statistical_trend' : ''), evidence_type: o.evidence_type || (s.statistic ? 'aggregate_statistic' : ''),
      }))
    }).catch(() => { /* prefill is optional */ })
    return () => { live = false }
  }, [existing, draft, reportId])
  const showStat = v.evidence_type === 'aggregate_statistic' || v.category === 'statistical_trend' || !!v.s_value
  const save = useMutation({
    mutationFn: () => {
      const body = {
        page: Number(v.page), quote: v.quote, title: v.title, summary: v.summary || null, category: v.category, evidence_type: v.evidence_type,
        techniques: split(v.techniques), cves: split(v.cves), actors: split(v.actors), technologies: split(v.technologies), sectors: split(v.sectors), regions,
        statistic: showStat && v.s_value ? { value: v.s_value, population: v.s_population, period: v.s_period, definition: v.s_definition } : null,
        confidence: v.confidence || null, notes: v.notes || null,
      }
      return existing ? api.patch(`${findingsPath(reportId)}/${existing.id}`, body) : api.post(findingsPath(reportId), { ...body, origin: draft?.origin ?? 'analyst' })
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['findings', reportId] }); onDone() },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'Could not save'),
  })
  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate() }}>
      <div className="rp-grid">
        <Field label="Page"><input className="input" inputMode="numeric" required {...f('page')} /></Field>
        <Field label="Confidence" hint="How clearly the passage supports it.">
          <select className="input" {...f('confidence')}><option value="">Not set</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
        </Field>
      </div>
      <Field label="Quote" hint={onPage === false ? 'This text was not found on that page. Copy the passage exactly as the report has it.' : 'The passage exactly as the report has it, up to 600 characters. It is checked against the page.'}>
        <textarea className="input" rows={4} maxLength={600} required {...f('quote')} aria-invalid={onPage === false || undefined} />
      </Field>
      <Field label="Title"><input className="input" required minLength={3} maxLength={200} {...f('title')} autoFocus={!existing} /></Field>
      <Field label="Summary (optional)" hint="One or two sentences in your words, adding nothing the passage does not say."><textarea className="input" rows={2} maxLength={1200} {...f('summary')} /></Field>
      <div className="rp-grid">
        <Field label="Category">
          <select className="input" required {...f('category')}><option value="">Choose</option>{Object.entries(cats).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        </Field>
        <Field label="Evidence type" hint={EVIDENCE_HELP[v.evidence_type]}>
          <select className="input" required {...f('evidence_type')}><option value="">Choose</option>{Object.entries(evid).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
        </Field>
      </div>
      {showStat && (
        <fieldset className="rp-fieldset">
          <legend className="field-label">The figure, as the report states it</legend>
          <p className="xsmall muted mb-0">Leave a field empty when the report does not say. Figures from different reports are never added together.</p>
          <div className="rp-grid">
            <Field label="Value"><input className="input" placeholder="for example 30%" {...f('s_value')} /></Field>
            <Field label="Of what (population)"><input className="input" placeholder="for example IR engagements" {...f('s_population')} /></Field>
            <Field label="Period"><input className="input" placeholder="for example 2025" {...f('s_period')} /></Field>
            <Field label="What was measured"><input className="input" {...f('s_definition')} /></Field>
          </div>
        </fieldset>
      )}
      <Field label="ATT&CK techniques" hint="IDs, comma separated. Checked against ATT&CK v20.1; unknown IDs are dropped. An ID printed on the page counts as the publisher's mapping, otherwise as yours.">
        <input className="input" placeholder="T1539, T1550.004" {...f('techniques')} />
      </Field>
      <div className="rp-grid">
        <Field label="CVEs" hint="Kept only if the page states them."><input className="input" {...f('cves')} /></Field>
        <Field label="Threat actors"><input className="input" {...f('actors')} /></Field>
        <Field label="Technologies"><input className="input" {...f('technologies')} /></Field>
        <Field label="Sectors"><input className="input" {...f('sectors')} /></Field>
      </div>
      <fieldset className="choice-row">
        <legend className="field-label">Regions the passage names</legend>
        <div className="chips">{['GLOBAL', 'NZ', 'AU', 'APAC', 'US', 'UK', 'EU', 'OTHER'].map((r) => (
          <button key={r} type="button" className={`chip ${regions.includes(r) ? 'on' : ''}`} aria-pressed={regions.includes(r)}
            onClick={() => setRegions(regions.includes(r) ? regions.filter((x) => x !== r) : [...regions, r])}>{REGION_LABEL[r] ?? 'Other'}</button>))}
        </div>
      </fieldset>
      <Field label="Notes (optional)"><textarea className="input" rows={2} maxLength={4000} {...f('notes')} /></Field>
      {error && <p className="field-error" role="alert">{error}</p>}
      <div className="sheet-actions sheet-sticky">
        <button type="button" className="btn" onClick={onDone}>Cancel</button>
        <button type="submit" className="btn primary" aria-busy={save.isPending}>{existing ? 'Save and accept' : 'Save finding'}</button>
      </div>
    </form>
  )
}

function AIPanel({ reportId, data }: { reportId: number; data: FindingsResponse }) {
  const qc = useQueryClient()
  const toast = useToast()
  const confirm = useConfirm()
  const a = data.ai
  const live = data.runs.find((r) => RUN_ACTIVE.has(r.status))
  const last = data.runs.find((r) => !RUN_ACTIVE.has(r.status))
  const go = useMutation({
    mutationFn: () => api.post(`/api/reports/${reportId}/ai/run`, { confirm_usd: a.estimate_usd }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', reportId] }),
    onError: (e) => toast(e instanceof ApiError ? e.message : 'Could not start', 'error'),
  })
  const stop = useMutation({ mutationFn: () => api.post(`/api/reports/${reportId}/ai/cancel`), onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', reportId] }) })
  if (!a.enabled) return <div className="notice">AI extraction is not set up on this server. You can still add findings from the Summary, from selected text in Read, or by hand.</div>
  const left = Math.max(0, a.month_budget_usd - a.month_spent_usd)
  return (
    <section className="card" aria-labelledby="rp-ai-h">
      <h2 id="rp-ai-h" className="rp-h">Extract findings with AI</h2>
      {live ? (
        <div role="status">
          <p className="small mb-0">{live.status === 'queued' ? 'Starting.' : `Reading section ${Math.min(live.chunks_done + 1, live.chunks)} of ${live.chunks}.`} {live.kept} finding{live.kept === 1 ? '' : 's'} kept so far, {usd(live.cost_usd)} spent.</p>
          <button type="button" className="btn small rp-gap" onClick={() => stop.mutate()}>Stop</button>
        </div>
      ) : (
        <>
          <p className="small">Sends this report's extracted text to {a.model.includes('haiku') ? 'Claude Haiku' : 'Claude Sonnet'}, one section at a time ({a.chunks} section{a.chunks === 1 ? '' : 's'}, {a.pages} pages). Product guidance and figure labels are left out. Nothing else is sent: not your profiles, notes or other reports. Each proposed finding is kept only if its quote is found on the page it cites.</p>
          <p className="small mb-0">About <strong>{usd(a.estimate_usd)}</strong>, never more than {usd(Math.min(a.cap_usd, left))}. Report AI this month: {usd(a.month_spent_usd)} of {usd(a.month_budget_usd)}, separate from the daily news budget.</p>
          <button type="button" className="btn primary rp-gap" disabled={left < Math.min(a.estimate_usd, a.cap_usd) || go.isPending} aria-busy={go.isPending}
            onClick={async () => { if (await confirm({ title: `Spend about ${usd(a.estimate_usd)}?`, body: `The report text goes to Anthropic's API in ${a.chunks} request${a.chunks === 1 ? '' : 's'}. The run stops before it could pass ${usd(Math.min(a.cap_usd, left))}. Findings arrive unreviewed.`, confirmLabel: 'Extract findings' })) go.mutate() }}>
            Extract findings (about {usd(a.estimate_usd)})</button>
        </>
      )}
      {last && !live && (
        <p className="xsmall muted mb-0 rp-gap">Last run <TimeAgo iso={last.finished_at ?? last.created_at} />: {RUN_LABEL[last.status] ?? last.status}{last.detail ? ` (${last.detail})` : ''}. {last.kept} kept, {last.rejected} discarded because the quote was not on the page or a value was invalid. Cost {usd(last.cost_usd)}.</p>
      )}
    </section>
  )
}
const RUN_LABEL: Record<string, string> = { done: 'finished', stopped: 'stopped at the cost cap', failed: 'failed', cancelled: 'stopped' }

function FindingCard({ f, reportId, cats, evid, onEdit }: { f: Finding; reportId: number; cats: Record<string, string>; evid: Record<string, string>; onEdit: () => void }) {
  const qc = useQueryClient()
  const confirm = useConfirm()
  const set = useMutation({
    mutationFn: (review_status: string) => api.patch(`${findingsPath(reportId)}/${f.id}`, { review_status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', reportId] }),
  })
  const del = useMutation({ mutationFn: () => api.del(`${findingsPath(reportId)}/${f.id}`), onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', reportId] }) })
  const status = f.review_status === 'unreviewed' ? (f.origin === 'ai' ? 'AI, not yet reviewed' : 'Not yet reviewed') : f.review_status === 'accepted' ? (f.origin === 'ai' ? (f.edited ? 'AI, edited and accepted' : 'AI, accepted by you') : ORIGIN_LABEL[f.origin]) : 'Rejected'
  return (
    <article className={`card rp-finding ${f.review_status}`} aria-labelledby={`f-${f.id}`}>
      <div className="row between top wrap">
        <h3 id={`f-${f.id}`} className="rp-f-title">{f.title}</h3>
        <span className={`rp-status ${f.review_status === 'accepted' ? 'good' : f.review_status === 'rejected' ? 'bad' : 'neutral'}`}>{status}</span>
      </div>
      <p className="xsmall muted mb-0">{evid[f.evidence_type] ?? f.evidence_type} · {cats[f.category] ?? f.category}{f.confidence ? ` · ${f.confidence} confidence` : ''}</p>
      <blockquote className="rp-quote">{f.quote} <PageLink page={f.page_no} /></blockquote>
      {f.summary && <p className="small mb-0">{f.summary}</p>}
      {f.statistic && (
        <dl className="kv rp-stat">
          <dt>Figure</dt><dd>{f.statistic.value}</dd>
          <dt>Of</dt><dd>{f.statistic.population || <span className="muted">Not stated</span>}</dd>
          <dt>Period</dt><dd>{f.statistic.period || <span className="muted">Not stated</span>}</dd>
          {f.statistic.definition && <><dt>Measures</dt><dd>{f.statistic.definition}</dd></>}
        </dl>
      )}
      {(f.techniques.length + f.cves.length + f.actors.length + f.technologies.length + f.regions.length) > 0 && (
        <ul className="rp-named rp-f-tags">
          {f.techniques.map((t) => <li key={t.id}><ExtLink href={techniqueUrl(t.id) ?? '#'}>{t.id}</ExtLink> {t.name}<span className="rp-tag">{t.basis === 'publisher' ? "Publisher's mapping" : f.origin === 'ai' ? 'Suggested by AI' : 'Your mapping'}</span></li>)}
          {f.cves.length > 0 && <li>CVEs: {f.cves.join(', ')}</li>}
          {f.actors.length > 0 && <li>Actors: {f.actors.join(', ')}</li>}
          {f.technologies.length > 0 && <li>Technologies: {f.technologies.join(', ')}</li>}
          {f.regions.length > 0 && <li>Regions: {f.regions.map((r) => REGION_LABEL[r] ?? r).join(', ')}</li>}
        </ul>
      )}
      {f.notes && <p className="xsmall muted mb-0">Note: {f.notes}</p>}
      <div className="row wrap rp-actions">
        {f.review_status !== 'accepted' && <button type="button" className="btn small" onClick={() => set.mutate('accepted')}>Accept</button>}
        <button type="button" className="btn small" onClick={onEdit}>Edit</button>
        {f.review_status !== 'rejected' ? <button type="button" className="btn small quiet" onClick={() => set.mutate('rejected')}>Reject</button>
          : <button type="button" className="btn small quiet" onClick={() => set.mutate('unreviewed')}>Restore</button>}
        {f.origin !== 'ai' && <button type="button" className="btn small quiet danger" onClick={async () => {
          if (await confirm({ title: 'Delete this finding?', confirmLabel: 'Delete', danger: true })) del.mutate()
        }}>Delete</button>}
      </div>
    </article>
  )
}

export function Findings({ reportId, onAdd, onEdit }: { reportId: number; onAdd: (d?: FindingDraft) => void; onEdit: (f: Finding) => void }) {
  const q = useFindings(reportId)
  const [filter, setFilter] = useState<string>('')
  if (q.isLoading) return <Loading />
  if (q.error || !q.data) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  const d = q.data
  const view = filter || (d.counts.unreviewed ? 'unreviewed' : 'accepted')
  const list = d.findings.filter((f) => view === 'all' ? f.review_status !== 'rejected' : f.review_status === view)
  return (
    <div className="stack">
      <p className="small muted mb-0">Findings are individual passages you can cite: an observation, a figure, a conclusion or a recommendation, each with its exact quote and page. Accepted findings are the ones you have checked; later phases build the behaviour library from them.</p>
      <AIPanel reportId={reportId} data={d} />
      <div className="row between wrap">
        <div className="chips" role="group" aria-label="Review status">
          {[['unreviewed', 'To review'], ['accepted', 'Accepted'], ['rejected', 'Rejected'], ['all', 'All but rejected']].map(([k, l]) => (
            <button key={k} type="button" className={`chip ${view === k ? 'on' : ''}`} aria-pressed={view === k} onClick={() => setFilter(k)}>
              {l}{k !== 'all' ? ` (${d.counts[k] ?? 0})` : ''}</button>))}
        </div>
        <button type="button" className="btn small" onClick={() => onAdd()}>Add a finding</button>
      </div>
      {!d.findings.length ? (
        <div className="notice">No findings yet. Use "Save as finding" on the Summary, select text in Read and add it, or extract them with AI above.</div>
      ) : !list.length ? <div className="notice">Nothing here.</div>
        : list.map((f) => <FindingCard key={f.id} f={f} reportId={reportId} cats={d.categories} evid={d.evidence} onEdit={() => onEdit(f)} />)}
    </div>
  )
}
