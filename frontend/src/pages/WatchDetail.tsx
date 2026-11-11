import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief, Claim, WatchDetail, WatchRecord } from '../types'
import { ArticleCard, BackLink, CitedText, Cites, copy, Empty, ErrorBox, Eyebrow, fmtDate, Loading, TimeAgo, usePageTitle, useToast } from '../components/ui'
import { IconCopy, IconRefresh } from '../components/icons'
import { useConfirm } from '../components/Sheet'

const PREFS: [string, string][] = [['important', 'Important changes immediately'], ['all', 'All meaningful new findings'], ['digest', 'Daily digest'], ['silent', 'Silent tracking']]
type Tab = 'overview' | 'timeline' | 'evidence' | 'history' | 'notes' | 'matching'

function ClaimList({ items, empty }: { items: Claim[]; empty: string }) {
  if (!items.length) return <p className="muted small">{empty}</p>
  return <ul className="claims">{items.map((c, i) => <li key={i}>{c.claim} <Cites ids={c.article_ids} />{c.note && <span className="small faint"> — {c.note}</span>}</li>)}</ul>
}

function RecordView({ r }: { r: WatchRecord }) {
  const toast = useToast()
  return (
    <>
      <section className="card">
        <div className="row between"><h2 style={{ margin: 0 }}>Current assessment</h2><span className="small faint">v{r.version} · {fmtDate(r.created_at)}</span></div>
        <div className={`notice ${r.method === 'ai' ? 'ai' : ''}`} style={{ margin: '.6rem 0' }}>
          {r.method === 'ai' ? `AI-generated cumulative summary (${r.model}). Claims without a valid source citation are automatically removed.` : 'Built from linked source reporting (AI synthesis not configured).'}
        </div>
        <p style={{ whiteSpace: 'pre-wrap' }}><CitedText text={r.summary} /></p>
      </section>
      {r.changes.length > 0 && <section className="card"><h2>What changed in v{r.version}</h2>
        <ul className="claims">{r.changes.map((c, i) => <li key={i}>{c.change} <Cites ids={c.article_ids} /></li>)}</ul></section>}
      <section className="card"><h2>Confirmed</h2><ClaimList items={r.confirmed} empty="No facts confirmed by an official source or independent corroboration yet." />
        <div className="divider" /><h2>Uncertain or single-source</h2><ClaimList items={r.uncertain} empty="No uncertain or disputed claims recorded." /></section>
      {r.detection.length > 0 && <section className="card"><h2>Detection guidance</h2><ClaimList items={r.detection} empty="" /></section>}
      {r.techniques.length > 0 && <section className="card"><h2>MITRE ATT&CK</h2>
        <ul className="claims">{r.techniques.map((t) => <li key={t.id}><a href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer"><code>{t.id}</code></a> {t.name ?? ''}
          {t.inferred && <span className="small faint"> ({t.ai ? 'AI-mapped' : 'keyword-inferred'})</span>} <Cites ids={t.article_ids} /></li>)}</ul></section>}
      {r.iocs.length > 0 && <section className="card"><h2>Indicators ({r.iocs.length})</h2>
        <p className="small muted">Extracted deterministically from source text (never AI-generated). Refanged — handle with care.</p>
        {r.iocs.map((i) => <div key={i.type + i.value} className="ioc"><span className="chip">{i.type}</span><code>{i.value}</code><Cites ids={i.article_ids} />
          <button className="btn icon ghost" aria-label={`Copy ${i.value}`} onClick={() => copy(i.value, toast)}><IconCopy /></button></div>)}
        <button className="btn" style={{ marginTop: '.6rem' }} onClick={() => copy(r.iocs.map((i) => i.value).join('\n'), toast)}>Copy all</button></section>}
    </>
  )
}

export default function WatchPage() {
  const { id = '' } = useParams()
  const [tab, setTab] = useState<Tab>('overview')
  const [ver, setVer] = useState<number | null>(null)
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const q = useQuery({ queryKey: ['watch', id], queryFn: () => api.get<WatchDetail>(`/api/watches/${id}`) })
  const version = useQuery({ queryKey: ['watch', id, 'v', ver], queryFn: () => api.get<WatchRecord>(`/api/watches/${id}/versions/${ver}`), enabled: ver !== null })
  const patch = useMutation({ mutationFn: (b: Record<string, unknown>) => api.patch(`/api/watches/${id}`, b), onSuccess: () => { toast('Saved'); qc.invalidateQueries() } })
  const act = useMutation({ mutationFn: ({ aid, action }: { aid: number; action: string }) => api.post(`/api/watches/${id}/evidence/${aid}`, { action }),
    onSuccess: (_d, v) => { toast(v.action === 'link' ? 'Linked — record updated' : 'Marked not relevant'); qc.invalidateQueries() } })
  const refresh = useMutation({ mutationFn: () => api.post<{ linked: number }>(`/api/watches/${id}/refresh`), onSuccess: (r) => { toast(`Re-checked: ${r.linked} new link(s)`); qc.invalidateQueries() } })
  const confirm = useConfirm()
  const del = useMutation({ mutationFn: () => api.del(`/api/watches/${id}`), onSuccess: () => { qc.invalidateQueries(); nav('/watch') } })

  usePageTitle(q.data?.title)
  if (q.isError) return <><BackLink fallback="/watch" label="Following" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  if (!q.data) return <Loading lines={10} />
  const w = q.data
  const unseen = (a: ArticleBrief) => w.previous_viewed_at && a.link && a.link.linked_at > w.previous_viewed_at

  return (
    <>
      <BackLink fallback="/watch" label="Following" />
      <Eyebrow parts={[`Following / ${w.kind}`, w.status === 'archived' && 'Archived']} />
      <h1 className="measure">{w.title}</h1>
      <div className="chips" style={{ marginBottom: '.5rem' }}>
        {w.identifiers.map((x) => <span key={x} className="chip" title="Identifier">{x}</span>)}
        {w.aliases.map((x) => <span key={x} className="chip" title="Alias" style={{ fontStyle: 'italic' }}>{x}</span>)}
      </div>
      <div className="small muted">Following since {fmtDate(w.created_at)} · last checked <TimeAgo iso={w.last_checked_at} /> · last updated <TimeAgo iso={w.last_updated_at} /></div>
      <div className="row" style={{ margin: '.8rem 0' }}>
        <label className="sr-only" htmlFor="pref">Notifications</label>
        <select id="pref" className="input" style={{ width: 'auto' }} value={w.notify_pref} onChange={(e) => patch.mutate({ notify_pref: e.target.value })}>
          {PREFS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        <button className="btn" onClick={() => refresh.mutate()} disabled={refresh.isPending}><IconRefresh />Re-check</button>
        <button className="btn" onClick={() => patch.mutate({ status: w.status === 'active' ? 'archived' : 'active' })}>{w.status === 'active' ? 'Archive' : 'Reactivate'}</button>
      </div>

      <div className="tabs" role="tablist">
        {([['overview', 'Overview'], ['timeline', 'Timeline'], ['evidence', `Evidence (${w.evidence.length})`], ['history', `History (${w.versions.length})`], ['notes', 'Notes & tags'], ['matching', 'Matching']] as [Tab, string][]).map(([t, l]) => (
          <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>{l}{t === 'evidence' && w.candidates.length > 0 && <span className="badge" style={{ marginLeft: 4 }}>{w.candidates.length}</span>}</button>))}
      </div>

      {tab === 'overview' && (w.record ? <RecordView r={w.record} /> : <Empty title="No record yet" />)}

      {tab === 'timeline' && (
        <ol className="timeline">{w.timeline.map((t) => (
          <li key={t.id} className={t.event_type}>
            <div className="small faint">{fmtDate(t.occurred_at)} · {t.event_type.replace('_', ' ')}</div>
            <div style={{ fontWeight: 600 }}>{t.article_id ? <Link to={`/article/${t.article_id}`}>{t.title}</Link> : t.title}</div>
            {t.detail && <div className="small muted">{t.detail}</div>}
            {t.summary_version && <button className="btn ghost small" onClick={() => { setVer(t.summary_version); setTab('history') }}>View v{t.summary_version}</button>}
          </li>))}</ol>
      )}

      {tab === 'evidence' && <>
        {w.candidates.length > 0 && <section className="card" style={{ marginBottom: '1rem' }}>
          <h2>Needs your review ({w.candidates.length})</h2>
          <p className="small muted">These items partially match but were not linked automatically (e.g. same actor, different incident, or only a passing mention).</p>
          <div className="alist">{w.candidates.map((a) => <ArticleCard key={a.id} a={a} extra={<>
            <div className="small muted" style={{ marginTop: '.3rem' }}>Match {a.link?.match_score}: {a.link?.match_reasons.join('; ')}</div>
            <div className="row" style={{ marginTop: '.4rem' }}><button className="btn primary" onClick={() => act.mutate({ aid: a.id, action: 'link' })}>Link to this watch</button>
              <button className="btn" onClick={() => act.mutate({ aid: a.id, action: 'reject' })}>Not relevant</button></div></>} />)}</div>
        </section>}
        {w.evidence.length === 0 ? <Empty title="No linked evidence yet">New reporting is checked every ingestion cycle.</Empty> :
          <div className="alist">{[...w.evidence].reverse().map((a) => <ArticleCard key={a.id} a={a} extra={
            <div className="small" style={{ marginTop: '.35rem' }}>
              <div className="row">{unseen(a) && <span className="badge">new</span>}<span className={`sig ${a.link?.significance}`}>{a.link?.significance}</span><span className="muted">{a.link?.assessment}</span></div>
              <div className="faint">Linked {a.link?.linked_by === 'auto' ? 'automatically' : `by ${a.link?.linked_by}`} · {a.link?.match_reasons.join('; ')}
                {a.link?.linked_by !== 'origin' && <> · <button className="btn ghost small" style={{ minHeight: 0, padding: 0 }} onClick={() => act.mutate({ aid: a.id, action: 'reject' })}>unlink</button></>}</div>
            </div>} />)}</div>}
      </>}

      {tab === 'history' && <>
        <p className="small muted">Every update creates a new version. Earlier assessments are preserved for comparison.</p>
        <div className="stack">{w.versions.map((v) => (
          <div key={v.version} className="card">
            <div className="row between"><strong>v{v.version}</strong><span className="small faint">{fmtDate(v.created_at)} · {v.method}{v.model ? ` (${v.model})` : ''}</span></div>
            {v.changes.length > 0 ? <ul className="claims small">{v.changes.map((c, i) => <li key={i}>{c.change} <Cites ids={c.article_ids} /></li>)}</ul> : <p className="small muted">{v.version === 1 ? 'Initial record' : 'No material changes recorded'}</p>}
            <button className="btn" onClick={() => setVer(ver === v.version ? null : v.version)}>{ver === v.version ? 'Hide' : 'View this version'}</button>
            {ver === v.version && (version.data ? <div style={{ marginTop: '.75rem' }}><RecordView r={version.data} /></div> : <Loading />)}
          </div>))}</div>
      </>}

      {tab === 'notes' && <NotesForm w={w} onSave={(b) => patch.mutate(b)} />}
      {tab === 'matching' && <MatchingForm w={w} onSave={(b) => patch.mutate(b)} onDelete={async () => { if (await confirm({ title: 'Stop following and delete?', body: `This permanently deletes “${w.title}”, its timeline and all record versions. Linked articles are kept.`, confirmLabel: 'Delete watch', danger: true })) del.mutate() }} />}
    </>
  )
}

const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

function NotesForm({ w, onSave }: { w: WatchDetail; onSave: (b: Record<string, unknown>) => void }) {
  const [notes, setNotes] = useState(w.notes)
  const [tags, setTags] = useState(w.tags.join(', '))
  return (
    <form className="card" onSubmit={(e) => { e.preventDefault(); onSave({ notes, tags: split(tags) }) }}>
      <label className="field"><span>Personal notes (private; never sent to the AI provider)</span><textarea className="input" style={{ minHeight: 180 }} value={notes} onChange={(e) => setNotes(e.target.value)} /></label>
      <label className="field"><span>Tags (comma separated)</span><input className="input" value={tags} onChange={(e) => setTags(e.target.value)} /></label>
      <button className="btn primary">Save</button>
    </form>
  )
}

function MatchingForm({ w, onSave, onDelete }: { w: WatchDetail; onSave: (b: Record<string, unknown>) => void; onDelete: () => void }) {
  const [f, setF] = useState({ title: w.title, description: w.description, identifiers: w.identifiers.join(', '), aliases: w.aliases.join(', '), context: w.context_terms.join(', '), exclude: w.exclude_terms.join(', ') })
  return (
    <form className="card" onSubmit={(e) => { e.preventDefault(); onSave({ title: f.title, description: f.description, identifiers: split(f.identifiers), aliases: split(f.aliases), context_terms: split(f.context), exclude_terms: split(f.exclude) }) }}>
      <p className="small muted">Identifiers and aliases decide what is linked. Context terms only boost relevance — for incidents they never suffice alone, so other incidents by the same actor are not merged. Saving re-checks the last 30 days.</p>
      <label className="field"><span>Name</span><input className="input" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></label>
      <label className="field"><span>Description (used for contextual matching)</span><textarea className="input" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></label>
      <label className="field"><span>Identifiers</span><input className="input" value={f.identifiers} onChange={(e) => setF({ ...f, identifiers: e.target.value })} /></label>
      <label className="field"><span>Aliases</span><input className="input" value={f.aliases} onChange={(e) => setF({ ...f, aliases: e.target.value })} /></label>
      <label className="field"><span>Context terms</span><input className="input" value={f.context} onChange={(e) => setF({ ...f, context: e.target.value })} /></label>
      <label className="field"><span>Exclude terms</span><input className="input" value={f.exclude} onChange={(e) => setF({ ...f, exclude: e.target.value })} /></label>
      <div className="row between"><button className="btn primary">Save & re-check</button><button type="button" className="btn danger" onClick={onDelete}>Delete watch</button></div>
    </form>
  )
}
