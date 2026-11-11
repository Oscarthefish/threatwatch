import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief, Claim, SocAction, WatchDetail, WatchRecord } from '../types'
import {
  ActionList, ArticleCard, BackLink, CitedText, Cites, copy, Empty, ErrorBox, Eyebrow, Field, fmtDate, Highlight, Loading, TimeAgo, usePageTitle, useToast,
} from '../components/ui'
import { IconCopy, IconRefresh } from '../components/icons'
import { useConfirm } from '../components/Sheet'
import { humanReason, kindLabel, matchStrength, NOTIFY, SIGNIFICANCE, splitList } from '../components/follow'

type Tab = 'overview' | 'timeline' | 'evidence' | 'settings'
const EVENT: Record<string, string> = {
  created: 'Started following', evidence: 'New report linked', summary: 'Record updated', note: 'Note', status: 'Status',
  user_link: 'You linked a report', user_reject: 'You marked a report not relevant',
}

function ClaimList({ items, empty }: { items: Claim[]; empty: string }) {
  if (!items.length) return <p className="muted small mb-0">{empty}</p>
  return <ul className="claims">{items.map((c, i) => <li key={i}>{c.claim} <Cites ids={c.article_ids} />{c.note && <span className="xsmall faint"> ({c.note})</span>}</li>)}</ul>
}

function RecordView({ r, compact }: { r: WatchRecord; compact?: boolean }) {
  const toast = useToast()
  return (
    <div className="stack">
      <section className="panel" aria-labelledby={`assess-${r.version}`}>
        <header>
          <h2 id={`assess-${r.version}`}>Current assessment</h2>
          <span className={`basis ${r.method === 'ai' ? '' : 'playbook'}`}>{r.method === 'ai' ? `AI · ${r.model}` : 'From linked reports'} · v{r.version}</span>
        </header>
        <div className="body">
          <p className="prewrap measure"><CitedText text={r.summary} /></p>
          <p className="xsmall faint mb-0">
            {r.method === 'ai' ? 'Generated from the linked reports. Claims without a valid source citation are removed automatically.' : 'Headlines are grouped by how well they are corroborated. Add an AI key for a written synthesis.'}
            {' '}Updated {fmtDate(r.created_at)}.
          </p>
        </div>
      </section>
      {r.changes.length > 0 && !compact && (
        <section className="panel" aria-labelledby="chg-h">
          <header><h2 id="chg-h">What changed in this update</h2></header>
          <div className="body"><ul className="claims">{r.changes.map((c, i) => <li key={i}>{c.change} <Cites ids={c.article_ids} /></li>)}</ul></div>
        </section>
      )}
      <section className="panel" aria-labelledby={`facts-${r.version}`}>
        <header><h2 id={`facts-${r.version}`}>Confirmed</h2><span className="xsmall muted">official or corroborated</span></header>
        <div className="body">
          <ClaimList items={r.confirmed} empty="Nothing confirmed by an official source or independent reporting yet." />
          <h3>Uncertain or single-source</h3>
          <ClaimList items={r.uncertain} empty="No uncertain or disputed claims." />
        </div>
      </section>
      {r.detection.length > 0 && (
        <section className="panel"><header><h2>Detection guidance</h2></header><div className="body"><ClaimList items={r.detection} empty="" /></div></section>
      )}
      {r.techniques.length > 0 && (
        <section className="panel"><header><h2>MITRE ATT&CK</h2></header><div className="body">
          <ul className="claims">{r.techniques.map((t) => (
            <li key={t.id}>
              <a href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer"><code>{t.id}</code></a> {t.name ?? ''}
              {t.inferred && <span className="xsmall faint"> ({t.ai ? 'AI-mapped' : 'keyword-inferred'})</span>} <Cites ids={t.article_ids} />
            </li>))}</ul>
        </div></section>
      )}
      {r.iocs.length > 0 && (
        <section className="panel">
          <header><h2>Indicators ({r.iocs.length})</h2>
            <button type="button" className="link" onClick={() => copy(r.iocs.map((i) => i.value).join('\n'), toast)}>Copy all</button></header>
          <div className="body">
            <p className="xsmall muted">Taken verbatim from the linked reports (never AI-generated) and refanged. Handle with care.</p>
            {r.iocs.map((i) => (
              <div key={i.type + i.value} className="ioc"><span className="chip">{i.type}</span><code>{i.value}</code><Cites ids={i.article_ids} />
                <button type="button" className="btn icon quiet compact" aria-label={`Copy ${i.value}`} onClick={() => copy(i.value, toast)}><IconCopy /></button></div>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}

/** Next steps across all linked evidence, newest first, de-duplicated; urgent steps lead. */
function nextSteps(evidence: ArticleBrief[]): SocAction[] {
  const seen = new Set<string>()
  const out: SocAction[] = []
  for (const a of [...evidence].sort((x, y) => y.published_at.localeCompare(x.published_at))) {
    for (const s of a.actions ?? []) {
      const key = s.kind === 'patch' || s.basis === 'Playbook' ? s.kind + s.label : s.kind + s.detail
      if (!seen.has(key)) { seen.add(key); out.push(s) }
    }
  }
  return out.sort((x, y) => Number(y.urgent) - Number(x.urgent)).slice(0, 8)
}

function MatchNote({ a }: { a: ArticleBrief }) {
  const l = a.link
  if (!l) return null
  return (
    <div className="match-note">
      <p className="xsmall muted mb-0">
        <span className="strong">{l.linked_by === 'auto' ? `Why it matched (${matchStrength(l.match_score).toLowerCase()})` : l.linked_by === 'origin' ? 'Where you started following' : 'Linked by you'}</span>
        {l.linked_by === 'auto' && l.match_reasons.length > 0 && <>: {l.match_reasons.map(humanReason).join(', ')}</>}
      </p>
      {l.passages?.map((p, i) => <blockquote key={i} className="fup-quote"><Highlight text={p.text} terms={p.terms} /></blockquote>)}
    </div>
  )
}

export default function WatchPage() {
  const { id = '' } = useParams()
  const [tab, setTab] = useState<Tab>('overview')
  const [ver, setVer] = useState<number | null>(null)
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const confirm = useConfirm()
  const q = useQuery({ queryKey: ['watch', id], queryFn: () => api.get<WatchDetail>(`/api/watches/${id}`) })
  const version = useQuery({ queryKey: ['watch', id, 'v', ver], queryFn: () => api.get<WatchRecord>(`/api/watches/${id}/versions/${ver}`), enabled: ver !== null })
  const patch = useMutation({
    mutationFn: (b: Record<string, unknown>) => api.patch(`/api/watches/${id}`, b),
    onSuccess: () => { toast('Saved'); qc.invalidateQueries() },
    onError: () => toast('Not saved. Check your connection and try again.', 'error'),
  })
  const act = useMutation({
    mutationFn: ({ aid, action }: { aid: number; action: string }) => api.post(`/api/watches/${id}/evidence/${aid}`, { action }),
    onSuccess: (_d, v) => { toast(v.action === 'link' ? 'Linked. The record has been updated.' : 'Marked not relevant. It will not be linked again.'); qc.invalidateQueries() },
  })
  const refresh = useMutation({
    mutationFn: () => api.post<{ linked: number }>(`/api/watches/${id}/refresh`),
    onSuccess: (r) => { toast(r.linked ? `Found ${r.linked} new report${r.linked > 1 ? 's' : ''}.` : 'No new reports in the last 60 days.'); qc.invalidateQueries() },
  })
  const del = useMutation({ mutationFn: () => api.del(`/api/watches/${id}`), onSuccess: () => { qc.invalidateQueries(); toast('Deleted'); nav('/watch') } })

  usePageTitle(q.data?.title)
  if (q.isError) return <><BackLink fallback="/watch" label="Following" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  if (!q.data) return <Loading lines={10} />
  const w = q.data
  const unseen = (a: ArticleBrief) => !!w.previous_viewed_at && !!a.link && a.link.linked_at > w.previous_viewed_at
  const steps = nextSteps(w.evidence)
  const tabs: [Tab, string, number?][] = [['overview', 'Overview'], ['timeline', 'Timeline'], ['evidence', 'Reports', w.candidates.length], ['settings', 'Settings']]

  return (
    <>
      <BackLink fallback="/watch" label="Following" />
      <header className="doc-head mb-3">
        <Eyebrow parts={[kindLabel(w.kind), `Following since ${fmtDate(w.created_at)}`, w.status === 'archived' && 'Archived']} />
        <h1>{w.title}</h1>
        {(w.identifiers.length > 0 || w.aliases.length > 0) && (
          <p className="small muted mb-2">Matches {[...w.identifiers, ...w.aliases].map((x, i) => <span key={x}>{i > 0 && ', '}<b>{x}</b></span>)}</p>
        )}
        <div className="watch-bar">
          <span className="small muted">{w.evidence.length} report{w.evidence.length === 1 ? '' : 's'} · checked <TimeAgo iso={w.last_checked_at} /></span>
          <div className="row">
            <label className="sr-only" htmlFor="pref">Notifications</label>
            <select id="pref" className="input w-auto" value={w.notify_pref} onChange={(e) => patch.mutate({ notify_pref: e.target.value })}>
              {NOTIFY.map(([v, l]) => <option key={v} value={v}>Notify: {l}</option>)}
            </select>
            <button type="button" className="btn" aria-busy={refresh.isPending || undefined} onClick={() => refresh.mutate()}><IconRefresh />Check now</button>
          </div>
        </div>
      </header>

      {w.candidates.length > 0 && tab !== 'evidence' && (
        <div className="notice row between mb-3">
          <span>{w.candidates.length} report{w.candidates.length > 1 ? 's' : ''} might be related and need{w.candidates.length > 1 ? '' : 's'} your decision.</span>
          <button type="button" className="btn small" onClick={() => setTab('evidence')}>Review</button>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Sections">
        {tabs.map(([t, l, n]) => (
          <button key={t} type="button" role="tab" id={`tab-${t}`} aria-selected={tab === t} aria-controls={`panel-${t}`} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
            {l}{t === 'evidence' && <span className="faint"> {w.evidence.length}</span>}{!!n && <span className="badge ml-1" aria-label={`${n} to review`}>{n}</span>}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'overview' && (
          <div className="doc-grid">
            <div className="doc-main">
              {w.record ? <RecordView r={w.record} /> : <Empty title="No record yet">The record is built as soon as a report is linked.</Empty>}
              {w.versions.length > 1 && (
                <details className="disclose panel versions">
                  <summary>Earlier versions ({w.versions.length - 1})</summary>
                  <div className="body">
                    {w.versions.slice(1).map((v) => (
                      <div key={v.version} className="version">
                        <div className="row between"><strong>Version {v.version}</strong><span className="xsmall faint">{fmtDate(v.created_at)} · {v.method === 'ai' ? 'AI' : 'from reports'}</span></div>
                        {v.changes.length > 0 ? <ul className="claims small">{v.changes.map((c, i) => <li key={i}>{c.change} <Cites ids={c.article_ids} /></li>)}</ul>
                          : <p className="small muted">{v.version === 1 ? 'First record' : 'No material change'}</p>}
                        <button type="button" className="btn small" onClick={() => setVer(ver === v.version ? null : v.version)}>{ver === v.version ? 'Hide this version' : 'Show this version'}</button>
                        {ver === v.version && <div className="mt-3">{version.data ? <RecordView r={version.data} compact /> : <Loading />}</div>}
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </div>
            <aside className="doc-aside" aria-label="Next steps">
              {steps.length ? <ActionList actions={steps} /> : (
                <section className="panel"><header><h2>What to do</h2></header>
                  <div className="body"><p className="small muted mb-0">No specific steps from the linked reports yet.</p></div></section>
              )}
            </aside>
          </div>
        )}

        {tab === 'timeline' && (
          <ol className="timeline">{w.timeline.map((t) => (
            <li key={t.id} className={t.event_type}>
              <div className="xsmall faint mono">{fmtDate(t.occurred_at)} · {EVENT[t.event_type] ?? t.event_type}</div>
              <div className="strong">{t.article_id ? <a href={`/article/${t.article_id}`} onClick={(e) => { e.preventDefault(); nav(`/article/${t.article_id}`) }}>{t.title}</a> : t.title}</div>
              {t.detail && <div className="small muted">{t.event_type === 'evidence' ? t.detail.split(' · ')[0] : t.detail}</div>}
              {t.summary_version && <button type="button" className="link" onClick={() => { setVer(t.summary_version); setTab('overview') }}>See version {t.summary_version}</button>}
            </li>))}</ol>
        )}

        {tab === 'evidence' && (
          <div className="stack">
            {w.candidates.length > 0 && (
              <section className="panel review" aria-labelledby="rev-h">
                <header><h2 id="rev-h">Needs your decision ({w.candidates.length})</h2></header>
                <div className="body">
                  <p className="small muted">These partly match but were not linked automatically, for example the same actor in a different incident, or only a passing mention.</p>
                  <div className="alist">{w.candidates.map((a) => (
                    <ArticleCard key={a.id} a={a} extra={<>
                      <MatchNote a={a} />
                      <div className="row mt-2">
                        <button type="button" className="btn primary small" onClick={() => act.mutate({ aid: a.id, action: 'link' })}>Same subject, link it</button>
                        <button type="button" className="btn small" onClick={() => act.mutate({ aid: a.id, action: 'reject' })}>Not relevant</button>
                      </div>
                    </>} />
                  ))}</div>
                </div>
              </section>
            )}
            {w.evidence.length === 0 ? <Empty title="No linked reports yet">Every collection run checks new reporting against this watch.</Empty> : (
              <div className="alist">{[...w.evidence].reverse().map((a) => (
                <ArticleCard key={a.id} a={a} extra={<>
                  <div className="row mt-2">
                    {unseen(a) && <span className="sig meaningful">New</span>}
                    {a.link && <span className={`sig ${a.link.significance}`}>{SIGNIFICANCE[a.link.significance] ?? a.link.significance}</span>}
                    {a.link?.assessment && <span className="xsmall muted">{a.link.assessment}</span>}
                  </div>
                  <MatchNote a={a} />
                  {a.link?.linked_by !== 'origin' && (
                    <button type="button" className="link xsmall" onClick={() => act.mutate({ aid: a.id, action: 'reject' })}>Not relevant, unlink</button>
                  )}
                </>} />
              ))}</div>
            )}
          </div>
        )}

        {tab === 'settings' && (
          <div className="stack">
            <NotesForm w={w} onSave={(b) => patch.mutate(b)} busy={patch.isPending} />
            <MatchingForm w={w} onSave={(b) => patch.mutate(b)} busy={patch.isPending} />
            <section className="panel danger-zone" aria-labelledby="dz-h">
              <header><h2 id="dz-h">Stop following</h2></header>
              <div className="body row between">
                <p className="small muted mb-0">Archive keeps the record but stops checking. Delete removes the record, timeline and versions.</p>
                <div className="row">
                  <button type="button" className="btn" onClick={() => patch.mutate({ status: w.status === 'active' ? 'archived' : 'active' })}>{w.status === 'active' ? 'Archive' : 'Resume following'}</button>
                  <button type="button" className="btn danger" onClick={async () => {
                    if (await confirm({ title: 'Delete this watch?', body: `This permanently deletes “${w.title}”, its timeline and all record versions. Linked articles are kept.`, confirmLabel: 'Delete', danger: true })) del.mutate()
                  }}>Delete</button>
                </div>
              </div>
            </section>
          </div>
        )}
      </div>
    </>
  )
}

function NotesForm({ w, onSave, busy }: { w: WatchDetail; onSave: (b: Record<string, unknown>) => void; busy: boolean }) {
  const [notes, setNotes] = useState(w.notes)
  const [tags, setTags] = useState(w.tags.join(', '))
  return (
    <form className="panel" onSubmit={(e) => { e.preventDefault(); onSave({ notes, tags: splitList(tags) }) }}>
      <header><h2>Notes and tags</h2><span className="xsmall muted">private, never sent to the AI provider</span></header>
      <div className="body">
        <Field label="Notes"><textarea className="input notes" value={notes} onChange={(e) => setNotes(e.target.value)} /></Field>
        <Field label="Tags" hint="Comma separated."><input className="input" value={tags} onChange={(e) => setTags(e.target.value)} /></Field>
        <button className="btn primary" aria-busy={busy || undefined}>Save notes</button>
      </div>
    </form>
  )
}

function MatchingForm({ w, onSave, busy }: { w: WatchDetail; onSave: (b: Record<string, unknown>) => void; busy: boolean }) {
  const [f, setF] = useState({ title: w.title, description: w.description, identifiers: w.identifiers.join(', '), aliases: w.aliases.join(', '), context: w.context_terms.join(', '), exclude: w.exclude_terms.join(', ') })
  return (
    <form className="panel" onSubmit={(e) => { e.preventDefault(); onSave({ title: f.title, description: f.description, identifiers: splitList(f.identifiers), aliases: splitList(f.aliases), context_terms: splitList(f.context), exclude_terms: splitList(f.exclude) }) }}>
      <header><h2>Matching</h2><span className="xsmall muted">saving re-checks the last 30 days</span></header>
      <div className="body">
        <Field label="Name"><input className="input" value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></Field>
        <Field label="Identifiers" hint="Names that identify this subject. Any one is enough to link a report."><input className="input" value={f.identifiers} onChange={(e) => setF({ ...f, identifiers: e.target.value })} /></Field>
        <Field label="Aliases" hint="Other names for the same subject."><input className="input" value={f.aliases} onChange={(e) => setF({ ...f, aliases: e.target.value })} /></Field>
        <Field label="Context terms" hint="Raise relevance only. For incidents they never link a report alone."><input className="input" value={f.context} onChange={(e) => setF({ ...f, context: e.target.value })} /></Field>
        <Field label="Exclude terms" hint="Reports containing these are never linked."><input className="input" value={f.exclude} onChange={(e) => setF({ ...f, exclude: e.target.value })} /></Field>
        <Field label="Description" hint="Used to judge similar wording in new reports."><textarea className="input" value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
        <button className="btn primary" aria-busy={busy || undefined}>Save and re-check</button>
      </div>
    </form>
  )
}
