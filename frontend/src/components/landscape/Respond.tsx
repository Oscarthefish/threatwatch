import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, ApiError } from '../../api'
import { ErrorBox, Field, fmtDate, Loading, TimeAgo, useToast } from '../ui'
import { Sheet, useConfirm } from '../Sheet'
import { useInvalidate } from './Overview'
import { lsPath, PRIORITY_CLASS, type ProfileResponse } from '../../landscape'

interface Q { key: string; area: string; area_label: string; text: string; why: string; answer: string; evidence: string; critical: boolean; refs: string[] }
interface Scen { scenario: string; title: string; priority: string; because: string; questions: Q[]; answered: number; applicable: number; score: number | null; unknown: number; gaps: number }
interface Imp { key: string; text: string; why: string; action: string; owner: string; critical: boolean; answer: string; scenarios: string[]; validate: string; refs: string[] }
interface Readiness { scenarios: Scen[]; improvements: Imp[]; answers: Record<string, [string, number | null]>; score_note: string }
interface PbList { saved: { id: number; scenario: string; title: string; version: number; reviewed_at: string | null; updated_at: string; review_due: boolean }[]; scenarios: { key: string; title: string; priority: string; because: string }[] }
interface Pb { id: number; title: string; body: string; version: number; reviewed_at: string | null; updated_at: string; versions: { version: number; saved_at: string }[] }
interface ExList { available: { scenario: string; title: string; stages: number }[]; runs: { id: number; scenario: string; format: string; difficulty: string; stage: number; created_at: string; completed_at: string | null }[] }
interface ExQ { key: string; text: string; points?: string[] }
interface Ex { id: number; stage: number; completed_at: string | null; format: string; responses: Record<string, { answer: string; covered: string[] }>; spec: { title: string; setting: string; total: number; stages: { title: string; narrative: string; questions: ExQ[] }[] } }

function groupBy<T>(xs: T[], key: (x: T) => string): [string, T[]][] {
  const m = new Map<string, T[]>()
  for (const x of xs) m.set(key(x), [...(m.get(key(x)) ?? []), x])
  return [...m.entries()]
}

const SUBS = [['readiness', 'Readiness'], ['playbooks', 'Playbooks'], ['exercises', 'Exercises']] as const
const ANSWER_ORDER = ['tested', 'implemented', 'partial', 'not_implemented', 'unknown', 'na']

function Question({ pid, q, labels }: { pid: number; q: Q; labels: Readiness['answers'] }) {
  const inval = useInvalidate(pid)
  const [evidence, setEvidence] = useState(q.evidence)
  const save = useMutation({ mutationFn: (b: { answer: string; evidence: string }) => api.put(lsPath(pid, `/readiness/${q.key}`), b), onSuccess: inval })
  return (
    <li className="ls-q">
      <p className="small mb-0"><strong>{q.text}</strong>{q.critical && <span className="xsmall muted"> · key question</span>}</p>
      <p className="xsmall muted">{q.why}{q.refs.length ? ` (${q.refs.join(', ')})` : ''}</p>
      <div className="ls-q-row">
        <select className="input w-auto" aria-label={`Answer: ${q.text}`} value={q.answer} onChange={(e) => save.mutate({ answer: e.target.value, evidence })}>
          {ANSWER_ORDER.map((k) => <option key={k} value={k}>{labels[k][0]}</option>)}
        </select>
        <input className="input grow" aria-label={`Evidence: ${q.text}`} placeholder="Evidence (document, test date)" value={evidence} maxLength={4000}
          onChange={(e) => setEvidence(e.target.value)} onBlur={() => evidence !== q.evidence && save.mutate({ answer: q.answer, evidence })} />
      </div>
    </li>
  )
}

function ReadinessView({ pid }: { pid: number }) {
  const q = useQuery({ queryKey: ['ls', pid, 'readiness'], queryFn: () => api.get<Readiness>(lsPath(pid, '/readiness')) })
  const [open, setOpen] = useState<string | null>(null)
  const toast = useToast()
  const inval = useInvalidate(pid)
  const add = useMutation({ mutationFn: (i: Imp) => api.post(lsPath(pid, '/actions'), { kind: 'readiness', ref: i.key, title: i.action, detail: i.why, priority: i.critical ? 'high' : 'medium', owner: i.owner }),
    onSuccess: () => { inval(); toast('Added to actions') }, onError: (e) => toast(e instanceof ApiError && e.status === 409 ? 'Already on the action list' : 'Could not add', 'error') })
  if (q.isLoading) return <Loading />
  if (q.error || !q.data) return <ErrorBox error={q.error} />
  const r = q.data
  const cur = r.scenarios.find((s) => s.scenario === open)
  return (
    <div className="stack">
      <p className="xsmall muted measure mb-0">Incident scenarios most relevant to this profile, with readiness questions aligned to NIST SP 800-61 Rev. 3 and CSF 2.0. {r.score_note}</p>
      <ul role="list" className="ls-rows">
        {r.scenarios.map((s) => (
          <li key={s.scenario}>
            <button type="button" className="ls-row" aria-expanded={open === s.scenario} onClick={() => setOpen(open === s.scenario ? null : s.scenario)}>
              <span className={`sev ${PRIORITY_CLASS[s.priority]}`}>{s.priority}</span>
              <span className="grow"><strong>{s.title}</strong><span className="xsmall muted"> · because of {s.because}</span></span>
              <span className="xsmall nowrap">{s.score == null ? `${s.answered} of ${s.applicable} answered` : `${s.score}% · ${s.gaps} gaps, ${s.unknown} unknown`}</span>
            </button>
          </li>))}
      </ul>
      {cur && (
        <section className="panel" aria-labelledby="rq-h">
          <header><h2 id="rq-h">{cur.title}</h2></header>
          <div className="body">
            {groupBy(cur.questions, (x) => x.area_label).map(([area, qs]) => (
              <div key={area}><h3 className="mini-h">{area}</h3><ul role="list" className="ls-qs">{qs.map((x) => <Question key={x.key} pid={pid} q={x} labels={r.answers} />)}</ul></div>
            ))}
          </div>
        </section>
      )}
      <section className="panel" aria-labelledby="imp-h">
        <header><h2 id="imp-h">Improvement plan</h2></header>
        <div className="body">
          {r.improvements.length === 0 ? <p className="small muted mb-0">No gaps or unknowns recorded.</p> : (
            <ol className="ls-steps">{r.improvements.slice(0, 25).map((i) => (
              <li key={i.key}>
                <strong>{i.action}</strong>{i.critical && <span className="xsmall muted"> · key question</span>}
                <div className="xsmall muted">Now: {r.answers[i.answer][0]}. Why: {i.why} Affects: {i.scenarios.join(', ')}. Suggested owner: {i.owner}. Validate: {i.validate}</div>
                <button type="button" className="btn small quiet" onClick={() => add.mutate(i)}>Add to actions</button>
              </li>))}</ol>)}
        </div>
      </section>
    </div>
  )
}

function PlaybookSheet({ pid, id, onClose }: { pid: number; id: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ['ls', pid, 'pb', id], queryFn: () => api.get<Pb>(lsPath(pid, `/playbooks/${id}`)) })
  const inval = useInvalidate(pid)
  const toast = useToast()
  const [body, setBody] = useState<string | null>(null)
  const save = useMutation({ mutationFn: (reviewed: boolean) => api.patch<{ version: number }>(lsPath(pid, `/playbooks/${id}`), { body: body ?? q.data!.body, reviewed }),
    onSuccess: (r) => { inval(); q.refetch(); setBody(null); toast(`Saved as version ${r.version}`) } })
  const d = q.data
  return (
    <Sheet title={d?.title ?? 'Playbook'} onClose={onClose}>
      {!d ? <Loading /> : (
        <div className="stack">
          <p className="xsmall muted mb-0">Version {d.version}, updated {fmtDate(d.updated_at)}{d.reviewed_at ? `, reviewed ${fmtDate(d.reviewed_at)}` : ', not yet reviewed'}. Markdown. Earlier versions are kept.</p>
          <label className="sr-only" htmlFor="pb-body">Playbook text</label>
          <textarea id="pb-body" className="input mono ls-editor" rows={24} value={body ?? d.body} onChange={(e) => setBody(e.target.value)} />
          <div className="row wrap">
            <button type="button" className="btn primary" disabled={body == null} aria-busy={save.isPending} onClick={() => save.mutate(false)}>Save</button>
            <button type="button" className="btn" onClick={() => save.mutate(true)}>Mark reviewed</button>
            <a className="btn" href={lsPath(pid, `/playbooks/${id}/export.md`)} download>Download .md</a>
          </div>
        </div>
      )}
    </Sheet>
  )
}

function Playbooks({ pid }: { pid: number }) {
  const q = useQuery({ queryKey: ['ls', pid, 'playbooks'], queryFn: () => api.get<PbList>(lsPath(pid, '/playbooks')) })
  const inval = useInvalidate(pid)
  const confirm = useConfirm()
  const [open, setOpen] = useState<number | null>(null)
  const create = useMutation({ mutationFn: (scenario: string) => api.post<{ id: number }>(lsPath(pid, '/playbooks'), { scenario }), onSuccess: (r) => { inval(); q.refetch(); setOpen(r.id) } })
  const del = useMutation({ mutationFn: (id: number) => api.del(lsPath(pid, `/playbooks/${id}`)), onSuccess: () => { inval(); q.refetch() } })
  if (q.isLoading) return <Loading />
  if (!q.data) return <ErrorBox error={q.error} />
  return (
    <div className="stack">
      <p className="xsmall muted measure mb-0">Drafts follow the NIST SP 800-61 Rev. 3 lifecycle and include the intelligence that makes each scenario relevant. They leave organisation-specific contacts, approvals and legal obligations as blanks to complete; Threat Watch never fills those in or runs any response action.</p>
      {q.data.saved.length > 0 && (
        <section className="panel"><header><h2>Saved playbooks</h2></header><div className="body">
          <ul role="list" className="ls-rows">{q.data.saved.map((p) => (
            <li key={p.id} className="row">
              <button type="button" className="ls-row grow" onClick={() => setOpen(p.id)}><span className="grow">{p.title}</span>
                <span className="xsmall muted">v{p.version} · <TimeAgo iso={p.updated_at} /></span>{p.review_due && <span className="ls-status blocked">Review: new threats since last review</span>}</button>
              <button type="button" className="btn small quiet" aria-label={`Delete ${p.title}`} onClick={async () => { if (await confirm({ title: 'Delete playbook?', confirmLabel: 'Delete', danger: true })) del.mutate(p.id) }}>Delete</button>
            </li>))}</ul></div></section>)}
      <section className="panel"><header><h2>Draft a playbook</h2></header><div className="body">
        <ul role="list" className="ls-rows">{q.data.scenarios.map((s) => (
          <li key={s.key}><button type="button" className="ls-row" aria-busy={create.isPending} onClick={() => create.mutate(s.key)}>
            <span className={`sev ${PRIORITY_CLASS[s.priority]}`}>{s.priority}</span><span className="grow">{s.title}<span className="xsmall muted"> · {s.because}</span></span><span className="xsmall">Draft</span></button></li>))}</ul>
      </div></section>
      {open && <PlaybookSheet pid={pid} id={open} onClose={() => setOpen(null)} />}
    </div>
  )
}

function ExerciseSheet({ pid, id, onClose }: { pid: number; id: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ['ls', pid, 'ex', id], queryFn: () => api.get<Ex>(lsPath(pid, `/exercises/${id}`)) })
  const [resp, setResp] = useState<Record<string, { answer: string; covered: string[] }>>({})
  const save = useMutation({ mutationFn: (advance: boolean) => api.patch(lsPath(pid, `/exercises/${id}`), { responses: resp, advance }), onSuccess: () => { setResp({}); q.refetch() } })
  const d = q.data
  const r = (k: string) => resp[k] ?? d?.responses[k] ?? { answer: '', covered: [] }
  return (
    <Sheet title={d?.spec.title ?? 'Exercise'} onClose={onClose}>
      {!d ? <Loading /> : (
        <div className="stack">
          <p className="notice small mb-0">{d.spec.setting}</p>
          {d.spec.stages.map((s, i) => (
            <section key={s.title} aria-labelledby={`st-${i}`}>
              <h3 id={`st-${i}`} className="mini-h">Stage {i + 1} of {d.spec.total}: {s.title}</h3>
              <p className="small measure">{s.narrative}</p>
              {s.questions.map((x) => (
                <div key={x.key} className="ls-q">
                  <Field label={x.text}>
                    <textarea className="input" rows={3} value={r(x.key).answer} readOnly={!!x.points && i < d.stage}
                      onChange={(e) => setResp({ ...resp, [x.key]: { ...r(x.key), answer: e.target.value } })} />
                  </Field>
                  {x.points && (
                    <fieldset className="ls-points"><legend className="xsmall muted">Reference points: tick the ones your answer covered</legend>
                      {x.points.map((p) => (
                        <label key={p} className="check small"><input type="checkbox" checked={r(x.key).covered.includes(p)}
                          onChange={(e) => setResp({ ...resp, [x.key]: { ...r(x.key), covered: e.target.checked ? [...r(x.key).covered, p] : r(x.key).covered.filter((c) => c !== p) } })} /> {p}</label>))}
                    </fieldset>)}
                </div>))}
            </section>))}
          <div className="row wrap">
            <button type="button" className="btn" disabled={!Object.keys(resp).length} onClick={() => save.mutate(false)}>Save answers</button>
            {!d.completed_at && <button type="button" className="btn primary" aria-busy={save.isPending} onClick={() => save.mutate(true)}>
              {d.stage + 1 >= d.spec.total ? 'Finish and show reference points' : 'Next stage'}</button>}
            {d.completed_at && <span className="small muted">Completed {fmtDate(d.completed_at)}. Review the points you missed, and add improvement actions on the Readiness tab.</span>}
          </div>
          <p className="xsmall muted mb-0">Reference points appear after you move on, so you answer first. They are prompts for discussion, not a complete answer key.</p>
        </div>
      )}
    </Sheet>
  )
}

function Exercises({ pid }: { pid: number }) {
  const q = useQuery({ queryKey: ['ls', pid, 'exercises'], queryFn: () => api.get<ExList>(lsPath(pid, '/exercises')) })
  const [open, setOpen] = useState<number | null>(null)
  const [format, setFormat] = useState('individual')
  const start = useMutation({ mutationFn: (scenario: string) => api.post<{ id: number }>(lsPath(pid, '/exercises'), { scenario, format }), onSuccess: (r) => { q.refetch(); setOpen(r.id) } })
  if (!q.data) return q.error ? <ErrorBox error={q.error} /> : <Loading />
  return (
    <div className="stack">
      <p className="xsmall muted measure mb-0">Staged tabletop exercises. Scenarios are fictional and clearly marked as simulated; they never describe events at a real organisation.</p>
      <Field label="Format"><select className="input w-auto" value={format} onChange={(e) => setFormat(e.target.value)}>
        <option value="individual">Individual practice</option><option value="team">Team tabletop</option><option value="guided">Guided investigation</option><option value="interview">Interview preparation</option></select></Field>
      <ul role="list" className="ls-rows">{q.data.available.map((x) => (
        <li key={x.scenario}><button type="button" className="ls-row" onClick={() => start.mutate(x.scenario)}><span className="grow">{x.title}</span><span className="xsmall muted">{x.stages} stages · Start</span></button></li>))}</ul>
      {q.data.runs.length > 0 && <section className="panel"><header><h2>Past runs</h2></header><div className="body"><ul role="list" className="ls-rows">{q.data.runs.map((r) => (
        <li key={r.id}><button type="button" className="ls-row" onClick={() => setOpen(r.id)}><span className="grow">{q.data.available.find((a) => a.scenario === r.scenario)?.title} · {r.format}</span>
          <span className="xsmall muted">{r.completed_at ? `Completed ${fmtDate(r.completed_at)}` : `Stage ${r.stage + 1}`}</span></button></li>))}</ul></div></section>}
      {open && <ExerciseSheet pid={pid} id={open} onClose={() => { setOpen(null); q.refetch() }} />}
    </div>
  )
}

export function Respond({ data }: { data: ProfileResponse }) {
  const [params, setParams] = useSearchParams()
  const sub = SUBS.find(([k]) => k === params.get('sub'))?.[0] ?? 'readiness'
  const pid = data.profile.id
  return (
    <div className="stack">
      <div className="seg ls-seg" role="group" aria-label="Section">
        {SUBS.map(([k, l]) => <button key={k} type="button" aria-pressed={sub === k} onClick={() => setParams((p) => { const n = new URLSearchParams(p); n.set('sub', k); return n }, { replace: true })}>{l}</button>)}
      </div>
      {sub === 'readiness' ? <ReadinessView pid={pid} /> : sub === 'playbooks' ? <Playbooks pid={pid} /> : <Exercises pid={pid} />}
    </div>
  )
}
