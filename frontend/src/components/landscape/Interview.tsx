import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, ApiError } from '../../api'
import { ErrorBox, Field, Loading, useToast } from '../ui'
import { useConfirm } from '../Sheet'
import { lsPath, PRIORITY_CLASS, type ProfileResponse } from '../../landscape'

interface IQ { key: string; text: string; category_label: string; points: string[]; pitfalls: string[]; answer: string; covered: string[]; confidence: string; revise: boolean }
interface Prep { id: number; role: string; job_description: string; level: string; questions: IQ[] }
interface Data { profile_kind: string; preps: Prep[]; scenarios: { key: string; title: string; priority: string; because: string }[]; has_assessment: boolean }

function QuestionCard({ pid, prep, q }: { pid: number; prep: number; q: IQ }) {
  const toast = useToast()
  const [answer, setAnswer] = useState(q.answer)
  const [covered, setCovered] = useState(q.covered)
  const [confidence, setConfidence] = useState(q.confidence)
  const [show, setShow] = useState(q.covered.length > 0)
  const save = useMutation({ mutationFn: () => api.put(lsPath(pid, `/interview/${prep}/answers/${q.key}`), { answer, covered, confidence }), onSuccess: () => toast('Saved') })
  const dirty = answer !== q.answer || covered.join() !== q.covered.join() || confidence !== q.confidence
  return (
    <details className="panel ls-details">
      <summary><h3 className="ls-finding-title">{q.text}</h3><p className="xsmall muted mb-0">{q.category_label}{q.answer ? ` · answered${q.revise ? ', revise' : ''}` : ''}</p></summary>
      <div className="body stack">
        <Field label="My answer" hint="Write it as you would say it. Then compare with the reference points."><textarea className="input" rows={5} value={answer} onChange={(e) => setAnswer(e.target.value)} /></Field>
        {!show ? <div><button type="button" className="btn small" onClick={() => setShow(true)}>Compare with reference points</button></div> : (
          <fieldset className="ls-points"><legend className="xsmall muted">Reference points: tick the ones your answer covers</legend>
            {q.points.map((p) => <label key={p} className="check small"><input type="checkbox" checked={covered.includes(p)} onChange={(e) => setCovered(e.target.checked ? [...covered, p] : covered.filter((c) => c !== p))} /> {p}</label>)}
            <p className="xsmall muted mb-0">Pitfalls: {q.pitfalls.join('; ')}</p>
          </fieldset>)}
        <Field label="How confident are you?">
          <select className="input w-auto" value={confidence} onChange={(e) => setConfidence(e.target.value)}>
            <option value="">Not rated</option><option value="revise">Needs revision</option><option value="ok">Comfortable</option><option value="strong">Strong</option>
          </select>
        </Field>
        <div><button type="button" className="btn primary" disabled={!dirty} aria-busy={save.isPending} onClick={() => save.mutate()}>Save</button></div>
      </div>
    </details>
  )
}

export function Interview({ data }: { data: ProfileResponse }) {
  const pid = data.profile.id
  const q = useQuery({ queryKey: ['ls', pid, 'interview'], queryFn: () => api.get<Data>(lsPath(pid, '/interview')) })
  const [role, setRole] = useState('Senior Cyber Security Analyst')
  const [jd, setJd] = useState('')
  const [error, setError] = useState<string | null>(null)
  const confirm = useConfirm()
  const create = useMutation({ mutationFn: () => api.post(lsPath(pid, '/interview'), { role, job_description: jd }), onSuccess: () => q.refetch(),
    onError: (e) => setError(e instanceof ApiError ? e.message : 'Could not create') })
  const del = useMutation({ mutationFn: (id: number) => api.del(lsPath(pid, `/interview/${id}`)), onSuccess: () => q.refetch() })
  if (q.isLoading) return <Loading />
  if (!q.data) return <ErrorBox error={q.error} />
  const d = q.data
  return (
    <div className="stack">
      <p className="small muted measure mb-0">A discussion aid for interviews with this {d.profile_kind === 'organisation' ? 'organisation' : 'sector'}: its public profile, the threats relevant to it, and practice questions for the role. Threats are relevance to the sector and profile, never claims about the company's own security.</p>
      <div className="row wrap">
        <a className="btn" href={lsPath(pid, '/export.md')} download>Download briefing (.md)</a>
        {!d.has_assessment && <span className="xsmall muted">Run an assessment to include the threat landscape.</span>}
      </div>
      {d.scenarios.length > 0 && (
        <section className="panel"><header><h2>Scenarios to be ready to discuss</h2></header><div className="body">
          <ul role="list" className="ls-top">{d.scenarios.map((s) => <li key={s.key}><span className={`sev ${PRIORITY_CLASS[s.priority]}`}>{s.priority}</span> <strong>{s.title}</strong> <span className="xsmall muted">because of {s.because}</span></li>)}</ul>
          <p className="xsmall muted mb-0">Practise them in Readiness and response, Exercises (Interview preparation format), and read the matching playbook draft.</p>
        </div></section>)}
      {d.preps.map((p) => {
        const answered = p.questions.filter((x) => x.answer).length
        const revise = p.questions.filter((x) => x.revise)
        return (
          <section key={p.id} className="stack" aria-labelledby={`prep-${p.id}`}>
            <div className="row between wrap">
              <h2 id={`prep-${p.id}`} className="mb-0">{p.role}</h2>
              <div className="row">
                <a className="btn small" href={lsPath(pid, `/export.md?prep=${p.id}`)} download>Download with answers</a>
                <button type="button" className="btn small quiet" onClick={async () => { if (await confirm({ title: 'Delete this preparation and its answers?', confirmLabel: 'Delete', danger: true })) del.mutate(p.id) }}>Delete</button>
              </div>
            </div>
            <p className="xsmall muted mb-0">{answered} of {p.questions.length} answered.{revise.length ? ` To revise: ${revise.map((x) => x.category_label).join(', ')}.` : ''}</p>
            {p.questions.map((x) => <QuestionCard key={x.key} pid={pid} prep={p.id} q={x} />)}
          </section>)
      })}
      <section className="panel" aria-labelledby="new-prep-h"><header><h2 id="new-prep-h">{d.preps.length ? 'Prepare for another role' : 'Prepare for a role'}</h2></header>
        <form className="body stack" onSubmit={(e) => { e.preventDefault(); setError(null); create.mutate() }}>
          <Field label="Job title"><input className="input" required minLength={2} maxLength={200} value={role} onChange={(e) => setRole(e.target.value)} /></Field>
          <Field label="Job description (optional)" hint="Stored here for your reference; not sent anywhere."><textarea className="input" rows={4} maxLength={20000} value={jd} onChange={(e) => setJd(e.target.value)} /></Field>
          {error && <p className="field-error" role="alert">{error}</p>}
          <div><button type="submit" className="btn primary" aria-busy={create.isPending}>Create question set</button></div>
        </form>
      </section>
    </div>
  )
}
