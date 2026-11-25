import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, ApiError } from '../../api'
import { copy, ErrorBox, ExtLink, Field, fmtDate, Loading, techniqueUrl, TimeAgo, useToast } from '../ui'
import { Sheet } from '../Sheet'
import { useInvalidate } from './Overview'
import { CONTROL_STATUS, HUNT_STATUS, lsPath, PRIORITY_CLASS, type ProfileResponse, TELEMETRY_STATUS } from '../../landscape'

type Ref = { key: string; title: string; priority: string }
type Tel = { key: string; label: string; detail: string; status: string }
type Tech = { id: string; name: string | null; note: string | null }
interface Mon { key: string; title: string; behaviour: string; why: string; fields: string; correlation: string; logic: string; false_positives: string; severity: string; escalation: string; techniques: Tech[]; telemetry: Tel[]; queries: { platform: string; query: string; status: string }[]; findings: Ref[] }
interface HuntT { key: string; title: string; hypothesis: string; timeframe: string; systems: string; indicators: string[]; behaviours: string[]; steps: string[]; expected: string; false_positives: string[]; evidence: string[]; escalation: string; techniques: Tech[]; telemetry: Tel[]; blocked_by: string[]; findings: Ref[] }
interface Hard { key: string; title: string; action: string; why: string; priority: string; complexity: string; prerequisites: string; team: string; verify: string; cis: { id: string; name: string }[]; csf: { id: string; name: string }[]; mitigations: { id: string; name: string | null; url: string }[]; status: string; findings: Ref[] }
interface Action { id: number; kind: string; ref: string; title: string; detail: string; priority: string; owner: string; status: string; note: string; updated_at: string }
interface DefendData { monitoring: Mon[]; hunts: HuntT[]; hardening: Hard[]; telemetry: { key: string; label: string; status: string; needed_by: string[] }[]; query_note: string; saved_hunts: { id: number; template: string; title: string; status: string; updated_at: string }[]; actions: Action[] }
interface HuntRow { id: number; title: string; status: string; notes: string; conclusion: string; limitations: string; created_at: string; updated_at: string; plan: HuntT & { finding: Ref | null; intelligence: { title: string; url: string; source: string; published_at: string }[]; groups: string[] } }

const PLATFORM: Record<string, string> = { splunk: 'Splunk SPL', sentinel: 'Sentinel / Defender KQL', xdr: 'Cortex XDR XQL' }
const SUBS = [['monitoring', 'Monitoring'], ['hunts', 'Hunting'], ['hardening', 'Hardening'], ['telemetry', 'Telemetry'], ['actions', 'Actions']] as const

function Refs({ items }: { items: Ref[] }) {
  return <p className="xsmall muted mb-0">Supports: {items.slice(0, 4).map((f, i) => <span key={f.key}>{i > 0 && '; '}<span className={`sev ${PRIORITY_CLASS[f.priority]}`}>{f.priority}</span> {f.title}</span>)}</p>
}
function Techs({ items }: { items: Tech[] }) {
  return <ul role="list" className="chips">{items.map((t) => <li key={t.id}><a className="chip link-chip" href={techniqueUrl(t.id) ?? undefined} target="_blank" rel="noopener noreferrer" title={t.note ?? undefined}>{t.id} {t.name ?? ''}</a></li>)}</ul>
}
function TelList({ items }: { items: Tel[] }) {
  return <ul className="claims">{items.map((t) => <li key={t.key}><strong>{t.label}</strong> <span className={`ls-tel ${t.status}`}>{TELEMETRY_STATUS[t.status]}</span><div className="xsmall muted">{t.detail}</div></li>)}</ul>
}

function useAddAction(pid: number) {
  const inval = useInvalidate(pid)
  const toast = useToast()
  return useMutation({
    mutationFn: (b: { kind: string; ref: string; title: string; detail: string; priority: string }) => api.post(lsPath(pid, '/actions'), b),
    onSuccess: () => { inval(); toast('Added to actions') },
    onError: (e) => toast(e instanceof ApiError && e.status === 409 ? 'Already on the action list' : 'Could not add', 'error'),
  })
}

function Monitoring({ pid, d }: { pid: number; d: DefendData }) {
  const toast = useToast()
  const add = useAddAction(pid)
  return (
    <div className="stack">
      <p className="xsmall muted measure mb-0">Vendor-neutral monitoring guidance for the threats on this profile, ordered by the priority they support. {d.query_note}</p>
      {d.monitoring.map((m) => (
        <details key={m.key} className="panel ls-details">
          <summary><h3 className="ls-finding-title">{m.title}</h3><Refs items={m.findings} /></summary>
          <div className="body stack">
            <dl className="kv ls-kv">
              <dt>What to monitor</dt><dd>{m.behaviour}</dd>
              <dt>Why it matters</dt><dd>{m.why}</dd>
              <dt>Fields and event IDs</dt><dd>{m.fields}</dd>
              <dt>Correlate with</dt><dd>{m.correlation}</dd>
              <dt>Detection logic</dt><dd>{m.logic}</dd>
              <dt>False positives</dt><dd>{m.false_positives}</dd>
              <dt>Severity</dt><dd>{m.severity}</dd>
              <dt>Escalate when</dt><dd>{m.escalation}</dd>
            </dl>
            <div><h4 className="mini-h">Telemetry needed</h4><TelList items={m.telemetry} /></div>
            <Techs items={m.techniques} />
            {m.queries.map((q) => (
              <div key={q.platform} className="ls-query">
                <div className="row between"><span className="xsmall"><strong>{PLATFORM[q.platform]}</strong> · <span className="ls-label">Conceptual, not syntax-checked or tested</span></span>
                  <button type="button" className="btn small quiet" onClick={() => copy(q.query, toast)}>Copy</button></div>
                <pre><code>{q.query}</code></pre>
              </div>))}
            <div><button type="button" className="btn small" onClick={() => add.mutate({ kind: 'detection', ref: m.key, title: `Detection: ${m.title}`, detail: m.logic, priority: m.findings[0]?.priority <= 'P2' ? 'high' : 'medium' })}>Add to actions</button></div>
          </div>
        </details>))}
    </div>
  )
}

function HuntSheet({ pid, id, onClose }: { pid: number; id: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ['ls', pid, 'hunt', id], queryFn: () => api.get<HuntRow>(lsPath(pid, `/hunts/${id}`)) })
  const inval = useInvalidate(pid)
  const toast = useToast()
  const [edit, setEdit] = useState<Partial<HuntRow>>({})
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => api.patch(lsPath(pid, `/hunts/${id}`), edit),
    onSuccess: () => { inval(); q.refetch(); setEdit({}); toast('Hunt saved') },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'Could not save'),
  })
  const h = q.data
  const v = <K extends keyof HuntRow>(k: K) => (edit[k] ?? h?.[k] ?? '') as string
  return (
    <Sheet title={h?.title ?? 'Hunt'} onClose={onClose}>
      {!h ? <Loading /> : (
        <div className="stack">
          <p className="small mb-0"><strong>Hypothesis:</strong> {h.plan.hypothesis}</p>
          {h.plan.finding && <p className="xsmall muted mb-0">From <span className={`sev ${PRIORITY_CLASS[h.plan.finding.priority]}`}>{h.plan.finding.priority}</span> {h.plan.finding.title}{h.plan.groups.length ? `; groups in the evidence: ${h.plan.groups.join(', ')}` : ''}. Started {fmtDate(h.created_at)}.</p>}
          {h.plan.intelligence.length > 0 && <div><h4 className="mini-h">Supporting intelligence</h4><ul className="claims">{h.plan.intelligence.map((i) => <li key={i.url}><ExtLink href={i.url}>{i.title}</ExtLink> <span className="xsmall muted">{i.source}, {fmtDate(i.published_at)}</span></li>)}</ul></div>}
          <dl className="kv ls-kv"><dt>Systems</dt><dd>{h.plan.systems}</dd><dt>Timeframe</dt><dd>{h.plan.timeframe}</dd><dt>Escalate when</dt><dd>{h.plan.escalation}</dd><dt>Expected outcome</dt><dd>{h.plan.expected}</dd></dl>
          <div><h4 className="mini-h">Telemetry</h4><TelList items={h.plan.telemetry} /></div>
          <Techs items={h.plan.techniques} />
          <div><h4 className="mini-h">Initial indicators</h4><ul className="claims">{h.plan.indicators.map((x) => <li key={x}>{x}</li>)}</ul></div>
          <div><h4 className="mini-h">Suspicious behaviour</h4><ul className="claims">{h.plan.behaviours.map((x) => <li key={x}>{x}</li>)}</ul></div>
          <div><h4 className="mini-h">Investigation steps</h4><ol className="ls-steps">{h.plan.steps.map((x) => <li key={x}>{x}</li>)}</ol></div>
          <div><h4 className="mini-h">False positives</h4><ul className="claims">{h.plan.false_positives.map((x) => <li key={x}>{x}</li>)}</ul></div>
          <div><h4 className="mini-h">Evidence to collect</h4><ul className="claims">{h.plan.evidence.map((x) => <li key={x}>{x}</li>)}</ul></div>
          <hr className="divider" />
          <Field label="Status">
            <select className="input" value={v('status')} onChange={(e) => setEdit({ ...edit, status: e.target.value })}>{Object.entries(HUNT_STATUS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          </Field>
          <Field label="Investigation notes"><textarea className="input" rows={5} value={v('notes')} onChange={(e) => setEdit({ ...edit, notes: e.target.value })} /></Field>
          <Field label="Conclusion" hint="Required to close. Record what was checked even when nothing was found."><textarea className="input" rows={3} value={v('conclusion')} onChange={(e) => setEdit({ ...edit, conclusion: e.target.value })} /></Field>
          <Field label="Limitations" hint="Missing telemetry, short retention, systems not covered."><textarea className="input" rows={2} value={v('limitations')} onChange={(e) => setEdit({ ...edit, limitations: e.target.value })} /></Field>
          {error && <p className="field-error" role="alert">{error}</p>}
          <div className="row"><button type="button" className="btn primary" aria-busy={save.isPending} disabled={!Object.keys(edit).length} onClick={() => { setError(null); save.mutate() }}>Save</button>
            <span className="xsmall muted">Updated <TimeAgo iso={h.updated_at} /></span></div>
        </div>
      )}
    </Sheet>
  )
}

function Hunts({ pid, d }: { pid: number; d: DefendData }) {
  const inval = useInvalidate(pid)
  const [open, setOpen] = useState<number | null>(null)
  const start = useMutation({
    mutationFn: (h: HuntT) => api.post<{ id: number }>(lsPath(pid, '/hunts'), { template: h.key, finding_key: h.findings[0]?.key }),
    onSuccess: (r) => { inval(); setOpen(r.id) },
  })
  return (
    <div className="stack">
      {d.saved_hunts.length > 0 && (
        <section className="panel"><header><h2>Your hunts</h2></header><div className="body">
          <ul role="list" className="ls-rows">{d.saved_hunts.map((h) => (
            <li key={h.id}><button type="button" className="ls-row" onClick={() => setOpen(h.id)}><span className="grow">{h.title}</span><span className={`ls-status ${h.status}`}>{HUNT_STATUS[h.status]}</span><span className="xsmall muted"><TimeAgo iso={h.updated_at} /></span></button></li>))}</ul>
        </div></section>
      )}
      <p className="xsmall muted measure mb-0">Hunt hypotheses for the threats on this profile. Starting a hunt saves an editable copy with the supporting intelligence, so you can record notes, a conclusion and the limits of what you could check.</p>
      {d.hunts.map((h) => (
        <article key={h.key} className="panel">
          <header><h3 className="ls-finding-title">{h.title}</h3><button type="button" className="btn small" aria-busy={start.isPending} onClick={() => start.mutate(h)}>Start hunt</button></header>
          <div className="body stack-tight">
            <p className="small mb-0">{h.hypothesis}</p>
            <Refs items={h.findings} />
            <p className="xsmall muted mb-0">Telemetry: {h.telemetry.map((t) => `${t.label} (${TELEMETRY_STATUS[t.status].toLowerCase()})`).join(', ')}</p>
            {h.blocked_by.length > 0 && <p className="notice small mb-0">Blocked until available: {h.blocked_by.join(', ')}.</p>}
          </div>
        </article>))}
      {open && <HuntSheet pid={pid} id={open} onClose={() => setOpen(null)} />}
    </div>
  )
}

function Hardening({ pid, d }: { pid: number; d: DefendData }) {
  const add = useAddAction(pid)
  return (
    <div className="stack">
      <p className="xsmall muted measure mb-0">Preventive measures for the threats on this profile. Status comes from the controls recorded on the Overview tab; anything not recorded is shown as unknown, not as missing.</p>
      {d.hardening.map((x) => (
        <details key={x.key} className="panel ls-details">
          <summary>
            <div className="row between top"><h3 className="ls-finding-title">{x.title}</h3><span className={`ls-ctl ${x.status}`}>{CONTROL_STATUS[x.status]}</span></div>
            <Refs items={x.findings} />
          </summary>
          <div className="body stack">
            <dl className="kv ls-kv">
              <dt>Action</dt><dd>{x.action}</dd><dt>Business justification</dt><dd>{x.why}</dd>
              <dt>Priority</dt><dd>{x.priority}</dd><dt>Complexity</dt><dd>{x.complexity}</dd>
              {x.prerequisites && <><dt>Prerequisites</dt><dd>{x.prerequisites}</dd></>}
              <dt>Suggested owner</dt><dd>{x.team}</dd><dt>Verify by</dt><dd>{x.verify}</dd>
              {x.cis.length > 0 && <><dt>CIS Controls v8.1</dt><dd>{x.cis.map((c) => `${c.id} ${c.name}`).join('; ')}</dd></>}
              {x.csf.length > 0 && <><dt>NIST CSF 2.0</dt><dd>{x.csf.map((c) => `${c.id} ${c.name}`).join('; ')}</dd></>}
              {x.mitigations.length > 0 && <><dt>ATT&CK mitigations</dt><dd>{x.mitigations.map((m, i) => <span key={m.id}>{i > 0 && '; '}<ExtLink href={m.url}>{m.id} {m.name ?? ''}</ExtLink></span>)}</dd></>}
            </dl>
            <div><button type="button" className="btn small" onClick={() => add.mutate({ kind: 'hardening', ref: x.key, title: x.title, detail: x.action, priority: x.priority })}>Add to actions</button></div>
          </div>
        </details>))}
    </div>
  )
}

function Actions({ pid, d }: { pid: number; d: DefendData }) {
  const inval = useInvalidate(pid)
  const patch = useMutation({ mutationFn: ({ id, ...b }: { id: number; status?: string; owner?: string }) => api.patch(lsPath(pid, `/actions/${id}`), b), onSuccess: inval })
  const del = useMutation({ mutationFn: (id: number) => api.del(lsPath(pid, `/actions/${id}`)), onSuccess: inval })
  if (!d.actions.length) return <p className="muted">No saved actions. Use “Add to actions” on monitoring, hardening or readiness items.</p>
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Scrollable table">
      <table className="ls-table">
        <thead><tr><th scope="col">Action</th><th scope="col">Type</th><th scope="col">Priority</th><th scope="col">Owner</th><th scope="col">Status</th><th scope="col"><span className="sr-only">Remove</span></th></tr></thead>
        <tbody>{d.actions.map((a) => (
          <tr key={a.id}>
            <td>{a.title}<div className="xsmall muted">{a.detail}</div></td><td>{a.kind}</td><td>{a.priority}</td>
            <td><input className="input" aria-label={`Owner for ${a.title}`} defaultValue={a.owner} onBlur={(e) => e.target.value !== a.owner && patch.mutate({ id: a.id, owner: e.target.value })} /></td>
            <td><select className="input" aria-label={`Status of ${a.title}`} value={a.status} onChange={(e) => patch.mutate({ id: a.id, status: e.target.value })}>
              <option value="open">Open</option><option value="in_progress">In progress</option><option value="done">Done</option><option value="wont_do">Won't do</option></select></td>
            <td><button type="button" className="btn small quiet" aria-label={`Remove ${a.title}`} onClick={() => del.mutate(a.id)}>Remove</button></td>
          </tr>))}</tbody>
      </table>
    </div>
  )
}

export function Defend({ data }: { data: ProfileResponse }) {
  const pid = data.profile.id
  const [params, setParams] = useSearchParams()
  const sub = (SUBS.find(([k]) => k === params.get('sub'))?.[0] ?? 'monitoring')
  const q = useQuery({ queryKey: ['ls', pid, 'defend', data.assessment?.id, data.profile.updated_at], queryFn: () => api.get<DefendData>(lsPath(pid, '/defend')) })
  return (
    <div className="stack">
      <div className="seg ls-seg" role="group" aria-label="Section">
        {SUBS.map(([k, l]) => <button key={k} type="button" aria-pressed={sub === k} onClick={() => setParams((p) => { const n = new URLSearchParams(p); n.set('sub', k); return n }, { replace: true })}>{l}{k === 'actions' && q.data ? ` (${q.data.actions.filter((a) => a.status !== 'done' && a.status !== 'wont_do').length})` : ''}</button>)}
      </div>
      {q.isLoading ? <Loading /> : q.error || !q.data ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> :
        sub === 'monitoring' ? <Monitoring pid={pid} d={q.data} /> : sub === 'hunts' ? <Hunts pid={pid} d={q.data} /> : sub === 'hardening' ? <Hardening pid={pid} d={q.data} />
          : sub === 'actions' ? <Actions pid={pid} d={q.data} /> : (
            <div className="stack">
              <p className="xsmall muted measure mb-0">Log sources the recommended monitoring depends on. Record availability on the Overview tab (Available logs). Availability is not detection: record detections per technique on the ATT&CK tab.</p>
              <div className="table-wrap" tabIndex={0} role="region" aria-label="Scrollable table"><table className="ls-table">
                <thead><tr><th scope="col">Log source</th><th scope="col">Status</th><th scope="col">Needed by</th></tr></thead>
                <tbody>{q.data.telemetry.map((t) => <tr key={t.key}><td>{t.label}</td><td><span className={`ls-tel ${t.status}`}>{TELEMETRY_STATUS[t.status]}</span></td><td className="small">{t.needed_by.join('; ')}</td></tr>)}</tbody>
              </table></div>
            </div>)}
    </div>
  )
}
