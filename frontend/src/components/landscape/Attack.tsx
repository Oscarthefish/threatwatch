import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '../../api'
import { ErrorBox, ExtLink, Field, fmtDate, Loading, useToast } from '../ui'
import { Sheet } from '../Sheet'
import { useInvalidate } from './Overview'
import { BASIS, type Basis, DETECTION, lsPath, PRIORITY_CLASS, type ProfileResponse, TELEMETRY_STATUS } from '../../landscape'

interface Cell { id: string; name: string; basis: Basis; all_basis: Basis[]; findings: { key: string; title: string; priority: string }[]; groups: string[]; detection: string; telemetry: string }
interface Matrix { attack_version: string | null; loaded: boolean; tactics: { attack_id: string; shortname: string; name: string; url: string; techniques: Cell[] }[]; unresolved: string[] }
interface Detail {
  attack_id: string; name: string; description: string; url: string; tactics: string[]; platforms: string[]; note: string | null; resolved_from: string | null
  parent: { attack_id: string; name: string } | null
  mitigations: { attack_id: string; name: string; description: string; url: string }[]
  detections: { attack_id: string; name: string; url: string; analytics: { id: string; platforms: string[]; description: string; log_sources: { name: string; channel: string }[] }[] }[]
  used_by: { groups: { attack_id: string; name: string; url: string }[]; group_count: number; software_count: number }
  guidance: { key: string; title: string }[]
  profile?: { findings: { key: string; title: string; priority: string }[]; basis: Basis[]; groups: string[]; notes: string[]; articles: { id: number; title: string; source: string; published_at: string }[] }
  coverage?: { telemetry: string; detection: string; note: string }
}
interface Coverage { backlog: { id: string; name: string; basis: Basis; priority: string; telemetry: string; detection: string; step: string }[]; totals: Record<string, number>; note: string }

const SHORT: Record<Basis, string> = { reported: 'Reported', group: 'Group', keyword: 'Inferred', guidance: 'Guidance' }

function TechniqueSheet({ pid, tid, onClose }: { pid: number; tid: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['ls', pid, 'tech', tid], queryFn: () => api.get<Detail>(lsPath(pid, `/attack/${tid}`)) })
  const inval = useInvalidate(pid)
  const toast = useToast()
  const [cov, setCov] = useState<{ telemetry: string; detection: string; note: string } | null>(null)
  const c = cov ?? q.data?.coverage ?? { telemetry: 'unknown', detection: 'unknown', note: '' }
  const save = useMutation({ mutationFn: () => api.put(lsPath(pid, `/coverage/${tid}`), c), onSuccess: () => { inval(); toast('Coverage saved') } })
  const d = q.data
  return (
    <Sheet title={d ? `${d.attack_id} ${d.name}` : tid} onClose={onClose}>
      {q.isLoading ? <Loading /> : q.error || !d ? <ErrorBox error={q.error} /> : (
        <div className="stack">
          {d.note && <p className="notice small">{d.note}</p>}
          <p className="xsmall muted mb-0">{d.tactics.join(', ')} · {d.platforms.join(', ')}{d.parent ? ` · sub-technique of ${d.parent.attack_id} ${d.parent.name}` : ''} · <ExtLink href={d.url}>MITRE ATT&CK</ExtLink></p>
          <p className="measure prewrap small mb-0">{d.description}</p>
          {d.profile && (
            <section>
              <h3 className="mini-h">Why it is on this profile</h3>
              <ul className="claims">
                {d.profile.basis.map((b) => <li key={b}>{BASIS[b]}</li>)}
                {d.profile.groups.length > 0 && <li>Groups: {d.profile.groups.join(', ')}</li>}
                {d.profile.findings.map((f) => <li key={f.key}><span className={`sev ${PRIORITY_CLASS[f.priority]}`}>{f.priority}</span> {f.title}</li>)}
              </ul>
              {d.profile.articles.length > 0 && <ul className="claims">{d.profile.articles.map((a) => <li key={a.id}><Link to={`/article/${a.id}`}>{a.title}</Link> <span className="xsmall muted">{a.source}, {fmtDate(a.published_at)}</span></li>)}</ul>}
              <p className="xsmall muted mb-0">Relevance to the profile, not evidence that the technique was used against the organisation.</p>
            </section>
          )}
          <section>
            <h3 className="mini-h">Detection coverage for this profile</h3>
            <div className="ls-cov-form">
              <Field label="Telemetry"><select className="input" value={c.telemetry} onChange={(e) => setCov({ ...c, telemetry: e.target.value })}>{Object.entries(TELEMETRY_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
              <Field label="Detection"><select className="input" value={c.detection} onChange={(e) => setCov({ ...c, detection: e.target.value })}>{Object.entries(DETECTION).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
            </div>
            <Field label="Note" hint="Rule names, known gaps, last test date."><textarea className="input" rows={2} value={c.note} onChange={(e) => setCov({ ...c, note: e.target.value })} /></Field>
            <button type="button" className="btn" aria-busy={save.isPending} onClick={() => save.mutate()}>Save coverage</button>
            <p className="xsmall muted">“Validated” means tested with simulated activity. Collecting the telemetry alone does not mean a detection exists.</p>
          </section>
          {d.detections.length > 0 && (
            <section>
              <h3 className="mini-h">MITRE detection strategies</h3>
              {d.detections.map((s) => (
                <details key={s.attack_id} className="ls-det">
                  <summary><span className="mono-id">{s.attack_id}</span> {s.name}</summary>
                  <ul className="claims">{s.analytics.map((a) => (
                    <li key={a.id}><strong>{a.platforms.join(', ')}</strong>: {a.description}
                      {a.log_sources.length > 0 && <div className="xsmall muted">Log sources: {a.log_sources.map((l) => `${l.name} (${l.channel})`).join('; ')}</div>}</li>))}</ul>
                  <ExtLink href={s.url} className="xsmall">Open on attack.mitre.org</ExtLink>
                </details>))}
            </section>
          )}
          {d.guidance.length > 0 && <p className="small mb-0">Threat Watch monitoring guidance: {d.guidance.map((g) => g.title).join('; ')} (Monitor, hunt, harden tab).</p>}
          {d.mitigations.length > 0 && (
            <section>
              <h3 className="mini-h">Mitigations</h3>
              <ul className="claims">{d.mitigations.map((m) => <li key={m.attack_id}><ExtLink href={m.url}><span className="mono-id">{m.attack_id}</span> {m.name}</ExtLink>{m.description && <div className="xsmall muted clamp-3">{m.description}</div>}</li>)}</ul>
            </section>
          )}
          <p className="xsmall muted mb-0">Used by {d.used_by.group_count} groups and {d.used_by.software_count} software entries in ATT&CK.</p>
        </div>
      )}
    </Sheet>
  )
}

export function AttackTab({ data }: { data: ProfileResponse }) {
  const pid = data.profile.id
  const q = useQuery({ queryKey: ['ls', pid, 'attack', data.assessment?.id], queryFn: () => api.get<Matrix>(lsPath(pid, '/attack')) })
  const cov = useQuery({ queryKey: ['ls', pid, 'coverage', data.assessment?.id], queryFn: () => api.get<Coverage>(lsPath(pid, '/coverage')) })
  const [basis, setBasis] = useState<Basis | 'evidence' | ''>('evidence')
  const [finding, setFinding] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  if (q.isLoading) return <Loading />
  if (q.error || !q.data) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />
  const m = q.data
  if (!m.loaded) return <p className="notice">ATT&CK data has not been synced yet. It downloads weekly from MITRE; check Settings, Sources.</p>
  const keep = (c: Cell) => (!basis || (basis === 'evidence' ? c.basis === 'reported' || c.basis === 'group' : c.all_basis.includes(basis)))
    && (!finding || c.findings.some((f) => f.key === finding))
  const findings = data.assessment!.findings
  const shown = m.tactics.map((t) => ({ ...t, techniques: t.techniques.filter(keep) }))
  const total = new Set(shown.flatMap((t) => t.techniques.map((c) => c.id))).size
  return (
    <div className="stack">
      <div className="row between wrap">
        <p className="small muted measure mb-0">ATT&CK Enterprise v{m.attack_version}. Techniques relevant to this profile, by how strongly the evidence supports them. Select one for MITRE's description, detection strategies, mitigations and your coverage.</p>
        <a className="btn small" href={lsPath(pid, '/navigator')} download>Export Navigator layer</a>
      </div>
      <div className="row wrap">
        <div className="seg ls-seg" role="group" aria-label="Filter by basis">
          <button type="button" aria-pressed={basis === 'evidence'} onClick={() => setBasis('evidence')}>Reporting and groups</button>
          <button type="button" aria-pressed={basis === ''} onClick={() => setBasis('')}>All</button>
          {(['reported', 'group', 'keyword', 'guidance'] as Basis[]).map((b) => <button key={b} type="button" aria-pressed={basis === b} onClick={() => setBasis(b)}>{SHORT[b]}</button>)}
        </div>
        <label className="ls-inline-field"><span className="xsmall">Threat</span>
          <select className="input w-auto" value={finding} onChange={(e) => setFinding(e.target.value)}>
            <option value="">All threats</option>{findings.map((f) => <option key={f.key} value={f.key}>{f.priority.code} {f.title}</option>)}
          </select></label>
      </div>
      <ul className="ls-legend" role="list" aria-label="Legend">
        {(['reported', 'group', 'keyword', 'guidance'] as Basis[]).map((b) => <li key={b}><span className={`ls-swatch ${b}`} aria-hidden="true" />{BASIS[b]}</li>)}
      </ul>
      <p className="xsmall muted mb-0" aria-live="polite">{total} technique{total === 1 ? '' : 's'} shown.{basis === 'evidence' && total === 0 ? ' No technique is named in the evidence or documented for its groups; choose All to see guidance mappings.' : ''}</p>
      <div className="ls-matrix" role="region" aria-label="ATT&CK matrix" tabIndex={0}>
        {shown.map((t) => (
          <section key={t.attack_id} className="ls-tactic" aria-labelledby={`tac-${t.attack_id}`}>
            <h3 id={`tac-${t.attack_id}`} className="ls-tactic-h">{t.name} <span className="faint">{t.techniques.length}</span></h3>
            <ul role="list">
              {t.techniques.map((c) => (
                <li key={c.id}>
                  <button type="button" className={`ls-cell ${c.basis}`} onClick={() => setOpen(c.id)}>
                    <span className="mono-id">{c.id}</span> <span className="ls-cell-name">{c.name}</span>
                    <span className="ls-cell-meta">{SHORT[c.basis]} · {DETECTION[c.detection]}</span>
                  </button>
                </li>))}
            </ul>
          </section>
        ))}
      </div>
      {m.unresolved.length > 0 && <p className="xsmall muted">Not in this ATT&CK release: {m.unresolved.join(', ')}.</p>}
      <section className="panel" aria-labelledby="cov-h">
        <header><h2 id="cov-h">Detection backlog</h2></header>
        <div className="body">
          {cov.isLoading ? <Loading lines={2} /> : cov.data && <>
            <p className="xsmall muted">{cov.data.note} Recorded: {Object.entries(cov.data.totals).map(([k, v]) => `${DETECTION[k]} ${v}`).join(', ')}.</p>
            {cov.data.backlog.length === 0 ? <p className="small muted mb-0">Nothing outstanding for evidence-based techniques.</p> : (
              <div className="table-wrap" tabIndex={0} role="region" aria-label="Scrollable table"><table className="ls-table">
                <thead><tr><th scope="col">Technique</th><th scope="col">Priority</th><th scope="col">Basis</th><th scope="col">Telemetry</th><th scope="col">Detection</th><th scope="col">Next step</th></tr></thead>
                <tbody>{cov.data.backlog.slice(0, 30).map((r) => (
                  <tr key={r.id}><td><button type="button" className="link" onClick={() => setOpen(r.id)}><span className="mono-id">{r.id}</span> {r.name}</button></td>
                    <td><span className={`sev ${PRIORITY_CLASS[r.priority]}`}>{r.priority}</span></td><td>{SHORT[r.basis]}</td>
                    <td>{TELEMETRY_STATUS[r.telemetry]}</td><td>{DETECTION[r.detection]}</td><td>{r.step}</td></tr>))}</tbody>
              </table></div>)}
          </>}
        </div>
      </section>
      {open && <TechniqueSheet pid={pid} tid={open} onClose={() => setOpen(null)} />}
    </div>
  )
}
