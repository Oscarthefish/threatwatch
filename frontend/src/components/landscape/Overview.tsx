import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../../api'
import { Field, fmtDate, TimeAgo, useToast } from '../ui'
import { Sheet, useConfirm } from '../Sheet'
import { ProfileForm, useMeta } from '../../pages/Landscapes'
import {
  CLASSIFICATION, CONTROL_STATUS, FACT_CATEGORIES, type Fact, lsPath, PRIORITY_CLASS, type ProfileResponse, PROVENANCE, type Provenance, TELEMETRY_STATUS,
} from '../../landscape'

export function useInvalidate(id: number) {
  const qc = useQueryClient()
  return () => { qc.invalidateQueries({ queryKey: ['landscape', String(id)] }); qc.invalidateQueries({ queryKey: ['ls', id] }); qc.invalidateQueries({ queryKey: ['landscapes'] }) }
}

export function ProvenanceTag({ p }: { p: Provenance }) {
  return <span className={`ls-prov ${p}`}>{PROVENANCE[p]}</span>
}

function FactSheet({ pid, fact, category, onClose }: { pid: number; fact?: Fact; category: string; onClose: () => void }) {
  const meta = useMeta()
  const inval = useInvalidate(pid)
  const [f, setF] = useState({
    category: fact?.category ?? category, subtype: fact?.subtype ?? '', value: fact?.value ?? '', status: fact?.status ?? (category === 'telemetry' || category === 'control' ? 'unknown' : ''),
    provenance: (fact?.provenance ?? 'user') as Provenance, source_url: fact?.source_url ?? '', source_title: fact?.source_title ?? '',
    verified_at: fact?.verified_at ?? '', note: fact?.note ?? '',
  })
  const [error, setError] = useState<string | null>(null)
  const set = (k: keyof typeof f, v: string) => setF((x) => ({ ...x, [k]: v }))
  const cat = f.category
  const save = useMutation({
    mutationFn: () => {
      const body = { ...f, source_url: f.source_url || null, source_title: f.source_title || null, verified_at: f.verified_at || null,
        value: f.value || (cat === 'telemetry' ? meta.data?.telemetry[f.subtype] : cat === 'control' ? meta.data?.hardening[f.subtype] : '') || '' }
      return fact ? api.put(lsPath(pid, `/facts/${fact.id}`), body) : api.post(lsPath(pid, '/facts'), body)
    },
    onSuccess: () => { inval(); onClose() },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'Could not save'),
  })
  const del = useMutation({ mutationFn: () => api.del(lsPath(pid, `/facts/${fact!.id}`)), onSuccess: () => { inval(); onClose() } })
  return (
    <Sheet title={`${fact ? 'Edit' : 'Add'}: ${FACT_CATEGORIES[cat].label.toLowerCase()}`} onClose={onClose}>
      <form className="stack" onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate() }}>
        {cat === 'tech' && (
          <Field label="Type">
            <select className="input" required value={f.subtype} onChange={(e) => set('subtype', e.target.value)}>
              <option value="">Choose</option>{Object.entries(meta.data?.tech_types ?? {}).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>)}
        {cat === 'telemetry' && <>
          <Field label="Log source">
            <select className="input" required value={f.subtype} onChange={(e) => set('subtype', e.target.value)}>
              <option value="">Choose</option>{Object.entries(meta.data?.telemetry ?? {}).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
          <Field label="Availability" hint="Collected and searchable by the SOC. This is not the same as having detections.">
            <select className="input" value={f.status} onChange={(e) => set('status', e.target.value)}>{Object.entries(TELEMETRY_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
          </Field></>}
        {cat === 'control' && <>
          <Field label="Control">
            <select className="input" required value={f.subtype} onChange={(e) => set('subtype', e.target.value)}>
              <option value="">Choose</option>{Object.entries(meta.data?.hardening ?? {}).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
          <Field label="Status" hint="Only “implemented and tested” lowers a threat's priority, and the reason is shown.">
            <select className="input" value={f.status} onChange={(e) => set('status', e.target.value)}>{Object.entries(CONTROL_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
          </Field></>}
        <Field label={cat === 'tech' ? 'Product' : cat === 'telemetry' || cat === 'control' ? 'Details (optional)' : 'Description'}
          hint={cat === 'tech' ? 'Vendor and product, for example "Fortinet FortiGate" or "Microsoft Exchange Server".' : FACT_CATEGORIES[cat].hint}>
          <input className="input" required={cat !== 'telemetry' && cat !== 'control'} maxLength={500} value={f.value} onChange={(e) => set('value', e.target.value)} />
        </Field>
        <Field label="Where this comes from">
          <select className="input" value={f.provenance} onChange={(e) => set('provenance', e.target.value)}>
            {Object.entries(PROVENANCE).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </Field>
        {f.provenance === 'public' && <>
          <Field label="Source URL" hint="Required for public facts."><input className="input" type="url" required value={f.source_url} onChange={(e) => set('source_url', e.target.value)} /></Field>
          <Field label="Source title (optional)"><input className="input" maxLength={300} value={f.source_title} onChange={(e) => set('source_title', e.target.value)} /></Field>
          <Field label="Checked on (optional)"><input className="input" type="date" value={f.verified_at.slice(0, 10)} onChange={(e) => set('verified_at', e.target.value)} /></Field>
        </>}
        {f.provenance === 'inferred' && <p className="xsmall muted mb-0">Inferred facts are shown as assumptions and are never treated as verified.</p>}
        <Field label="Note (optional)"><textarea className="input" rows={2} maxLength={2000} value={f.note} onChange={(e) => set('note', e.target.value)} /></Field>
        {error && <p className="field-error" role="alert">{error}</p>}
        <div className="row">
          <button type="submit" className="btn primary" aria-busy={save.isPending}>Save</button>
          {fact && <button type="button" className="btn danger" onClick={() => del.mutate()}>Remove</button>}
        </div>
      </form>
    </Sheet>
  )
}

function FactList({ data, category, onEdit }: { data: ProfileResponse; category: string; onEdit: (f: Fact | null, c: string) => void }) {
  const meta = useMeta()
  const facts = data.profile.facts.filter((f) => f.category === category)
  const label = (f: Fact) => category === 'tech' ? `${meta.data?.tech_types[f.subtype] ?? f.subtype}: ${f.value}`
    : category === 'telemetry' ? `${meta.data?.telemetry[f.subtype] ?? f.subtype}: ${TELEMETRY_STATUS[f.status || 'unknown']}`
      : category === 'control' ? `${meta.data?.hardening[f.subtype] ?? f.subtype}: ${CONTROL_STATUS[f.status || 'unknown']}` : f.value
  return (
    <div className="ls-facts">
      <div className="row between">
        <h3 className="mini-h">{FACT_CATEGORIES[category].label}</h3>
        <button type="button" className="btn small" onClick={() => onEdit(null, category)} aria-label={`Add ${FACT_CATEGORIES[category].label.toLowerCase()}`}>Add</button>
      </div>
      {facts.length === 0 ? <p className="xsmall faint mb-0">None recorded. Treated as unknown.</p> : (
        <ul role="list" className="ls-fact-list">
          {facts.map((f) => (
            <li key={f.id}>
              <button type="button" className="ls-fact" onClick={() => onEdit(f, category)}>
                <span className="grow">{label(f)}{category !== 'tech' && (category === 'telemetry' || category === 'control') && f.value && f.value !== meta.data?.telemetry[f.subtype] && f.value !== meta.data?.hardening[f.subtype] ? <span className="muted"> ({f.value})</span> : null}</span>
                <ProvenanceTag p={f.provenance} />
              </button>
              {f.source_url && <a className="xsmall" href={f.source_url} target="_blank" rel="noopener noreferrer">{f.source_title || new URL(f.source_url).hostname}</a>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Options({ data }: { data: ProfileResponse }) {
  const meta = useMeta()
  const p = data.profile
  const inval = useInvalidate(p.id)
  const save = useMutation({ mutationFn: (options: object) => api.patch(lsPath(p.id), { options }), onSuccess: inval })
  const o = p.options
  return (
    <details className="panel ls-details">
      <summary><h2>Assessment options</h2></summary>
      <div className="body stack">
        <Field label="Look back">
          <select className="input w-auto" value={o.lookback_days} onChange={(e) => save.mutate({ lookback_days: Number(e.target.value) })}>
            {[30, 60, 90, 180, 365].map((d) => <option key={d} value={d}>{d} days</option>)}
          </select>
        </Field>
        <label className="check"><input type="checkbox" checked={o.use_claims} onChange={(e) => save.mutate({ use_claims: e.target.checked })} /> Use ransomware leak-site claims (unverified, from ransomware.live)</label>
        <fieldset><legend className="field-label">Example query platforms</legend>
          {[['splunk', 'Splunk'], ['sentinel', 'Microsoft Sentinel / Defender (KQL)'], ['xdr', 'Cortex XDR (XQL)']].map(([k, v]) => (
            <label key={k} className="check"><input type="checkbox" checked={o.platforms.includes(k)}
              onChange={(e) => save.mutate({ platforms: e.target.checked ? [...o.platforms, k] : o.platforms.filter((x) => x !== k) })} /> {v}</label>))}
        </fieldset>
        <fieldset><legend className="field-label">Sources to leave out</legend>
          <div className="ls-cols">{meta.data?.sources.map((s) => (
            <label key={s.key} className="check"><input type="checkbox" checked={o.excluded_sources.includes(s.key)}
              onChange={(e) => save.mutate({ excluded_sources: e.target.checked ? [...o.excluded_sources, s.key] : o.excluded_sources.filter((x) => x !== s.key) })} /> {s.name}</label>))}</div>
        </fieldset>
      </div>
    </details>
  )
}

export function Overview({ data, onTab }: { data: ProfileResponse; onTab: (t: 'threats' | 'history') => void }) {
  const { profile: p, assessment: a, stale, freshness } = data
  const toast = useToast()
  const confirm = useConfirm()
  const nav = useNavigate()
  const inval = useInvalidate(p.id)
  const [editing, setEditing] = useState(false)
  const [factEdit, setFactEdit] = useState<{ fact?: Fact; category: string } | null>(null)
  const run = useMutation({
    mutationFn: () => api.post<{ unchanged: boolean }>(lsPath(p.id, '/assess')),
    onSuccess: (r) => { inval(); toast(r.unchanged ? 'Nothing has changed since the last assessment, so no new version was saved.' : 'Assessment saved') },
    onError: () => toast('The assessment failed. Try again.', 'error'),
  })
  const remove = async () => {
    if (await confirm({ title: `Delete ${p.name}?`, body: 'The profile, its assessments, hunts, playbooks and notes are removed permanently.', confirmLabel: 'Delete profile', danger: true })) {
      await api.del(lsPath(p.id)); inval(); nav('/landscapes')
    }
  }
  const dismissed = new Set(Object.values(data.reviews).filter((r) => r.decision === 'dismissed').map((r) => r.finding_key))
  const top = (a?.findings ?? []).filter((f) => !dismissed.has(f.key)).slice(0, 5)
  return (
    <div className="stack">
      <section className="panel" aria-labelledby="ls-assess-h">
        <header>
          <h2 id="ls-assess-h">Assessment</h2>
          <button type="button" className="btn primary" aria-busy={run.isPending} onClick={() => run.mutate()}>{a ? 'Re-assess now' : 'Run assessment'}</button>
        </header>
        <div className="body">
          {!a ? <p className="muted mb-0">Not assessed yet. The assessment uses only data Threat Watch already holds: collected reporting, CISA KEV, leak-site claims and MITRE ATT&CK. Nothing about the profile is sent to an AI provider or any outside service.</p> : <>
            <p className="small mb-0">Last assessed <TimeAgo iso={a.created_at} /> ({fmtDate(a.created_at)}) over the previous {a.inputs.window.days} days: {a.inputs.data.articles_considered} reports from {a.inputs.data.sources.length} sources, {a.inputs.data.kev_in_window} KEV entries{a.attack_version ? `, ATT&CK v${a.attack_version}` : ''}.</p>
            <p className="xsmall muted">Collection began {fmtDate(a.inputs.data.collection_started)}, so a longer look-back cannot see further than that. Latest report <TimeAgo iso={freshness.latest_article} />; claims <TimeAgo iso={freshness.latest_claim} />; KEV checked <TimeAgo iso={freshness.kev_checked} />.</p>
            {stale && (stale.profile_changed || stale.new_articles > 0 || stale.method_changed) && (
              <p className="notice small">{[stale.profile_changed && 'The profile changed', stale.new_articles > 0 && `${stale.new_articles} reports have arrived`, stale.method_changed && 'the method was updated'].filter(Boolean).join('; ')} since this assessment. Re-assess to update it.</p>
            )}
            <h3 className="mini-h">What changed</h3>
            <ul className="claims">{a.changes.summary.map((s) => <li key={s}>{s}</li>)}</ul>
            {data.assessments > 1 && <button type="button" className="link small" onClick={() => onTab('history')}>All {data.assessments} assessments</button>}
          </>}
        </div>
      </section>

      {top.length > 0 && (
        <section className="panel" aria-labelledby="ls-top-h">
          <header><h2 id="ls-top-h">Highest priorities</h2><button type="button" className="link" onClick={() => onTab('threats')}>All threats</button></header>
          <div className="body">
            <ul role="list" className="ls-top">
              {top.map((f) => (
                <li key={f.key}><span className={`sev ${PRIORITY_CLASS[f.priority.code]}`}>{f.priority.code}</span> <strong>{f.title}</strong> <span className="xsmall muted">{CLASSIFICATION[f.classification].label}; evidence {f.confidence.level === 'none' ? 'none' : f.confidence.level}</span></li>
              ))}
            </ul>
          </div>
        </section>
      )}

      <section className="panel" aria-labelledby="ls-prof-h">
        <header><h2 id="ls-prof-h">Profile</h2><button type="button" className="btn small" onClick={() => setEditing(true)}>Edit</button></header>
        <div className="body stack">
          {p.description && <p className="measure mb-0 prewrap">{p.description}</p>}
          <dl className="kv">
            <dt>Type</dt><dd>{p.kind === 'organisation' ? 'Organisation' : 'Industry or sector'}</dd>
            <dt>Sector</dt><dd>{p.sector_label ?? <span className="faint">Not set</span>}</dd>
            <dt>Countries</dt><dd>{p.countries.join(', ') || <span className="faint">Not set</span>}</dd>
            {p.kind === 'organisation' && <><dt>Domain</dt><dd>{p.domain ?? <span className="faint">Not set</span>}</dd>
              <dt>Other names</dt><dd>{p.match_terms.join(', ') || <span className="faint">None</span>}</dd></>}
          </dl>
          <p className="xsmall muted mb-0">Every fact carries where it came from. Public facts need a source; inferred facts stay assumptions; anything not recorded is unknown, never assumed missing.</p>
          {Object.keys(FACT_CATEGORIES).map((c) => <FactList key={c} data={data} category={c} onEdit={(fact, category) => setFactEdit({ fact: fact ?? undefined, category })} />)}
        </div>
      </section>

      <Options data={data} />

      <div className="danger-zone"><button type="button" className="btn danger" onClick={remove}>Delete profile</button></div>
      {editing && <Sheet title="Edit profile" onClose={() => setEditing(false)}><ProfileForm initial={p} submitLabel="Save" onDone={() => setEditing(false)} /></Sheet>}
      {factEdit && <FactSheet pid={p.id} fact={factEdit.fact} category={factEdit.category} onClose={() => setFactEdit(null)} />}
    </div>
  )
}
