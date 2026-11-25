import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { api } from '../../api'
import { Field, fmtDate, techniqueUrl } from '../ui'
import { Sheet } from '../Sheet'
import { useInvalidate } from './Overview'
import { BASIS, CLASSIFICATION, type ClaimsSummary, type Classification, type Finding, lsPath, PRIORITY_CLASS, type ProfileResponse } from '../../landscape'

function Factors({ f }: { f: Finding }) {
  return (
    <div className="table-wrap" tabIndex={0} role="region" aria-label="Scrollable table">
      <table className="ls-table">
        <caption className="sr-only">Why this priority</caption>
        <thead><tr><th scope="col">Factor</th><th scope="col">Detail</th><th scope="col">Basis</th><th scope="col" className="num">Points</th></tr></thead>
        <tbody>
          {f.factors.map((x) => <tr key={x.factor}><td>{x.factor}</td><td>{x.detail}</td><td className="muted">{x.basis}</td><td className="num">{x.points > 0 ? `+${x.points}` : x.points}</td></tr>)}
          {f.factors.length === 0 && <tr><td colSpan={4} className="muted">No factors apply. Listed as a scenario for this kind of organisation.</td></tr>}
        </tbody>
        <tfoot><tr><th scope="row" colSpan={3}>Total ({f.priority.code} {f.priority.label}{f.classification === 'plausible' || f.classification === 'historical' ? ', capped at P3 without recent evidence' : ''})</th><td className="num">{f.priority.points}</td></tr></tfoot>
      </table>
    </div>
  )
}

function Claims({ c }: { c: ClaimsSummary }) {
  return (
    <div>
      <h4 className="mini-h">Leak-site claims against {c.sector} organisations</h4>
      <p className="small mb-0">{c.count} claims in the window ({c.recent_30d} in the last 30 days){c.previous_complete ? `, ${c.previous} in the period before` : ''}.
        {c.in_countries > 0 && ` ${c.in_countries} name organisations in ${c.countries.join(', ')}${c.local_groups.length ? ` (${c.local_groups.map((g) => `${g.group} ${g.claims}`).join(', ')})` : ''}.`}</p>
      {c.top_groups.length > 0 && <p className="small">Most active groups: {c.top_groups.map((g, i) => <span key={g.group}>{i > 0 && ', '}<Link to={`/group/ransomware/${encodeURIComponent(g.group)}`}>{g.group}</Link> ({g.claims})</span>)}.</p>}
      <p className="xsmall muted mb-0">Claims are the groups' own statements, aggregated by ransomware.live. They are not verified and say nothing about how access was gained.</p>
    </div>
  )
}

function DismissSheet({ pid, f, onClose }: { pid: number; f: Finding; onClose: () => void }) {
  const inval = useInvalidate(pid)
  const [reason, setReason] = useState('')
  const save = useMutation({ mutationFn: () => api.put(lsPath(pid, `/reviews/${f.key}`), { decision: 'dismissed', reason }), onSuccess: () => { inval(); onClose() } })
  return (
    <Sheet title="Dismiss finding" narrow onClose={onClose} actions={<>
      <button type="button" className="btn" onClick={onClose}>Cancel</button>
      <button type="button" className="btn primary" disabled={!reason.trim()} aria-busy={save.isPending} onClick={() => save.mutate()}>Dismiss</button></>}>
      <p className="small">{f.title}. It stays in the assessment history and comes back if you restore it. Monitoring and hunting lists stop including it.</p>
      <Field label="Reason (required)" hint="For example: not applicable because the organisation does not use this technology.">
        <textarea className="input" rows={3} maxLength={1000} value={reason} onChange={(e) => setReason(e.target.value)} autoFocus />
      </Field>
    </Sheet>
  )
}

function FindingCard({ f, pid, review }: { f: Finding; pid: number; review?: { decision: string; reason: string } }) {
  const [dismissing, setDismissing] = useState(false)
  const inval = useInvalidate(pid)
  const restore = useMutation({ mutationFn: () => api.del(lsPath(pid, `/reviews/${f.key}`)), onSuccess: inval })
  const accept = useMutation({ mutationFn: () => api.put(lsPath(pid, `/reviews/${f.key}`), { decision: 'accepted', reason: '' }), onSuccess: inval })
  const strong = f.techniques.filter((t) => t.basis.some((b) => b === 'reported' || b === 'group'))
  const claims = f.claims && !Array.isArray(f.claims) ? f.claims as ClaimsSummary : null
  const orgClaims = Array.isArray(f.claims) ? f.claims : null
  return (
    <article className={`panel ls-finding ${review?.decision === 'dismissed' ? 'dismissed' : ''}`} aria-labelledby={`f-${f.key}`}>
      <details>
        <summary>
          <div className="row top">
            <span className={`sev ${PRIORITY_CLASS[f.priority.code]}`} title={`${f.priority.label}, ${f.priority.points} points`}>{f.priority.code}</span>
            <div className="grow">
              <h3 id={`f-${f.key}`} className="ls-finding-title">{f.title}</h3>
              <p className="xsmall muted mb-0">
                <span className={`ls-class ${f.classification}`}>{CLASSIFICATION[f.classification].label}</span>
                {' · '}Evidence confidence: {f.confidence.level === 'none' ? 'no direct evidence' : `${f.confidence.level} (${f.confidence.why})`}
                {f.evidence.length > 0 && ` · ${f.evidence.length} report${f.evidence.length === 1 ? '' : 's'}`}
                {review?.decision === 'accepted' && ' · Accepted'}
              </p>
            </div>
          </div>
        </summary>
        <div className="body stack">
          <p className="measure mb-0">{f.summary}</p>
          {review?.decision === 'dismissed' && <p className="notice small">Dismissed: {review.reason}</p>}
          <h4 className="mini-h">Why this priority</h4>
          <Factors f={f} />
          {f.vulnerabilities && f.vulnerabilities.length > 0 && (
            <div>
              <h4 className="mini-h">Exploited vulnerabilities (CISA KEV)</h4>
              <ul role="list" className="ls-vulns">
                {f.vulnerabilities.map((v) => (
                  <li key={v.cve_id}>
                    <Link to={`/vuln/${v.cve_id}`} className="mono-id">{v.cve_id}</Link> {v.vendor} {v.product}
                    <span className="xsmall muted"> · added {v.date_added}{v.ransomware ? ' · known ransomware use' : ''}{v.cvss != null ? ` · CVSS ${v.cvss}` : ''}
                      {v.epss != null ? ` · EPSS ${(v.epss * 100).toFixed(1)}%` : ''} · matched on {v.match}</span>
                  </li>))}
              </ul>
              <p className="xsmall muted mb-0">EPSS is FIRST's estimate of exploitation activity in the next 30 days, not the chance this organisation is compromised. CVSS describes severity, not exploitation.</p>
            </div>
          )}
          {claims && claims.count > 0 && <Claims c={claims} />}
          {orgClaims && (
            <div><h4 className="mini-h">Claims (unverified)</h4>
              <ul className="claims">{orgClaims.map((c) => <li key={c.record_url}>{c.group} listed “{c.victim}” on {fmtDate(c.discovered_at)} · <a href={c.record_url} target="_blank" rel="noopener noreferrer">tracker record</a></li>)}</ul></div>
          )}
          {f.profile_evidence && f.profile_evidence.length > 0 && (
            <div>
              <h4 className="mini-h">Recorded on this profile from public sources</h4>
              <ul role="list" className="ls-evidence">{f.profile_evidence.map((e) => (
                <li key={e.value}>{e.value}
                  <div className="xsmall muted"><a href={e.source_url} target="_blank" rel="noopener noreferrer">{e.source_title || new URL(e.source_url).hostname}</a>
                    {e.verified_at ? ` · checked ${e.verified_at.slice(0, 10)}` : ''}{e.note ? ` · ${e.note}` : ''}</div></li>))}</ul>
            </div>
          )}
          <div>
            <h4 className="mini-h">Supporting reporting</h4>
            {f.evidence.length === 0 ? <p className="small muted mb-0">No collected report ties this threat to the profile in the window.
              {f.reporting_volume ? ` Across all sectors: ${f.reporting_volume.stories} stories (${f.reporting_volume.last_30} in the last 30 days, ${f.reporting_volume.previous_30} in the 30 before).` : ''}</p> : (
              <ul role="list" className="ls-evidence">
                {f.evidence.map((e) => (
                  <li key={e.article_id}>
                    <Link to={`/article/${e.article_id}`}>{e.title}</Link>
                    <div className="xsmall muted">{e.source} · published {fmtDate(e.published_at)} · collected {fmtDate(e.retrieved_at)} · matched {e.matched.join(', ')}</div>
                  </li>))}
              </ul>)}
          </div>
          {f.techniques.length > 0 && (
            <div>
              <h4 className="mini-h">ATT&CK techniques</h4>
              <ul role="list" className="chips">
                {(strong.length ? strong : f.techniques).slice(0, 16).map((t) => (
                  <li key={t.id}><a className="chip link-chip" href={techniqueUrl(t.id) ?? undefined} target="_blank" rel="noopener noreferrer" title={t.basis.map((b) => BASIS[b]).join('; ')}>
                    {t.id} {t.name ?? ''}</a></li>))}
              </ul>
              <p className="xsmall muted mb-0">{strong.length ? `${strong.length} named in reporting or documented by MITRE for groups in the evidence` : 'From Threat Watch guidance only; review before relying on them'}; {f.techniques.length} in total. The ATT&CK tab shows them all with their basis.</p>
            </div>
          )}
          {f.unknowns.length > 0 && (
            <div><h4 className="mini-h">Unknown</h4><ul className="claims">{f.unknowns.map((u) => <li key={u}>{u}</li>)}</ul></div>
          )}
          <div className="row wrap">
            {review?.decision === 'dismissed' ? <button type="button" className="btn small" onClick={() => restore.mutate()}>Restore</button> : <>
              <button type="button" className="btn small" onClick={() => setDismissing(true)}>Dismiss with reason</button>
              {review?.decision !== 'accepted' && <button type="button" className="btn small" onClick={() => accept.mutate()}>Mark reviewed</button>}
            </>}
          </div>
        </div>
      </details>
      {dismissing && <DismissSheet pid={pid} f={f} onClose={() => setDismissing(false)} />}
    </article>
  )
}

export function Threats({ data }: { data: ProfileResponse }) {
  const a = data.assessment!
  const [cls, setCls] = useState<Classification | ''>('')
  const [showDismissed, setShowDismissed] = useState(false)
  const reviews = data.reviews
  const items = a.findings.filter((f) => (!cls || f.classification === cls) && (showDismissed || reviews[f.key]?.decision !== 'dismissed'))
  const hidden = a.findings.filter((f) => reviews[f.key]?.decision === 'dismissed').length
  return (
    <div className="stack">
      <p className="small muted measure mb-0">Prioritised by the listed factors. Relevance to the profile is not evidence of an attack on the organisation. Open a threat to see its evidence, techniques and what is unknown.</p>
      <div className="row wrap">
        <div className="seg ls-seg" role="group" aria-label="Filter by classification">
          <button type="button" aria-pressed={!cls} onClick={() => setCls('')}>All</button>
          {(Object.keys(CLASSIFICATION) as Classification[]).map((c) => <button key={c} type="button" aria-pressed={cls === c} onClick={() => setCls(c)}>{CLASSIFICATION[c].label}</button>)}
        </div>
        {hidden > 0 && <label className="check small"><input type="checkbox" checked={showDismissed} onChange={(e) => setShowDismissed(e.target.checked)} /> Show {hidden} dismissed</label>}
      </div>
      {cls && <p className="xsmall muted mb-0">{CLASSIFICATION[cls].help}</p>}
      {items.length === 0 ? <p className="muted">No findings match.</p> : items.map((f) => <FindingCard key={f.key} f={f} pid={data.profile.id} review={reviews[f.key]} />)}
    </div>
  )
}
