import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api'
import { ErrorBox, fmtDate, Loading } from '../ui'
import { Sheet } from '../Sheet'
import { type Assessment, type Changes, CLASSIFICATION, lsPath, PRIORITY_CLASS, type ProfileResponse } from '../../landscape'

interface Row { id: number; created_at: string; method_version: number; attack_version: string | null; changes: Changes; counts: Record<string, number>; findings: number }

function Snapshot({ pid, id, onClose }: { pid: number; id: number; onClose: () => void }) {
  const q = useQuery({ queryKey: ['ls', pid, 'snap', id], queryFn: () => api.get<Assessment>(lsPath(pid, `/assessments/${id}`)) })
  return (
    <Sheet title={q.data ? `Assessment of ${fmtDate(q.data.created_at)}` : 'Assessment'} onClose={onClose}>
      {!q.data ? <Loading /> : (
        <div className="stack">
          <p className="xsmall muted mb-0">Window {fmtDate(q.data.inputs.window.from)} to {fmtDate(q.data.inputs.window.to)} · {q.data.inputs.data.articles_considered} reports · method v{q.data.method_version}{q.data.attack_version ? ` · ATT&CK v${q.data.attack_version}` : ''}. Saved snapshots never change.</p>
          <ul role="list" className="ls-top">{q.data.findings.map((f) => (
            <li key={f.key}><span className={`sev ${PRIORITY_CLASS[f.priority.code]}`}>{f.priority.code}</span> {f.title} <span className="xsmall muted">{CLASSIFICATION[f.classification].label}, {f.evidence.length} reports</span></li>))}</ul>
        </div>)}
    </Sheet>
  )
}

export function History({ data }: { data: ProfileResponse }) {
  const pid = data.profile.id
  const q = useQuery({ queryKey: ['ls', pid, 'history', data.assessment?.id], queryFn: () => api.get<{ assessments: Row[] }>(lsPath(pid, '/assessments')) })
  const [open, setOpen] = useState<number | null>(null)
  if (q.isLoading) return <Loading />
  if (!q.data) return <ErrorBox error={q.error} />
  if (!q.data.assessments.length) return <p className="muted">No assessments yet.</p>
  return (
    <div className="stack">
      <p className="xsmall muted measure mb-0">A new version is saved only when findings, priorities or evidence change. Each entry lists what changed from the one before.</p>
      <ol className="ls-history">
        {q.data.assessments.map((a) => (
          <li key={a.id}>
            <div className="row between wrap">
              <button type="button" className="link" onClick={() => setOpen(a.id)}><strong>{fmtDate(a.created_at)}</strong></button>
              <span className="xsmall muted">{Object.entries(a.counts).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(' · ')}</span>
            </div>
            <ul className="claims small">{a.changes.summary.map((s) => <li key={s}>{s}</li>)}</ul>
          </li>))}
      </ol>
      {open && <Snapshot pid={pid} id={open} onClose={() => setOpen(null)} />}
    </div>
  )
}
