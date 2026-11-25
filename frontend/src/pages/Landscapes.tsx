import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../api'
import { Empty, ErrorBox, Field, Loading, PageHeader, TimeAgo } from '../components/ui'
import { Sheet } from '../components/Sheet'
import { COUNTRIES, type Meta, PRIORITY_CLASS } from '../landscape'

interface Row {
  id: number; kind: string; name: string; sector_label: string | null; countries: string[]; updated_at: string; assessed_at: string | null
  counts: Record<string, number>; top: { title: string; priority: string; classification: string }[] | null
}

export function useMeta() {
  return useQuery({ queryKey: ['ls-meta'], queryFn: () => api.get<Meta>('/api/landscapes/meta'), staleTime: 300_000 })
}

export function ProfileForm({ initial, onDone, submitLabel }: {
  initial?: { id: number; kind: string; name: string; sector: string | null; countries: string[]; description: string; domain: string | null; match_terms: string[]; size: string | null }
  onDone: (id?: number) => void; submitLabel: string
}) {
  const meta = useMeta()
  const qc = useQueryClient()
  const [kind, setKind] = useState(initial?.kind ?? 'organisation')
  const [name, setName] = useState(initial?.name ?? '')
  const [sector, setSector] = useState(initial?.sector ?? '')
  const [countries, setCountries] = useState((initial?.countries ?? ['NZ']).join(', '))
  const [description, setDescription] = useState(initial?.description ?? '')
  const [domain, setDomain] = useState(initial?.domain ?? '')
  const [terms, setTerms] = useState((initial?.match_terms ?? []).join(', '))
  const [size, setSize] = useState(initial?.size ?? '')
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: (): Promise<{ ok?: boolean; id?: number }> => {
      const body = { kind, name, sector: sector || null, countries: countries.split(/[,\s]+/).filter(Boolean), description,
        domain: domain || null, match_terms: terms.split(',').map((t) => t.trim()).filter(Boolean), size: size || null }
      return initial ? api.patch<{ ok: boolean }>(`/api/landscapes/${initial.id}`, body) : api.post<{ id: number }>('/api/landscapes', body)
    },
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ['landscapes'] }); qc.invalidateQueries({ queryKey: ['landscape'] }); onDone(r.id) },
    onError: (e) => setError(e instanceof ApiError ? e.message : 'Could not save'),
  })
  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); setError(null); save.mutate() }}>
      <fieldset className="choice-row">
        <legend className="field-label">Profile type</legend>
        <div className="seg" role="radiogroup">
          {(['organisation', 'industry'] as const).map((k) => (
            <button key={k} type="button" role="radio" aria-checked={kind === k} aria-pressed={kind === k} onClick={() => setKind(k)}>
              {k === 'organisation' ? 'Organisation' : 'Industry or sector'}</button>))}
        </div>
      </fieldset>
      <Field label={kind === 'organisation' ? 'Organisation name' : 'Profile name'} hint={kind === 'organisation' ? 'Used to find reporting and leak-site claims that name it.' : 'For example "New Zealand healthcare providers".'}>
        <input className="input" required minLength={2} maxLength={120} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
      </Field>
      <Field label="Sector" hint="Ties the profile to sector reporting and ransomware claims.">
        <select className="input" value={sector} onChange={(e) => setSector(e.target.value)}>
          <option value="">Not set</option>
          {meta.data?.sectors.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
        </select>
      </Field>
      <Field label="Countries" hint={`Two-letter codes, comma separated (${Object.entries(COUNTRIES).slice(0, 3).map(([k, v]) => `${k} ${v}`).join(', ')}).`}>
        <input className="input" value={countries} onChange={(e) => setCountries(e.target.value.toUpperCase())} />
      </Field>
      {kind === 'organisation' && <>
        <Field label="Website domain (optional)" hint="Matched against leak-site claims. Threat Watch never scans or visits it.">
          <input className="input" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" />
        </Field>
        <Field label="Other names (optional)" hint="Comma separated, for example a short name or former name.">
          <input className="input" value={terms} onChange={(e) => setTerms(e.target.value)} />
        </Field>
        <Field label="Approximate size (optional)">
          <select className="input" value={size} onChange={(e) => setSize(e.target.value)}>
            <option value="">Not set</option><option value="small">Small</option><option value="medium">Medium</option><option value="large">Large</option><option value="enterprise">Enterprise</option>
          </select>
        </Field>
      </>}
      <Field label="Description (optional)" hint="What the organisation or sector does. Add sources for public facts on the profile page.">
        <textarea className="input" rows={3} maxLength={4000} value={description} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      {error && <p className="field-error" role="alert">{error}</p>}
      <div><button type="submit" className="btn primary" aria-busy={save.isPending}>{submitLabel}</button></div>
    </form>
  )
}

export default function Landscapes() {
  const nav = useNavigate()
  const [creating, setCreating] = useState(false)
  const q = useQuery({ queryKey: ['landscapes'], queryFn: () => api.get<{ profiles: Row[] }>('/api/landscapes') })
  return (
    <>
      <PageHeader title="Threat landscapes" eyebrow={['Defend']}
        sub="Profiles of an organisation or sector, assessed against collected intelligence. Each threat shows why it matters, the evidence behind it, and what to monitor, hunt and harden."
        actions={<button type="button" className="btn primary" onClick={() => setCreating(true)}>New profile</button>} />
      {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} onRetry={() => q.refetch()} /> : !q.data?.profiles.length ? (
        <Empty title="No profiles yet">
          <p>Start with just a name and a sector. You can add technology, logs and controls later; anything you leave out is treated as unknown.</p>
          <button type="button" className="btn primary" onClick={() => setCreating(true)}>New profile</button>
        </Empty>
      ) : (
        <ul className="ls-list" role="list">
          {q.data.profiles.map((p) => (
            <li key={p.id}>
              <Link to={`/landscapes/${p.id}`} className="ls-card">
                <div className="row between top">
                  <div>
                    <h2 className="ls-card-title">{p.name}</h2>
                    <p className="xsmall muted mb-0">{p.kind === 'organisation' ? 'Organisation' : 'Industry'}{p.sector_label ? ` · ${p.sector_label}` : ''}{p.countries.length ? ` · ${p.countries.join(', ')}` : ''}</p>
                  </div>
                  <span className="xsmall muted nowrap">{p.assessed_at ? <>Assessed <TimeAgo iso={p.assessed_at} /></> : 'Not assessed'}</span>
                </div>
                {p.top && p.top.length > 0 && (
                  <ul className="ls-top" role="list">
                    {p.top.map((t) => <li key={t.title}><span className={`sev ${PRIORITY_CLASS[t.priority]}`}>{t.priority}</span> {t.title}</li>)}
                  </ul>
                )}
              </Link>
            </li>
          ))}
        </ul>
      )}
      {creating && (
        <Sheet title="New profile" onClose={() => setCreating(false)}>
          <ProfileForm submitLabel="Create profile" onDone={(id) => { setCreating(false); if (id) nav(`/landscapes/${id}`) }} />
        </Sheet>
      )}
    </>
  )
}
