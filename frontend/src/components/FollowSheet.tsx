import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { WatchSuggestion } from '../types'
import { useToast } from './ui'

const KINDS = ['incident', 'vulnerability', 'actor', 'malware', 'campaign', 'product', 'topic']
const PREFS: [string, string][] = [
  ['important', 'Important changes immediately'],
  ['all', 'All meaningful new findings'],
  ['digest', 'Daily digest'],
  ['silent', 'Silent tracking'],
]
const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

export function FollowSheet({ suggestions, originArticleId, onClose }: { suggestions: WatchSuggestion[]; originArticleId?: number; onClose: () => void }) {
  const [sel, setSel] = useState(0)
  const first = suggestions[0] ?? { kind: 'topic', title: '', identifiers: [], aliases: [], context_terms: [], existing_watch_id: null }
  const [form, setForm] = useState(() => toForm(first))
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.post<{ id: number; created: boolean }>('/api/watches', {
      kind: form.kind, title: form.title, description: form.description, identifiers: split(form.identifiers), aliases: split(form.aliases),
      context_terms: split(form.context), exclude_terms: split(form.exclude), notify_pref: form.notify, origin_article_id: originArticleId ?? null,
    }),
    onSuccess: (r) => { qc.invalidateQueries(); toast(r.created ? 'Now following' : 'Already following — opened existing watch'); nav(`/watch/${r.id}`) },
  })

  function pick(i: number) { setSel(i); setForm(toForm(suggestions[i])) }
  const current = suggestions[sel]

  return (
    <div className="sheet-backdrop" onClick={onClose} role="presentation">
      <div className="sheet-panel" role="dialog" aria-modal="true" aria-labelledby="follow-title" onClick={(e) => e.stopPropagation()}>
        <div className="row between"><h2 id="follow-title" style={{ margin: 0 }}>Follow</h2><button className="btn ghost" onClick={onClose}>Close</button></div>
        <p className="muted small">Following creates a persistent intelligence record. New reporting is checked against it on every ingestion run.</p>
        {suggestions.length > 0 && <>
          <div className="small muted" style={{ fontWeight: 600, margin: '.5rem 0 .35rem' }}>What do you want to track?</div>
          {suggestions.map((s, i) => (
            <button key={i} className={`suggest ${i === sel ? 'on' : ''}`} onClick={() => pick(i)}>
              <span className="chip">{s.kind}</span><span className="grow">{s.title}</span>
              {s.existing_watch_id && <span className="small muted">following</span>}
            </button>
          ))}
        </>}
        {current?.existing_watch_id ? (
          <div className="notice">You already follow this. <button className="btn" onClick={() => nav(`/watch/${current.existing_watch_id}`)}>Open watch</button></div>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); m.mutate() }} style={{ marginTop: '.75rem' }}>
            <div className="row" style={{ gap: '.75rem', alignItems: 'flex-start' }}>
              <label className="field" style={{ flex: '1 1 140px' }}><span>Type</span>
                <select className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>{KINDS.map((k) => <option key={k}>{k}</option>)}</select></label>
              <label className="field" style={{ flex: '3 1 240px' }}><span>Name</span>
                <input className="input" required minLength={2} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></label>
            </div>
            <label className="field"><span>Identifiers (comma separated) — {form.kind === 'incident' ? 'victim organisation, incident name' : 'CVE IDs, canonical names'}</span>
              <input className="input" value={form.identifiers} onChange={(e) => setForm({ ...form, identifiers: e.target.value })} required={form.kind === 'incident' && !form.aliases} /></label>
            {current?.hint && <p className="small muted">{current.hint}</p>}
            <label className="field"><span>Aliases</span><input className="input" value={form.aliases} onChange={(e) => setForm({ ...form, aliases: e.target.value })} /></label>
            <label className="field"><span>Context terms (boost relevance, never sufficient alone)</span><input className="input" value={form.context} onChange={(e) => setForm({ ...form, context: e.target.value })} /></label>
            <label className="field"><span>Exclude terms</span><input className="input" value={form.exclude} onChange={(e) => setForm({ ...form, exclude: e.target.value })} /></label>
            <label className="field"><span>Notifications</span>
              <select className="input" value={form.notify} onChange={(e) => setForm({ ...form, notify: e.target.value })}>{PREFS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></label>
            {m.isError && <p className="error">{(m.error as Error).message}</p>}
            <div className="row" style={{ justifyContent: 'flex-end' }}>
              <button type="button" className="btn" onClick={onClose}>Cancel</button>
              <button className="btn primary" disabled={m.isPending}>{m.isPending ? 'Following…' : 'Follow'}</button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}

function toForm(s: WatchSuggestion) {
  return { kind: s.kind, title: s.title, description: '', identifiers: s.identifiers.join(', '), aliases: s.aliases.join(', '),
    context: s.context_terms.join(', '), exclude: '', notify: 'important' }
}
