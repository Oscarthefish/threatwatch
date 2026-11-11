import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { WatchSuggestion } from '../types'
import { Field, useToast } from './ui'
import { Sheet } from './Sheet'

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
    onSuccess: (r) => { qc.invalidateQueries(); toast(r.created ? 'Now following. Earlier reporting from the last 30 days was checked.' : 'You already follow this. Opened the existing watch.'); onClose(); nav(`/watch/${r.id}`) },
  })

  function pick(i: number) { setSel(i); setForm(toForm(suggestions[i])) }
  const current = suggestions[sel]

  const needsId = form.kind === 'incident' && !split(form.identifiers).length && !split(form.aliases).length
  const [tried, setTried] = useState(false)

  return (
    <Sheet title="Follow" onClose={onClose}>
      <p className="muted small">Following keeps a versioned intelligence record. Every collection run checks new reporting against it.</p>
      {suggestions.length > 1 && <>
        <div className="field-label mt-3">What do you want to track?</div>
        {suggestions.map((s, i) => (
          <button type="button" key={i} className={`suggest ${i === sel ? 'on' : ''}`} aria-pressed={i === sel} onClick={() => pick(i)}>
            <span className="chip">{s.kind}</span><span className="grow">{s.title || 'New watch'}</span>
            {s.existing_watch_id && <span className="small muted">following</span>}
          </button>
        ))}
      </>}
      {current?.existing_watch_id ? (
        <div className="notice row between mt-3">You already follow this.<button type="button" className="btn primary" onClick={() => nav(`/watch/${current.existing_watch_id}`)}>Open watch</button></div>
      ) : (
        <form noValidate className="mt-3" onSubmit={(e) => { e.preventDefault(); setTried(true); if (!needsId && form.title.trim().length >= 2) m.mutate() }}>
          <div className="row top">
            <div style={{ flex: '1 1 140px' }}><Field label="Type">
              <select className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>{KINDS.map((k) => <option key={k}>{k}</option>)}</select></Field></div>
            <div style={{ flex: '3 1 240px' }}><Field label="Name" error={tried && form.title.trim().length < 2 ? 'Give this watch a name of at least 2 characters.' : null}>
              <input className="input" data-autofocus value={form.title} aria-invalid={tried && form.title.trim().length < 2} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field></div>
          </div>
          <Field label="Identifiers" error={tried && needsId ? 'Add the victim organisation or incident name, so unrelated incidents are not merged.' : null}
            hint={form.kind === 'incident' ? 'Comma separated. Victim organisation or incident name.' : 'Comma separated. CVE IDs or canonical names.'}>
            <input className="input" value={form.identifiers} aria-invalid={tried && needsId} onChange={(e) => setForm({ ...form, identifiers: e.target.value })} />
          </Field>
          {current?.hint && <p className="small muted">{current.hint}</p>}
          <Field label="Aliases" hint="Other names for the same subject."><input className="input" value={form.aliases} onChange={(e) => setForm({ ...form, aliases: e.target.value })} /></Field>
          <Field label="Context terms" hint="Raise relevance but never link an article on their own."><input className="input" value={form.context} onChange={(e) => setForm({ ...form, context: e.target.value })} /></Field>
          <Field label="Exclude terms" hint="Articles containing these are never linked."><input className="input" value={form.exclude} onChange={(e) => setForm({ ...form, exclude: e.target.value })} /></Field>
          <Field label="Notify me about">
            <select className="input" value={form.notify} onChange={(e) => setForm({ ...form, notify: e.target.value })}>{PREFS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
          </Field>
          {m.isError && <div className="alert mb-3" role="alert"><p className="mb-0">Not saved: {(m.error as Error).message}. Your entries are kept; try again.</p></div>}
          <div className="sheet-actions">
            <button type="button" className="btn" onClick={onClose}>Cancel</button>
            <button className="btn primary" aria-busy={m.isPending || undefined}>Follow</button>
          </div>
        </form>
      )}
    </Sheet>
  )
}

function toForm(s: WatchSuggestion) {
  return { kind: s.kind, title: s.title, description: '', identifiers: s.identifiers.join(', '), aliases: s.aliases.join(', '),
    context: s.context_terms.join(', '), exclude: '', notify: 'important' }
}
