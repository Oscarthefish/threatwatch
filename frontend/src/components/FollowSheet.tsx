import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { WatchSuggestion } from '../types'
import { Field, useToast } from './ui'
import { Sheet } from './Sheet'
import { KINDS, kindLabel, NOTIFY, splitList } from './follow'

const QUICK = new Set(['vulnerability', 'actor', 'malware'])

function toForm(s: WatchSuggestion) {
  return { kind: s.kind, title: s.title, identifiers: s.identifiers.join(', '), aliases: s.aliases.join(', '),
    context: s.context_terms.join(', '), exclude: '', notify: 'important' }
}

/**
 * Follow flow. A CVE, actor or malware family is one tap (its identity is already known);
 * incidents and topics ask only for what is needed to avoid false matches. Matching rules live under "Advanced".
 */
export function FollowSheet({ suggestions, originArticleId, onClose }: { suggestions: WatchSuggestion[]; originArticleId?: number; onClose: () => void }) {
  const manual = suggestions.length === 0 || (suggestions.length === 1 && !suggestions[0].title)
  const list = manual ? [] : suggestions
  const [sel, setSel] = useState(() => Math.max(0, list.findIndex((s) => QUICK.has(s.kind) && !s.existing_watch_id)))
  const [form, setForm] = useState(() => toForm(list[sel] ?? { kind: 'incident', title: '', identifiers: [], aliases: [], context_terms: [], existing_watch_id: null }))
  const [tried, setTried] = useState(false)
  const qc = useQueryClient()
  const nav = useNavigate()
  const toast = useToast()
  const current = list[sel]
  const quick = !manual && QUICK.has(form.kind) && splitList(form.identifiers).length > 0

  const m = useMutation({
    mutationFn: () => api.post<{ id: number; created: boolean }>('/api/watches', {
      kind: form.kind, title: form.title.trim(), identifiers: splitList(form.identifiers), aliases: splitList(form.aliases),
      context_terms: splitList(form.context), exclude_terms: splitList(form.exclude), notify_pref: form.notify, origin_article_id: originArticleId ?? null,
    }),
    onSuccess: (r) => {
      qc.invalidateQueries()
      toast(r.created ? 'Following. Reporting from the last 30 days has been checked.' : 'You already follow this. Opened it.')
      onClose(); nav(`/watch/${r.id}`)
    },
  })

  const titleErr = form.title.trim().length < 2 ? 'Give it a name of at least 2 characters.' : null
  const idErr = form.kind === 'incident' && !splitList(form.identifiers).length && !splitList(form.aliases).length
    ? 'Add the victim organisation or incident name. Without it, unrelated incidents could be merged.' : null
  const submit = (e: React.FormEvent) => { e.preventDefault(); setTried(true); if (!titleErr && !idErr) m.mutate() }

  const advanced = (
    <details className="disclose">
      <summary>Advanced matching</summary>
      <Field label="Aliases" hint="Other names for the same subject. Comma separated.">
        <input className="input" value={form.aliases} onChange={(e) => setForm({ ...form, aliases: e.target.value })} />
      </Field>
      <Field label="Context terms" hint="Raise relevance but never link a report on their own.">
        <input className="input" value={form.context} onChange={(e) => setForm({ ...form, context: e.target.value })} />
      </Field>
      <Field label="Exclude terms" hint="Reports containing these are never linked.">
        <input className="input" value={form.exclude} onChange={(e) => setForm({ ...form, exclude: e.target.value })} />
      </Field>
      {quick && (
        <Field label="Identifiers" hint="Comma separated.">
          <input className="input" value={form.identifiers} onChange={(e) => setForm({ ...form, identifiers: e.target.value })} />
        </Field>
      )}
    </details>
  )

  const notify = (
    <fieldset className="choices">
      <legend className="field-label">Tell me about</legend>
      {NOTIFY.map(([v, label, hint]) => (
        <label key={v} className={`choice ${form.notify === v ? 'on' : ''}`}>
          <input type="radio" name="notify" value={v} checked={form.notify === v} onChange={() => setForm({ ...form, notify: v })} />
          <span><b>{label}</b><small>{hint}</small></span>
        </label>
      ))}
    </fieldset>
  )

  return (
    <Sheet title={manual ? 'Follow something new' : 'Follow'} onClose={onClose}>
      {list.length > 1 && (
        <div role="radiogroup" aria-label="What to follow" className="mb-3">
          {list.map((s, i) => (
            <button type="button" role="radio" aria-checked={i === sel} key={i} className={`suggest ${i === sel ? 'on' : ''}`}
              onClick={() => { setSel(i); setForm(toForm(s)); setTried(false) }}>
              <span className="chip">{kindLabel(s.kind)}</span><span className="grow">{s.title}</span>
              {s.existing_watch_id && <span className="xsmall muted">following</span>}
            </button>
          ))}
        </div>
      )}

      {current?.existing_watch_id ? (
        <div className="notice row between">
          <span>You already follow this.</span>
          <button type="button" className="btn primary" onClick={() => { onClose(); nav(`/watch/${current.existing_watch_id}`) }}>Open</button>
        </div>
      ) : (
        <form noValidate onSubmit={submit}>
          {quick ? (
            <div className="subject">
              <span className="chip">{kindLabel(form.kind)}</span>
              <div className="strong">{form.title}</div>
              {splitList(form.aliases).length > 0 && <div className="xsmall muted">Also matches: {splitList(form.aliases).join(', ')}</div>}
              <p className="xsmall muted mb-0">New reporting that names this is linked automatically. Past 30 days are checked now.</p>
            </div>
          ) : <>
            {manual && (
              <Field label="Type">
                <select className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
                  {KINDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                </select>
              </Field>
            )}
            <Field label="Name" error={tried ? titleErr : null}>
              <input className="input" data-autofocus value={form.title} aria-invalid={tried && !!titleErr} onChange={(e) => setForm({ ...form, title: e.target.value })} />
            </Field>
            <Field label={form.kind === 'incident' ? 'Victim or incident name' : 'Names to match'} error={tried ? idErr : null}
              hint={form.kind === 'incident' ? 'Comma separated. Actor or malware names go under Advanced as context, so other incidents by the same group are not merged.'
                : 'Comma separated. CVE IDs, product, actor or malware names.'}>
              <input className="input" value={form.identifiers} aria-invalid={tried && !!idErr} onChange={(e) => setForm({ ...form, identifiers: e.target.value })} />
            </Field>
          </>}

          {notify}
          {advanced}

          {m.isError && <div className="alert mt-3" role="alert"><p className="mb-0">Not saved: {(m.error as Error).message}. Your entries are kept; try again.</p></div>}
          <div className="sheet-actions">
            <button type="button" className="btn quiet" onClick={onClose}>Cancel</button>
            <button className="btn primary" aria-busy={m.isPending || undefined} data-autofocus={quick || undefined}>Follow</button>
          </div>
        </form>
      )}
    </Sheet>
  )
}
