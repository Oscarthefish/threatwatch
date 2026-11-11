import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../api'
import type { ArticleBrief, SocAction } from '../types'
import { IconBack, IconBookmark, IconExternal } from './icons'

// ------------------------------------------------------------------ time
export function timeAgo(iso?: string | null): string {
  if (!iso) return 'never'
  const t = new Date(iso).getTime()
  const s = Math.round((Date.now() - t) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`
  return new Date(iso).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric' })
}
export function fmtDate(iso?: string | null): string {
  if (!iso) return 'unknown'
  return new Date(iso).toLocaleString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Pacific/Auckland' })
}
export const TimeAgo = ({ iso }: { iso?: string | null }) => <time dateTime={iso ?? undefined} title={fmtDate(iso)}>{timeAgo(iso)}</time>

// -------------------------------------------------------------- severity
const SEV = ['info', 'low', 'medium', 'high', 'critical']
/** Severity label. With reasons it becomes a button that reveals why (works on touch; no hover-only info). */
export function Severity({ level, reasons }: { level: number | string; reasons?: string[] }) {
  const label = typeof level === 'number' ? SEV[level] : level
  const [open, setOpen] = useState(false)
  const wrap = useRef<HTMLSpanElement>(null)
  const id = useId()
  useEffect(() => {
    if (!open) return
    const out = (e: Event) => { if (!wrap.current?.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('pointerdown', out); document.addEventListener('keydown', esc)
    return () => { document.removeEventListener('pointerdown', out); document.removeEventListener('keydown', esc) }
  }, [open])
  if (!reasons?.length) return <span className={`sev ${label}`}>{label}</span>
  return (
    <span className="pop-wrap" ref={wrap}>
      <button type="button" className={`sev ${label}`} aria-expanded={open} aria-controls={id}
        aria-label={`Severity ${label}. Show reasons`} onClick={(e) => { e.preventDefault(); setOpen(!open) }}><span>{label}</span></button>
      {open && <span className="popover" id={id} role="note">
        <span className="pop-title">Why {label}</span>
        <ul>{reasons.map((r) => <li key={r}>{r}</li>)}</ul>
      </span>}
    </span>
  )
}
const CONF: Record<string, string> = { official: 'Official source', corroborated: 'Corroborated by 3+ sources', 'multi-source': '2 sources', 'single-source': 'Single source' }
export const Confidence = ({ value }: { value: string }) => <span className={`conf ${value}`}>{CONF[value] ?? value}</span>

// ----------------------------------------------------------------- toast
type Tone = 'info' | 'error'
const ToastCtx = createContext<(m: string, tone?: Tone) => void>(() => {})
export function ToastProvider({ children }: { children: ReactNode }) {
  const [msg, setMsg] = useState<{ text: string; tone: Tone } | null>(null)
  const timer = useRef<number | undefined>(undefined)
  const show = useCallback((text: string, tone: Tone = 'info') => {
    setMsg({ text, tone }); window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setMsg(null), tone === 'error' ? 6000 : 3000)
  }, [])
  return (
    <ToastCtx.Provider value={show}>
      {children}
      <div aria-live="polite" role="status" className="sr-only">{msg?.text}</div>
      {msg && <div className={`toast ${msg.tone === 'error' ? 'error' : ''}`} aria-hidden="true">{msg.text}</div>}
    </ToastCtx.Provider>
  )
}
export const useToast = () => useContext(ToastCtx)

// ------------------------------------------------------------- feedback
export function Loading({ lines = 4 }: { lines?: number }) {
  return <div aria-busy="true" aria-label="Loading">{Array.from({ length: lines }).map((_, i) => <div key={i} className="skeleton" style={{ width: `${90 - i * 12}%` }} />)}</div>
}
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><h3>{title}</h3>{children && <div>{children}</div>}</div>
}
function explain(error: unknown): { what: string; fix: string } {
  if (!navigator.onLine) return { what: 'You are offline.', fix: 'Cached pages still work. This view will load when you reconnect.' }
  if (error instanceof ApiError) {
    if (error.status === 404) return { what: 'This item could not be found.', fix: 'It may have been removed by the retention policy. Go back and pick another item.' }
    if (error.status === 401) return { what: 'Your session has ended.', fix: 'Sign in again to continue.' }
    if (error.status === 429) return { what: 'Too many requests.', fix: 'Wait a minute, then try again.' }
    if (error.status === 503) return { what: error.message, fix: 'Try again shortly.' }
    if (error.status >= 500) return { what: 'The Threat Watch server hit an error.', fix: 'Try again. If it keeps happening, check the container logs (deploy/local.sh logs).' }
    return { what: error.message, fix: 'Try again.' }
  }
  return { what: 'The server could not be reached.', fix: 'Check that Threat Watch is running, then try again.' }
}
export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { what, fix } = explain(error)
  return (
    <div className="alert" role="alert">
      <div className="grow">
        <h3>{what}</h3>
        <p>{fix}</p>
        {onRetry && <button type="button" className="btn small" onClick={onRetry}>Try again</button>}
      </div>
    </div>
  )
}

/** Labelled form field with optional hint and inline error. The label is always visible. */
export function Field({ label, hint, error, children }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {error ? <span className="field-error" role="alert">{error}</span> : hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  )
}

// --------------------------------------------------------------- bookmark
export function useBookmark() {
  const qc = useQueryClient()
  const toast = useToast()
  return useMutation({
    mutationFn: ({ id, on }: { id: number; on: boolean }) => on ? api.put(`/api/bookmarks/${id}`, { note: '', tags: [] }) : api.del(`/api/bookmarks/${id}`),
    onSuccess: (_d, v) => { toast(v.on ? 'Bookmarked' : 'Bookmark removed'); qc.invalidateQueries() },
    onError: () => toast('Bookmark not saved. Check your connection and try again.', 'error'),
  })
}
export function BookmarkButton({ id, on, withLabel, compact }: { id: number; on: boolean; withLabel?: boolean; compact?: boolean }) {
  const m = useBookmark()
  return (
    <button type="button" data-key="b" className={`btn ${withLabel ? '' : `icon quiet ${compact ? 'compact' : ''}`} ${on ? 'on' : ''}`} aria-pressed={on}
      aria-label={withLabel ? undefined : on ? 'Remove bookmark' : 'Bookmark for later'} aria-busy={m.isPending || undefined}
      onClick={(e) => { e.preventDefault(); m.mutate({ id, on: !on }) }}>
      <IconBookmark filled={on} />{withLabel && (on ? 'Bookmarked' : 'Bookmark')}
    </button>
  )
}

// ------------------------------------------------------------ SecOps actions
/** Compact next-step tags for cards and rows. Urgent steps are marked in text, not only colour. */
export function ActionTags({ actions, max = 3 }: { actions?: SocAction[]; max?: number }) {
  if (!actions?.length) return null
  const shown = actions.slice(0, max)
  return (
    <ul className="acts" aria-label="Next steps for the SOC">
      {shown.map((a) => <li key={a.kind + a.label} className={`act ${a.urgent ? 'urgent' : ''}`}>{a.urgent && <span className="sr-only">Urgent: </span>}{a.label}</li>)}
      {actions.length > max && <li className="act more">+{actions.length - max}</li>}
    </ul>
  )
}

/** Full next-step guidance with the basis of each step. */
export function ActionList({ actions, ai }: { actions: SocAction[]; ai?: { action: string; rationale: string }[] }) {
  if (!actions.length && !ai?.length) return null
  return (
    <section className="panel" aria-labelledby="todo-h">
      <header><h2 id="todo-h">What to do</h2><span className="xsmall muted">Next steps for the SOC</span></header>
      <div className="body">
        <ol className="todo">
          {actions.map((a) => (
            <li key={a.kind + a.label} className={a.urgent ? 'urgent' : ''}>
              <div className="row between top">
                <strong>{a.label}{a.urgent && <span className="tag-urgent">Urgent</span>}</strong>
                <span className={`basis ${a.basis === 'Playbook' ? 'playbook' : ''}`}>{a.basis}</span>
              </div>
              <p>{a.detail}</p>
            </li>
          ))}
          {ai?.map((a, i) => (
            <li key={`ai${i}`}>
              <div className="row between top"><strong>{a.action}</strong><span className="basis">AI, from source</span></div>
              <p>{a.rationale}</p>
            </li>
          ))}
        </ol>
        <p className="xsmall faint mb-0">“Playbook” steps are standard practice for this type of threat, not claims about this incident. Other steps come directly from the named source.</p>
      </div>
    </section>
  )
}

// ------------------------------------------------------------ article card
export function ArticleCard({ a, extra }: { a: ArticleBrief; extra?: ReactNode }) {
  return (
    <article data-nav className={`acard s${a.severity} ${a.read ? 'read' : ''}`}>
      <div className="acard-body">
        <div className="meta">
          <Severity level={a.severity} reasons={a.severity_reasons} />
          <span className="src">{a.source.name}</span>
          <TimeAgo iso={a.published_at} />
        </div>
        <Link className="title" data-open to={`/article/${a.id}`}>{a.title}</Link>
        {(a.ai_summary || a.excerpt) && <p className="excerpt">{a.ai_summary ?? a.excerpt}</p>}
        {(a.related_count > 0 || (a.region && a.region !== 'GLOBAL')) && (
          <div className="row xsmall muted mt-2">
            {a.related_count > 0 && <span>+{a.related_count} more source{a.related_count > 1 ? 's' : ''}</span>}
            {a.region && a.region !== 'GLOBAL' && <span className="chip">{a.region}</span>}
          </div>
        )}
        <ActionTags actions={a.actions} />
        {extra}
      </div>
      <div className="acard-actions">
        <BookmarkButton id={a.id} on={a.bookmarked} compact />
        <a className="btn icon quiet compact" href={a.url} target="_blank" rel="noopener noreferrer" aria-label={`Open original on ${a.source.name}`}><IconExternal /></a>
      </div>
    </article>
  )
}

/** Compact one-line-ish row for dense dashboard lists. */
export function ArticleRow({ a }: { a: ArticleBrief }) {
  return (
    <div data-nav className={`arow ${a.read ? 'read' : ''}`}>
      <span className={`dot s${a.severity}`} aria-hidden="true" />
      <span className="sr-only">{SEV[a.severity]} severity.</span>
      <div className="grow">
        <Link className="t" to={`/article/${a.id}`}>{a.title}</Link>
        <div className="m">{a.source.name} · <TimeAgo iso={a.published_at} />{a.related_count > 0 && <> · +{a.related_count} source{a.related_count > 1 ? 's' : ''}</>}{a.region && a.region !== 'GLOBAL' && <> · {a.region}</>}</div>
        <ActionTags actions={a.actions} max={2} />
      </div>
      <BookmarkButton id={a.id} on={a.bookmarked} compact />
    </div>
  )
}

/** Empty state that distinguishes "nothing matches your filters" from "nothing collected". */
export function NoResults({ filtered, onClear, what = 'reports' }: { filtered: boolean; onClear?: () => void; what?: string }) {
  return filtered ? (
    <Empty title={`No ${what} match these filters`}>
      <p>Widen the time range or remove a filter.</p>
      {onClear && <button type="button" className="btn" onClick={onClear}>Clear filters</button>}
    </Empty>
  ) : <Empty title={`No ${what} yet`}><p>New items appear here after the next collection run (every 30 minutes).</p></Empty>
}

export function LoadMore({ show, busy, onClick }: { show: boolean; busy: boolean; onClick: () => void }) {
  if (!show) return null
  return <div className="center mt-4"><button type="button" className="btn" aria-busy={busy || undefined} onClick={onClick}>Load more</button></div>
}

export function ArticleList({ items, empty }: { items?: ArticleBrief[]; empty?: ReactNode }) {
  if (!items) return <Loading />
  if (!items.length) return <>{empty ?? <Empty title="Nothing here yet" />}</>
  return <div className="alist">{items.map((a) => <ArticleCard key={a.id} a={a} />)}</div>
}

// ------------------------------------------------------- citation rendering
/** Render text containing [E123] markers as plain text + links to evidence. Never uses innerHTML. */
export function CitedText({ text }: { text: string }) {
  const parts = text.split(/(\[E\d+\])/g)
  return <>{parts.map((p, i) => {
    const m = p.match(/^\[E(\d+)\]$/)
    return m ? <Link key={i} className="cite" to={`/article/${m[1]}`} aria-label={`Source E${m[1]}`}>E{m[1]}</Link> : <span key={i}>{p}</span>
  })}</>
}
export function Cites({ ids }: { ids: number[] }) {
  return <>{ids.map((id) => <Link key={id} className="cite" to={`/article/${id}`}>E{id}</Link>)}</>
}

/** Sets the browser tab / history title: "<page> · Threat Watch". */
export function usePageTitle(title?: string | null) {
  useEffect(() => { document.title = title ? `${title} · Threat Watch` : 'Threat Watch' }, [title])
}

/** Small monospace context line above a page heading, e.g. "SECTION · LAST 72 HOURS". */
export function Eyebrow({ parts }: { parts: (ReactNode | false | null | undefined)[] }) {
  const items = parts.filter(Boolean)
  return <div className="eyebrow">{items.map((p, i) => <span key={i} className="eb">{i > 0 && <span className="sep" aria-hidden="true">/</span>}{p}</span>)}</div>
}

export function PageHeader({ title, sub, actions, eyebrow }: { title: string; sub?: ReactNode; actions?: ReactNode; eyebrow?: (ReactNode | false | null | undefined)[] }) {
  usePageTitle(title)
  return (
    <div className="page-head row between top">
      <div className="grow">
        {eyebrow && <Eyebrow parts={eyebrow} />}
        <h1>{title}</h1>
        {sub && <p className="muted small measure mb-0">{sub}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  )
}

/** Consistent back affordance: returns to the previous in-app page, or to `fallback` when opened directly. */
export function BackLink({ fallback, label = 'Back' }: { fallback: string; label?: string }) {
  const nav = useNavigate()
  const canGoBack = (window.history.state?.idx ?? 0) > 0
  return (
    <a href={fallback} className="back" onClick={(e) => { e.preventDefault(); if (canGoBack) nav(-1); else nav(fallback) }}>
      <IconBack aria-hidden="true" />{label}
    </a>
  )
}

export function copy(text: string, toast: (m: string, tone?: 'info' | 'error') => void) {
  navigator.clipboard?.writeText(text).then(() => toast('Copied to clipboard'), () => toast('Copy blocked by the browser. Select the text and copy it manually.', 'error'))
}
