import { createContext, useCallback, useContext, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief } from '../types'
import { IconBookmark, IconExternal } from './icons'

// ------------------------------------------------------------------ time
export function timeAgo(iso?: string | null): string {
  if (!iso) return '—'
  const t = new Date(iso).getTime()
  const s = Math.round((Date.now() - t) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`
  return new Date(iso).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric' })
}
export function fmtDate(iso?: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Pacific/Auckland' })
}
export const TimeAgo = ({ iso }: { iso?: string | null }) => <time dateTime={iso ?? undefined} title={fmtDate(iso)}>{timeAgo(iso)}</time>

// -------------------------------------------------------------- severity
const SEV = ['info', 'low', 'medium', 'high', 'critical']
export function Severity({ level, reasons }: { level: number | string; reasons?: string[] }) {
  const label = typeof level === 'number' ? SEV[level] : level
  return <span className={`sev ${label}`} title={reasons?.join('\n')}>{label}</span>
}
const CONF: Record<string, string> = { official: 'Official source', corroborated: 'Corroborated (3+ sources)', 'multi-source': '2 sources', 'single-source': 'Single source' }
export const Confidence = ({ value }: { value: string }) => <span className={`conf ${value}`} title="Confidence based on source authority and independent corroboration">{CONF[value] ?? value}</span>

// ----------------------------------------------------------------- toast
const ToastCtx = createContext<(m: string) => void>(() => {})
export function ToastProvider({ children }: { children: ReactNode }) {
  const [msg, setMsg] = useState<string | null>(null)
  const show = useCallback((m: string) => { setMsg(m); window.setTimeout(() => setMsg(null), 2600) }, [])
  return <ToastCtx.Provider value={show}>{children}{msg && <div className="toast" role="status">{msg}</div>}</ToastCtx.Provider>
}
export const useToast = () => useContext(ToastCtx)

// ------------------------------------------------------------- feedback
export function Loading({ lines = 4 }: { lines?: number }) {
  return <div aria-busy="true" aria-label="Loading">{Array.from({ length: lines }).map((_, i) => <div key={i} className="skeleton" style={{ width: `${90 - i * 12}%` }} />)}</div>
}
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><h3>{title}</h3>{children && <div>{children}</div>}</div>
}
export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : 'Something went wrong'
  return <div className="card error" role="alert">Couldn’t load: {msg}. {navigator.onLine ? '' : 'You appear to be offline — showing cached data where available.'}</div>
}

// --------------------------------------------------------------- bookmark
export function useBookmark() {
  const qc = useQueryClient()
  const toast = useToast()
  return useMutation({
    mutationFn: ({ id, on }: { id: number; on: boolean }) => on ? api.put(`/api/bookmarks/${id}`, { note: '', tags: [] }) : api.del(`/api/bookmarks/${id}`),
    onSuccess: (_d, v) => { toast(v.on ? 'Bookmarked' : 'Bookmark removed'); qc.invalidateQueries() },
    onError: () => toast('Could not update bookmark'),
  })
}
export function BookmarkButton({ id, on, withLabel }: { id: number; on: boolean; withLabel?: boolean }) {
  const m = useBookmark()
  return (
    <button className={`btn ${withLabel ? '' : 'icon ghost'} ${on ? 'on' : ''}`} aria-pressed={on} aria-label={on ? 'Remove bookmark' : 'Bookmark'}
      title={on ? 'Remove bookmark' : 'Bookmark (read later)'} disabled={m.isPending} onClick={(e) => { e.preventDefault(); m.mutate({ id, on: !on }) }}>
      <IconBookmark filled={on} />{withLabel && (on ? 'Bookmarked' : 'Bookmark')}
    </button>
  )
}

// ------------------------------------------------------------ article card
export function ArticleCard({ a, extra }: { a: ArticleBrief; extra?: ReactNode }) {
  return (
    <article className={`acard s${a.severity} ${a.read ? 'read' : ''}`}>
      <div className="meta">
        <Severity level={a.severity} reasons={a.severity_reasons} />
        <span>{a.source.name}</span>
        <span>·</span>
        <TimeAgo iso={a.published_at} />
        {a.related_count > 0 && <span className="chip" title="Other sources reporting the same story">+{a.related_count} source{a.related_count > 1 ? 's' : ''}</span>}
        {a.region && a.region !== 'GLOBAL' && <span className="chip">{a.region}</span>}
        <span className="actions">
          <a className="btn icon ghost" href={a.url} target="_blank" rel="noopener noreferrer" aria-label="Open original source" title="Open original"><IconExternal /></a>
          <BookmarkButton id={a.id} on={a.bookmarked} />
        </span>
      </div>
      <Link className="title" to={`/article/${a.id}`}>{a.title}</Link>
      {(a.ai_summary || a.excerpt) && <p className="excerpt">{a.ai_summary ?? a.excerpt}</p>}
      {extra}
    </article>
  )
}

/** Compact one-line-ish row for dense dashboard lists. */
export function ArticleRow({ a }: { a: ArticleBrief }) {
  return (
    <div className={`arow ${a.read ? 'read' : ''}`}>
      <span className={`dot s${a.severity}`} title={`${['Info', 'Low', 'Medium', 'High', 'Critical'][a.severity]}: ${a.severity_reasons.join('; ')}`} />
      <div className="grow">
        <Link className="t" to={`/article/${a.id}`}>{a.title}</Link>
        <div className="m">{a.source.name} · <TimeAgo iso={a.published_at} />{a.related_count > 0 && <> · +{a.related_count} source{a.related_count > 1 ? 's' : ''}</>}{a.region && a.region !== 'GLOBAL' && <> · {a.region}</>}</div>
      </div>
      <BookmarkButton id={a.id} on={a.bookmarked} />
    </div>
  )
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
    return m ? <Link key={i} className="cite" to={`/article/${m[1]}`} title="Open source evidence">E{m[1]}</Link> : <span key={i}>{p}</span>
  })}</>
}
export function Cites({ ids }: { ids: number[] }) {
  return <>{ids.map((id) => <Link key={id} className="cite" to={`/article/${id}`}>E{id}</Link>)}</>
}

export function PageHeader({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="row between" style={{ marginBottom: '.75rem', alignItems: 'flex-start' }}>
      <div className="grow"><h1>{title}</h1>{sub && <div className="muted small">{sub}</div>}</div>
      {actions && <div className="row">{actions}</div>}
    </div>
  )
}

export function copy(text: string, toast: (m: string) => void) {
  navigator.clipboard?.writeText(text).then(() => toast('Copied'), () => toast('Copy failed'))
}
