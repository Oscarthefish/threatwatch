import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief } from '../types'
import { ArticleCard, Empty, ErrorBox, Field, Loading, PageHeader, TimeAgo, useToast } from '../components/ui'
import { useConfirm } from '../components/Sheet'
import { splitList } from '../components/follow'

type View = 'bookmarks' | 'history'

function BookmarkNote({ a }: { a: ArticleBrief }) {
  const [edit, setEdit] = useState(false)
  const [note, setNote] = useState(a.bookmark?.note ?? '')
  const [tags, setTags] = useState((a.bookmark?.tags ?? []).join(', '))
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({
    mutationFn: () => api.put(`/api/bookmarks/${a.id}`, { note, tags: splitList(tags) }),
    onSuccess: () => { toast('Saved'); setEdit(false); qc.invalidateQueries({ queryKey: ['bookmarks'] }) },
    onError: () => toast('Not saved. Your text is still in the form; try again.', 'error'),
  })
  if (!edit) return (
    <div className="bm-note mt-2">
      {a.bookmark?.note && <p className="small prewrap mb-2">{a.bookmark.note}</p>}
      <div className="row xsmall muted">
        {a.bookmark?.tags.map((t) => <span key={t} className="chip">#{t}</span>)}
        <span>saved <TimeAgo iso={a.bookmark?.created_at} /></span>
        <button type="button" className="link xsmall" onClick={() => setEdit(true)}>{a.bookmark?.note ? 'Edit note' : 'Add note'}</button>
      </div>
    </div>
  )
  return (
    <form className="mt-3" onSubmit={(e) => { e.preventDefault(); m.mutate() }}>
      <Field label="Note"><textarea className="input" value={note} autoFocus onChange={(e) => setNote(e.target.value)} /></Field>
      <Field label="Tags" hint="Comma separated."><input className="input" value={tags} onChange={(e) => setTags(e.target.value)} /></Field>
      <div className="row"><button className="btn primary" aria-busy={m.isPending || undefined}>Save</button><button type="button" className="btn quiet" onClick={() => setEdit(false)}>Cancel</button></div>
    </form>
  )
}

export default function Saved() {
  const [view, setView] = useState<View>('bookmarks')
  const [tag, setTag] = useState('')
  const bm = useQuery({ queryKey: ['bookmarks'], queryFn: () => api.get<ArticleBrief[]>('/api/bookmarks'), enabled: view === 'bookmarks' })
  const hist = useQuery({ queryKey: ['history'], queryFn: () => api.get<ArticleBrief[]>('/api/history'), enabled: view === 'history' })
  const allTags = [...new Set((bm.data ?? []).flatMap((a) => a.bookmark?.tags ?? []))].sort()
  const shown = (bm.data ?? []).filter((a) => !tag || a.bookmark?.tags.includes(tag))

  return (
    <>
      <PageHeader title="Saved" eyebrow={['Yours']}
        sub={<>Bookmarks are for reading later; to track an evolving threat, use <Link to="/watch">Following</Link>. Pages you have opened stay readable offline.</>} />
      <div className="seg mb-4" role="group" aria-label="Show">
        <button type="button" aria-pressed={view === 'bookmarks'} onClick={() => setView('bookmarks')}>Bookmarks{bm.data ? ` (${bm.data.length})` : ''}</button>
        <button type="button" aria-pressed={view === 'history'} onClick={() => setView('history')}>Reading history</button>
      </div>

      {view === 'bookmarks' && <>
        {allTags.length > 0 && (
          <div className="chips scroll mb-4" role="group" aria-label="Filter by tag">
            <button type="button" className={`chip ${!tag ? 'on' : ''}`} aria-pressed={!tag} onClick={() => setTag('')}>All</button>
            {allTags.map((t) => <button type="button" key={t} className={`chip ${tag === t ? 'on' : ''}`} aria-pressed={tag === t} onClick={() => setTag(tag === t ? '' : t)}>#{t}</button>)}
          </div>
        )}
        {bm.isError ? <ErrorBox error={bm.error} onRetry={() => bm.refetch()} /> : !bm.data ? <Loading /> : shown.length === 0 ? (
          tag ? <Empty title={`Nothing tagged #${tag}`}><button type="button" className="btn" onClick={() => setTag('')}>Show all bookmarks</button></Empty>
            : <Empty title="No bookmarks yet"><p>Use the bookmark button on any report to keep it here, with an optional note and tags.</p></Empty>
        ) : <div className="alist">{shown.map((a) => <ArticleCard key={a.id} a={a} extra={<BookmarkNote a={a} />} />)}</div>}
      </>}

      {view === 'history' && (hist.isError ? <ErrorBox error={hist.error} onRetry={() => hist.refetch()} /> : !hist.data ? <Loading /> : hist.data.length === 0
        ? <Empty title="No reading history"><p>Reports you open are listed here.</p></Empty>
        : <>
          <div className="alist">{hist.data.map((a) => <ArticleCard key={a.id} a={a} extra={<div className="xsmall muted mt-2">Read <TimeAgo iso={a.last_read_at} /></div>} />)}</div>
          <ClearHistory />
        </>)}
    </>
  )
}

function ClearHistory() {
  const qc = useQueryClient()
  const confirm = useConfirm()
  const m = useMutation({ mutationFn: () => api.del('/api/history'), onSuccess: () => qc.invalidateQueries() })
  return (
    <div className="center mt-4">
      <button type="button" className="btn danger" aria-busy={m.isPending || undefined}
        onClick={async () => { if (await confirm({ title: 'Clear reading history?', body: 'Reports will show as unread again. Bookmarks and followed items are not affected.', confirmLabel: 'Clear history', danger: true })) m.mutate() }}>
        Clear history
      </button>
    </div>
  )
}
