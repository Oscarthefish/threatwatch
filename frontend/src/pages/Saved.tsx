import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleBrief, Watch } from '../types'
import { ArticleCard, Empty, ErrorBox, Loading, PageHeader, TimeAgo, useToast } from '../components/ui'
import { WatchCard } from './Watches'
import { useConfirm } from '../components/Sheet'

type Tab = 'bookmarks' | 'following' | 'history'

function BookmarkExtra({ a }: { a: ArticleBrief }) {
  const [edit, setEdit] = useState(false)
  const [note, setNote] = useState(a.bookmark?.note ?? '')
  const [tags, setTags] = useState((a.bookmark?.tags ?? []).join(', '))
  const qc = useQueryClient()
  const toast = useToast()
  const m = useMutation({ mutationFn: () => api.put(`/api/bookmarks/${a.id}`, { note, tags: tags.split(',').map((t) => t.trim()).filter(Boolean) }),
    onSuccess: () => { toast('Saved'); setEdit(false); qc.invalidateQueries({ queryKey: ['bookmarks'] }) } })
  if (!edit) return (
    <div className="small" style={{ marginTop: '.35rem' }}>
      {a.bookmark?.note && <p style={{ whiteSpace: 'pre-wrap', margin: '0 0 .3rem' }}>{a.bookmark.note}</p>}
      <div className="row">{a.bookmark?.tags.map((t) => <span key={t} className="chip">#{t}</span>)}
        <span className="faint">saved <TimeAgo iso={a.bookmark?.created_at} /></span>
        <button className="btn ghost small" style={{ minHeight: 0 }} onClick={() => setEdit(true)}>Edit note & tags</button></div>
    </div>)
  return (
    <form style={{ marginTop: '.5rem' }} onSubmit={(e) => { e.preventDefault(); m.mutate() }}>
      <textarea className="input" aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)} />
      <input className="input" aria-label="Tags" style={{ marginTop: '.4rem' }} value={tags} placeholder="tags, comma separated" onChange={(e) => setTags(e.target.value)} />
      <div className="row" style={{ marginTop: '.4rem' }}><button className="btn primary">Save</button><button type="button" className="btn" onClick={() => setEdit(false)}>Cancel</button></div>
    </form>)
}

export default function Saved() {
  const [tab, setTab] = useState<Tab>('bookmarks')
  const [tag, setTag] = useState('')
  const bm = useQuery({ queryKey: ['bookmarks'], queryFn: () => api.get<ArticleBrief[]>('/api/bookmarks'), enabled: tab === 'bookmarks' })
  const wl = useQuery({ queryKey: ['watches', 'active'], queryFn: () => api.get<Watch[]>('/api/watches?status=active'), enabled: tab === 'following' })
  const hist = useQuery({ queryKey: ['history'], queryFn: () => api.get<ArticleBrief[]>('/api/history'), enabled: tab === 'history' })
  const allTags = [...new Set((bm.data ?? []).flatMap((a) => a.bookmark?.tags ?? []))].sort()
  const shown = (bm.data ?? []).filter((a) => !tag || a.bookmark?.tags.includes(tag))
  return (
    <>
      <PageHeader title="Saved" eyebrow={['Yours']} sub="Bookmarks are for reading later. Anything you have opened stays readable offline." />
      <div className="tabs" role="tablist">
        {([['bookmarks', 'Bookmarks'], ['following', 'Following'], ['history', 'Reading history']] as [Tab, string][]).map(([t, l]) =>
          <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>{l}</button>)}
      </div>
      {tab === 'bookmarks' && <>
        {allTags.length > 0 && <div className="chips" style={{ marginBottom: '.75rem' }}><button className={`chip ${!tag ? 'on' : ''}`} onClick={() => setTag('')}>All</button>
          {allTags.map((t) => <button key={t} className={`chip ${tag === t ? 'on' : ''}`} onClick={() => setTag(tag === t ? '' : t)}>#{t}</button>)}</div>}
        {bm.isError ? <ErrorBox error={bm.error} /> : !bm.data ? <Loading /> : shown.length === 0 ? <Empty title="No bookmarks yet">Tap the bookmark icon on any article to save it for later.</Empty>
          : <div className="alist">{shown.map((a) => <ArticleCard key={a.id} a={a} extra={<BookmarkExtra a={a} />} />)}</div>}
      </>}
      {tab === 'following' && (wl.isError ? <ErrorBox error={wl.error} /> : !wl.data ? <Loading /> : wl.data.length === 0 ? <Empty title="Not following anything" />
        : <div className="stack">{wl.data.map((w) => <WatchCard key={w.id} w={w} />)}</div>)}
      {tab === 'history' && (hist.isError ? <ErrorBox error={hist.error} /> : !hist.data ? <Loading /> : hist.data.length === 0 ? <Empty title="No reading history" />
        : <><div className="alist">{hist.data.map((a) => <ArticleCard key={a.id} a={a} extra={<div className="small faint">read <TimeAgo iso={a.last_read_at} /></div>} />)}</div>
          <ClearHistory /></>)}
    </>
  )
}

function ClearHistory() {
  const qc = useQueryClient()
  const confirm = useConfirm()
  const m = useMutation({ mutationFn: () => api.del('/api/history'), onSuccess: () => qc.invalidateQueries() })
  return <div className="center mt-4"><button className="btn danger" aria-busy={m.isPending || undefined}
    onClick={async () => { if (await confirm({ title: 'Clear reading history?', body: 'Articles will show as unread again. Bookmarks and follows are not affected.', confirmLabel: 'Clear history', danger: true })) m.mutate() }}>Clear history</button></div>
}
