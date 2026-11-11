import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api'
import type { ArticleDetail } from '../types'
import {
  ActionList, ArticleRow, BackLink, BookmarkButton, Confidence, copy, ErrorBox, Eyebrow, fmtDate, Loading, Severity, usePageTitle, useToast,
} from '../components/ui'
import { FollowSheet } from '../components/FollowSheet'
import { IconCopy, IconExternal, IconEye } from '../components/icons'

const ENTITY_LABELS: Record<string, string> = {
  cve: 'CVEs', actor: 'Threat actors', ransomware: 'Ransomware', malware: 'Malware and tools', vendor: 'Vendors', product: 'Products',
  victim: 'Organisations', attack_technique: 'ATT&CK techniques', attack_technique_inferred: 'ATT&CK (keyword-inferred)', region: 'Regions',
  country: 'Countries',
}
const ENTITY_ORDER = ['actor', 'ransomware', 'malware', 'victim', 'attack_technique', 'attack_technique_inferred', 'vendor', 'product', 'region', 'country']
const SECTION_LABELS: Record<string, [string, string]> = {
  breaking: ['Breaking', '/breaking'], 'threat-intel': ['Threat intelligence', '/intel'], vulnerabilities: ['Vulnerabilities', '/vulns'],
  'soc-dfir': ['SOC & DFIR', '/soc'], 'nz-apac': ['NZ & APAC', '/apac'],
}
const IOC_TYPES = ['ipv4', 'domain', 'url', 'sha256', 'sha1', 'md5']
const EXPLOIT: Record<string, string> = {
  confirmed: 'Exploitation confirmed', reported: 'Exploitation reported', poc_public: 'Public proof of concept',
  none_reported: 'No exploitation reported', not_applicable: 'Not a vulnerability story',
}

/** First sentence or two of the publisher's text, used as the lead when there is no AI summary. */
function lead(text: string, limit = 360): string {
  let t = text.replace(/\s+/g, ' ').trim()
  const truncated = /(\[(…|\.\.\.)\]|…|\.\.\.)$/.test(t)
  if (truncated) {  // drop the fragment left by the publisher's own truncation ("… OpenSSH is t…")
    t = t.replace(/(\[(…|\.\.\.)\]|…|\.\.\.)$/, '').trim()
    const end = Math.max(t.lastIndexOf('. '), t.lastIndexOf('? '), t.lastIndexOf('! '))
    if (end > 40) t = t.slice(0, end + 1)
  }
  if (t.length <= limit) return t
  const cut = t.slice(0, limit)
  const end = Math.max(cut.lastIndexOf('. '), cut.lastIndexOf('? '), cut.lastIndexOf('! '))
  return end > 80 ? cut.slice(0, end + 1) : `${cut.slice(0, cut.lastIndexOf(' '))} …`
}

export default function ArticlePage() {
  const { id = '' } = useParams()
  const qc = useQueryClient()
  const toast = useToast()
  const [follow, setFollow] = useState(false)
  const [note, setNote] = useState<string | null>(null)
  const q = useQuery({ queryKey: ['article', id], queryFn: () => api.get<ArticleDetail>(`/api/articles/${id}`) })
  useEffect(() => { if (q.data && !q.data.read) api.post(`/api/articles/${id}/read`).catch(() => {}) }, [q.data, id])
  const summarise = useMutation({
    mutationFn: () => api.post(`/api/articles/${id}/summarise`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['article', id] }),
    onError: (e) => toast(`No AI summary: ${(e as Error).message}`, 'error'),
  })
  const saveNote = useMutation({
    mutationFn: (n: string) => api.put(`/api/bookmarks/${id}`, { note: n, tags: q.data?.bookmark?.tags ?? [] }),
    onSuccess: () => { toast('Note saved'); setNote(null); qc.invalidateQueries({ queryKey: ['article', id] }) },
    onError: () => toast('Note not saved. Your text is still in the box; try again.', 'error'),
  })

  usePageTitle(q.data?.title)
  if (q.isError) return <><BackLink fallback="/" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  if (!q.data) return <Loading lines={10} />
  const a = q.data
  const ents = ENTITY_ORDER.filter((t) => a.entities[t]?.length).map((t) => [t, a.entities[t]] as const)
  const iocs = IOC_TYPES.flatMap((t) => (a.entities[t] ?? []).map((e) => ({ type: t, value: e.value })))
  const sourceText = a.content_text || a.summary_text
  const words = sourceText ? sourceText.split(/\s+/).length : 0
  const leadText = sourceText ? lead(sourceText) : ''
  const excerptOnly = !a.ai && words < 140  // the lead already shows everything the feed provided
  const following = a.watches.filter((w) => w.status === 'linked')
  const pending = a.watches.filter((w) => w.status === 'candidate')

  return (
    <article className="doc">
      <BackLink fallback="/" />
      <header className="doc-head">
        <Eyebrow parts={[a.source.name, fmtDate(a.published_at)]} />
        <h1>{a.title}</h1>
        <div className="row doc-tags">
          <Severity level={a.severity} reasons={a.severity_reasons} />
          <Confidence value={a.confidence} />
          {a.sections.map((s) => SECTION_LABELS[s] ? <Link key={s} className="chip link-chip" to={SECTION_LABELS[s][1]}>{SECTION_LABELS[s][0]}</Link> : <span key={s} className="chip">{s}</span>)}
        </div>
        <div className="row doc-actions">
          <a className="btn primary" href={a.url} target="_blank" rel="noopener noreferrer">Read on {a.source.name}<IconExternal /></a>
          <BookmarkButton id={a.id} on={a.bookmarked} withLabel />
          <button type="button" className={`btn ${following.length ? 'on' : ''}`} onClick={() => setFollow(true)}><IconEye />{following.length ? 'Following' : 'Follow'}</button>
        </div>
        {(following.length > 0 || pending.length > 0) && (
          <p className="small muted mb-0">
            {following.length > 0 && <>Part of {following.map((w, i) => <span key={w.id}>{i > 0 && ', '}<Link to={`/watch/${w.id}`}>{w.title}</Link></span>)}. </>}
            {pending.length > 0 && <>Awaiting your review for {pending.map((w, i) => <span key={w.id}>{i > 0 && ', '}<Link to={`/watch/${w.id}`}>{w.title}</Link></span>)}.</>}
          </p>
        )}
      </header>

      <div className="doc-grid">
        <div className="doc-main">
          <section className="panel" aria-labelledby="brief-h">
            <header>
              <h2 id="brief-h">In brief</h2>
              <span className={`basis ${a.ai ? '' : 'playbook'}`}>{a.ai ? `AI · ${a.ai.model}` : `From ${a.source.name}`}</span>
            </header>
            <div className="body">
              {a.ai ? <>
                <p className="lead">{a.ai.summary}</p>
                {a.ai.why_it_matters && <><h3>Why it matters</h3><p>{a.ai.why_it_matters}</p></>}
                {a.ai.technical && <><h3>Technical analysis</h3><p className="prewrap">{a.ai.technical}</p></>}
                <p className="xsmall faint mb-0">{EXPLOIT[a.ai.exploitation_status] ?? ''}. Generated from the source text; check the original before acting.</p>
              </> : <>
                {sourceText ? <p className="lead">{leadText}</p> : <p className="muted">The feed gave no text for this item. Read it on {a.source.name}.</p>}
                <h3>Why it is rated {['info', 'low', 'medium', 'high', 'critical'][a.severity]}</h3>
                <ul className="claims">{a.severity_reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                {a.ai_available && (
                  <button type="button" className="btn" aria-busy={summarise.isPending || undefined} onClick={() => summarise.mutate()}>Summarise with AI</button>
                )}
              </>}
            </div>
          </section>

          <ActionList actions={a.actions} ai={a.ai?.soc_actions} />

          <section className="panel" aria-labelledby="src-h">
            <header>
              <h2 id="src-h">Source text</h2>
              <span className="xsmall muted">{words ? `${words.toLocaleString()} words · ` : ''}untrusted, shown as plain text</span>
            </header>
            <div className="body">
              {!sourceText ? <p className="muted mb-0">No text in the feed. <a href={a.url} target="_blank" rel="noopener noreferrer">Read on {a.source.name}</a>.</p>
                : excerptOnly ? <p className="small muted mb-0">{a.source.name}’s feed only includes the excerpt shown above. <a href={a.url} target="_blank" rel="noopener noreferrer">Read the full article</a>.</p>
                : words < 140 ? <div className="source-text">{sourceText}</div>
                : (
                  <details className="disclose">
                    <summary>Show the full text from {a.source.name}</summary>
                    <div className="source-text" tabIndex={0} role="region" aria-label={`Source text from ${a.source.name}`}>{sourceText}</div>
                  </details>
                )}
            </div>
          </section>

          {a.related.length > 0 && (
            <section className="panel" aria-labelledby="rel-h">
              <header><h2 id="rel-h">Also reported by</h2><span className="xsmall muted">{a.related.length} other source{a.related.length > 1 ? 's' : ''}</span></header>
              <div className="body">{a.related.map((r) => <ArticleRow key={r.id} a={r} />)}</div>
            </section>
          )}
        </div>

        <aside className="doc-aside" aria-label="Facts">
          <section className="panel" aria-labelledby="rec-h">
            <header><h2 id="rec-h">Record</h2></header>
            <div className="body">
              <dl className="kv">
                <dt>Source</dt><dd>{a.source.homepage ? <a href={a.source.homepage} target="_blank" rel="noopener noreferrer">{a.source.name}</a> : a.source.name}</dd>
                {a.author && <><dt>Author</dt><dd>{a.author}</dd></>}
                <dt>Published</dt><dd className="mono">{fmtDate(a.published_at)}</dd>
                <dt>Collected</dt><dd className="mono">{fmtDate(a.retrieved_at)}</dd>
                <dt>Confidence</dt><dd><Confidence value={a.confidence} /></dd>
              </dl>
            </div>
          </section>

          {a.vulnerabilities.length > 0 && (
            <section className="panel" aria-labelledby="vul-h">
              <header><h2 id="vul-h">Vulnerabilities</h2></header>
              <div className="body">
                {a.vulnerabilities.map((v) => (
                  <Link key={v.cve_id} to={`/vuln/${v.cve_id}`} className="kevrow">
                    <div className="grow">
                      <div className="row nowrap"><code className="mono-id">{v.cve_id}</code>{v.kev && <span className="chip kev">KEV</span>}</div>
                      <div className="xsmall muted">{[v.vendor, v.product].filter(Boolean).join(' ') || 'Product not yet known'}</div>
                    </div>
                    <div className="r">
                      {v.cvss_score != null ? `CVSS ${v.cvss_score}` : 'CVSS n/a'}<br />
                      {v.epss != null ? `EPSS ${(v.epss * 100).toFixed(1)}%` : 'EPSS n/a'}
                    </div>
                  </Link>
                ))}
              </div>
            </section>
          )}

          {iocs.length > 0 && (
            <section className="panel" aria-labelledby="ioc-h">
              <header>
                <h2 id="ioc-h">Indicators ({iocs.length})</h2>
                <button type="button" className="link" onClick={() => copy(iocs.map((i) => i.value).join('\n'), toast)}>Copy all</button>
              </header>
              <div className="body">
                <p className="xsmall muted">Extracted from the source text and refanged. Handle with care.</p>
                {iocs.map((i) => (
                  <div key={i.value} className="ioc">
                    <span className="chip">{i.type}</span><code>{i.value}</code>
                    <button type="button" className="btn icon quiet compact" aria-label={`Copy ${i.value}`} onClick={() => copy(i.value, toast)}><IconCopy /></button>
                  </div>
                ))}
              </div>
            </section>
          )}

          {ents.length > 0 && (
            <section className="panel" aria-labelledby="ent-h">
              <header><h2 id="ent-h">Entities</h2></header>
              <div className="body stack-tight">
                {ents.map(([t, list]) => (
                  <div key={t}>
                    <div className="field-label">{ENTITY_LABELS[t] ?? t}</div>
                    <div className="chips">{list.map((e) => (
                      <span key={e.value} className="chip">
                        {e.value}{e.name ? ` ${e.name}` : ''}
                        {e.method === 'ai' && <span className="ai-mark" aria-label="extracted by AI, verified in the source text">AI</span>}
                      </span>
                    ))}</div>
                  </div>
                ))}
              </div>
            </section>
          )}

          <section className="panel" aria-labelledby="note-h">
            <header><h2 id="note-h">Your note</h2></header>
            <div className="body">
              {!a.bookmarked ? <p className="small muted mb-0">Bookmark this article to keep a private note with it.</p>
                : note === null ? <>
                  <p className={`prewrap ${a.bookmark?.note ? '' : 'muted'}`}>{a.bookmark?.note || 'No note yet.'}</p>
                  <button type="button" className="btn" onClick={() => setNote(a.bookmark?.note ?? '')}>{a.bookmark?.note ? 'Edit note' : 'Add note'}</button>
                </> : (
                  <form onSubmit={(e) => { e.preventDefault(); saveNote.mutate(note) }}>
                    <label className="sr-only" htmlFor="note">Note</label>
                    <textarea id="note" className="input" value={note} autoFocus onChange={(e) => setNote(e.target.value)} />
                    <div className="row mt-2">
                      <button className="btn primary" aria-busy={saveNote.isPending || undefined}>Save note</button>
                      <button type="button" className="btn quiet" onClick={() => setNote(null)}>Cancel</button>
                    </div>
                  </form>
                )}
            </div>
          </section>
        </aside>
      </div>
      {follow && <FollowSheet suggestions={a.watch_suggestions} originArticleId={a.id} onClose={() => setFollow(false)} />}
    </article>
  )
}
