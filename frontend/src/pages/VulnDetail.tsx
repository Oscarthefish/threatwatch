import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { Vuln } from '../types'
import { ArticleCard, BackLink, Empty, ErrorBox, Eyebrow, Loading, usePageTitle, Term } from '../components/ui'
import { FollowSheet } from '../components/FollowSheet'
import { IconExternal, IconEye } from '../components/icons'

export default function VulnDetail() {
  const { cve = '' } = useParams()
  const [follow, setFollow] = useState(false)
  const q = useQuery({ queryKey: ['vuln', cve], queryFn: () => api.get<Vuln>(`/api/vulnerabilities/${cve}`) })
  usePageTitle(cve.toUpperCase())
  if (q.isError) return <><BackLink fallback="/vulns" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  if (!q.data) return <Loading lines={8} />
  const v = q.data
  const product = [v.vendor, v.product].filter(Boolean).join(' ')

  return (
    <article className="doc">
      <BackLink fallback="/vulns" />
      <header className="doc-head">
        <Eyebrow parts={['Vulnerability', v.kev && 'Known exploited (CISA KEV)']} />
        <h1>{product || v.cve_id}</h1>
        <p className="row mb-3"><code className="mono-id">{v.cve_id}</code>{v.name && <span className="muted small">{v.name}</span>}</p>
        <div className="row doc-actions">
          {v.watch_id
            ? <Link className="btn on" to={`/watch/${v.watch_id}`}><IconEye />Following</Link>
            : <button type="button" className="btn primary" onClick={() => setFollow(true)}><IconEye />Follow this CVE</button>}
          {v.kev_url && <a className="btn" href={v.kev_url} target="_blank" rel="noopener noreferrer">CISA KEV entry<IconExternal /></a>}
        </div>
      </header>

      <div className="doc-grid">
        <div className="doc-main">
          {v.kev && (
            <section className="panel review" aria-labelledby="kevact-h">
              <header><h2 id="kevact-h">Exploited in the wild</h2><Term id="kev">What is KEV?</Term></header>
              <div className="body">
                <p className="mb-2"><span className="strong">CISA required action: </span>{v.kev_required_action}</p>
                <p className="small muted mb-0">Added {v.kev_date_added}. US federal deadline {v.kev_due_date}.
                  {v.kev_ransomware === 'Known' ? ' Known use in ransomware campaigns.' : ''}</p>
              </div>
            </section>
          )}
          <section className="panel" aria-labelledby="desc-h">
            <header><h2 id="desc-h">Description</h2><span className="basis playbook">CVE record</span></header>
            <div className="body">
              {v.description ? <p className="measure mb-0">{v.description}</p> : <p className="muted mb-0">No description retrieved from the CVE record yet. It is fetched during the next collection runs.</p>}
            </div>
          </section>
          <section aria-labelledby="rep-h">
            <div className="section-head"><h2 id="rep-h">Reporting that names {v.cve_id}</h2><span className="xsmall muted">{v.articles?.length ?? 0}</span></div>
            {v.articles?.length ? <div className="alist">{v.articles.map((a) => <ArticleCard key={a.id} a={a} />)}</div>
              : <Empty title="No reports name this CVE yet"><p>Follow it to be told when one does.</p></Empty>}
          </section>
        </div>

        <aside className="doc-aside" aria-label="Scores and references">
          <section className="panel" aria-labelledby="score-h">
            <header><h2 id="score-h">Scores</h2></header>
            <div className="body">
              <dl className="kv">
                <dt><Term id="epss">EPSS</Term></dt>
                <dd>{v.epss != null ? <><b className="mono">{(v.epss * 100).toFixed(2)}%</b> chance of exploitation in 30 days<div className="xsmall muted">percentile {((v.epss_percentile ?? 0) * 100).toFixed(0)} · {v.epss_date}</div></> : 'Not scored'}</dd>
                <dt><Term id="cvss">CVSS</Term></dt>
                <dd>{v.cvss_score != null ? <><b className="mono">{v.cvss_score}</b> {v.cvss_severity?.toLowerCase()}<div className="xsmall muted wrap-any">{v.cvss_source}</div><div className="mono xsmall muted wrap-any">{v.cvss_vector}</div></> : 'Not yet published'}</dd>
              </dl>
            </div>
          </section>
          <section className="panel" aria-labelledby="ref-h">
            <header><h2 id="ref-h">References</h2></header>
            <div className="body">
              <ul className="reflist">
                <li><a href={v.cve_url} target="_blank" rel="noopener noreferrer">CVE.org record</a></li>
                <li><a href={v.nvd_url} target="_blank" rel="noopener noreferrer">NVD</a></li>
                {v.references.slice(0, 15).map((r) => <li key={r}><a href={r} target="_blank" rel="noopener noreferrer" className="wrap-any">{r.replace(/^https?:\/\//, '')}</a></li>)}
              </ul>
            </div>
          </section>
        </aside>
      </div>
      {follow && <FollowSheet onClose={() => setFollow(false)} suggestions={[{ kind: 'vulnerability', title: `${v.cve_id}${product ? ` (${product})` : ''}`, identifiers: [v.cve_id], aliases: [], context_terms: [], existing_watch_id: null }]} />}
    </article>
  )
}
