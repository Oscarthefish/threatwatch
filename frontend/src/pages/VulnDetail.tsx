import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { Vuln } from '../types'
import { ArticleList, BackLink, Empty, ErrorBox, Loading, PageHeader } from '../components/ui'
import { FollowSheet } from '../components/FollowSheet'
import { IconExternal } from '../components/icons'

export default function VulnDetail() {
  const { cve = '' } = useParams()
  const [follow, setFollow] = useState(false)
  const q = useQuery({ queryKey: ['vuln', cve], queryFn: () => api.get<Vuln>(`/api/vulnerabilities/${cve}`) })
  if (q.isError) return <><BackLink fallback="/vulns" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  if (!q.data) return <Loading lines={8} />
  const v = q.data
  return (
    <>
      <BackLink fallback="/vulns" />
      <PageHeader title={v.cve_id} eyebrow={['Vulnerability', v.kev && 'CISA KEV']} sub={[v.vendor, v.product].filter(Boolean).join(' · ')} actions={
        v.watch_id ? <Link className="btn on" to={`/watch/${v.watch_id}`}>Following</Link> : <button className="btn primary" onClick={() => setFollow(true)}>Follow</button>} />
      <div className="card">
        <div className="chips" style={{ marginBottom: '.6rem' }}>
          {v.kev ? <span className="chip kev">In CISA KEV — exploitation confirmed</span> : <span className="chip">Not in CISA KEV</span>}
          {v.kev_ransomware === 'Known' && <span className="chip kev">Known ransomware campaign use</span>}
        </div>
        {v.name && <h2>{v.name}</h2>}
        {v.description ? <p>{v.description}</p> : <p className="muted">No CVE record description retrieved yet.</p>}
        <dl className="kv">
          <dt>CVSS</dt><dd>{v.cvss_score != null ? <>{v.cvss_score} {v.cvss_severity} <span className="faint small">({v.cvss_source})</span><div className="mono small faint">{v.cvss_vector}</div></> : '—'}</dd>
          <dt>EPSS</dt><dd>{v.epss != null ? <>{(v.epss * 100).toFixed(2)}% probability (percentile {((v.epss_percentile ?? 0) * 100).toFixed(0)}) · {v.epss_date}</> : '—'}</dd>
          {v.kev && <><dt>KEV added</dt><dd>{v.kev_date_added} (federal due date {v.kev_due_date})</dd>
            <dt>Required action</dt><dd>{v.kev_required_action}</dd></>}
        </dl>
        <div className="divider" />
        <h3>Remediation & references</h3>
        <ul className="claims">
          {v.kev_url && <li><a href={v.kev_url} target="_blank" rel="noopener noreferrer">CISA KEV entry <IconExternal width={12} /></a></li>}
          <li><a href={v.cve_url} target="_blank" rel="noopener noreferrer">CVE.org record <IconExternal width={12} /></a></li>
          <li><a href={v.nvd_url} target="_blank" rel="noopener noreferrer">NVD <IconExternal width={12} /></a></li>
          {v.references.slice(0, 15).map((r) => <li key={r}><a href={r} target="_blank" rel="noopener noreferrer" style={{ overflowWrap: 'anywhere' }}>{r}</a></li>)}
        </ul>
      </div>
      <section className="section">
        <div className="section-head"><h2>Reporting that mentions {v.cve_id}</h2></div>
        <ArticleList items={v.articles} empty={<Empty title="No articles reference this CVE yet" />} />
      </section>
      {follow && <FollowSheet onClose={() => setFollow(false)} suggestions={[{ kind: 'vulnerability', title: `${v.cve_id}${v.product ? ` (${v.vendor} ${v.product})` : ''}`, identifiers: [v.cve_id], aliases: [], context_terms: [], existing_watch_id: null }]} />}
    </>
  )
}
