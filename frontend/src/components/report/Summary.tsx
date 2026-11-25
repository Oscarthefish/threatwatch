import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ExtLink, techniqueUrl } from '../ui'
import { quoteFrom, type Analysis, type Chapter, type FindingDraft, type Named, type ReportDetail } from '../../reports'

const inRange = (p: number, c?: Chapter) => !c || (p >= c.start && p <= c.end)
const chapName = (c: Chapter) => `${c.number} ${c.title}`

function Save({ onClick, label }: { onClick: () => void; label: string }) {
  return <button type="button" className="rp-save" onClick={onClick} aria-label={`Save as finding: ${label.slice(0, 60)}`}>Save as finding</button>
}

export function PageLink({ page }: { page: number }) {
  return <Link className="rp-pl" to={`?tab=read&page=${page}`} aria-label={`Read page ${page}`}>p. {page}</Link>
}

function Pages({ pages }: { pages: number[] }) {
  return <span className="rp-pages-list">{pages.slice(0, 6).map((p) => <PageLink key={p} page={p} />)}{pages.length > 6 && <span className="xsmall muted">+{pages.length - 6}</span>}</span>
}

function Section({ id, title, note, children }: { id: string; title: string; note?: ReactNode; children: ReactNode }) {
  return (
    <section className="card rp-sum" aria-labelledby={id}>
      <h2 id={id} className="rp-h">{title}</h2>
      {note && <p className="xsmall muted">{note}</p>}
      {children}
    </section>
  )
}

/** Items carry their chapter label; show them under chapter subheadings when there are several chapters. */
function ByChapter<T extends { chapter: string | null }>({ items, render, one }: { items: T[]; render: (x: T, i: number) => ReactNode; one: boolean }) {
  if (one) return <>{items.map(render)}</>
  const groups: [string, T[]][] = []
  for (const x of items) {
    const k = x.chapter ?? 'Other'
    const g = groups.find(([n]) => n === k)
    if (g) g[1].push(x); else groups.push([k, [x]])
  }
  return <>{groups.map(([k, xs]) => <div key={k} className="rp-group"><h3 className="rp-gh">{k}</h3>{xs.map(render)}</div>)}</>
}

function NamedList({ items, kind }: { items: Named[]; kind?: 'cve' }) {
  return (
    <ul className="rp-named">
      {items.map((n) => (
        <li key={n.value}>
          {kind === 'cve' ? <Link to={`/vuln/${n.value}`}>{n.value}</Link> : <span>{n.value}</span>}
          {kind === 'cve' && n.known?.kev && <span className="rp-tag">Known exploited (CISA)</span>}
          {kind === 'cve' && n.known?.cvss != null && <span className="xsmall muted">CVSS {n.known.cvss}</span>}
          <Pages pages={n.pages} />
        </li>))}
    </ul>
  )
}

export function Summary({ d, onAdd }: { d: ReportDetail; onAdd: (dr: FindingDraft) => void }) {
  const a = d.analysis as Analysis
  const [chap, setChap] = useState<string>('')
  const c = a.chapters.find((x) => x.number === chap)
  const h = a.highlights
  const byChap = <T extends { chapter: string | null }>(xs: T[]) => (c ? xs.filter((x) => x.chapter === chapName(c)) : xs)
  const named = (xs: Named[]) => xs.map((n) => ({ ...n, pages: n.pages.filter((p) => inRange(p, c)) })).filter((n) => n.pages.length)
  const takeaways = byChap(h.takeaways), recs = byChap(h.recommendations), stats = byChap(h.statistics)
  const actors = named(h.actors), malware = named(h.malware), tech = named(h.technologies), cves = named(h.cves)
  const techniques = h.techniques.map((t) => ({ ...t, pages: t.pages.filter((p) => inRange(p, c)) })).filter((t) => t.pages.length)
  const vendor = h.vendor_guidance.filter((v) => inRange(v.page, c))
  const publisher = d.report.publisher || a.running_title?.split(' ')[0] || 'the publisher'
  const one = !!c || a.chapters.length < 2
  const nothing = !takeaways.length && !recs.length && !stats.length && !actors.length && !malware.length && !cves.length && !techniques.length
  return (
    <div className="stack">
      <p className="small muted mb-0">Pulled from the report's own text by layout rules, not by AI, so every line is the publisher's wording. Each item links to its page; check it in context before relying on it.</p>
      {a.chapters.length > 1 && (
        <>
          <div className="chips scroll" role="group" aria-label="Chapter">
            <button type="button" className={`chip ${!chap ? 'on' : ''}`} aria-pressed={!chap} onClick={() => setChap('')}>Whole report</button>
            {a.chapters.map((x) => <button key={x.number} type="button" className={`chip ${chap === x.number ? 'on' : ''}`} aria-pressed={chap === x.number} onClick={() => setChap(chap === x.number ? '' : x.number)}>{x.number} {x.title}</button>)}
          </div>
          {!c && (
            <Section id="rp-s-ch" title="In this report">
              <ol className="rp-chapters">
                {a.chapters.map((x) => (
                  <li key={x.number}><Link to={`?tab=read&page=${x.start}`}><span className="rp-ch-num">{x.number}</span><span><strong>{x.title}</strong>{x.subtitle && <> · {x.subtitle}</>}</span><span className="xsmall muted nowrap">pp. {x.start} to {x.end}</span></Link></li>))}
              </ol>
            </Section>
          )}
          {c && <p className="mb-0"><strong>{c.number} {c.title}</strong>{c.subtitle && <> · {c.subtitle}</>} <span className="xsmall muted">pp. {c.start} to {c.end}</span> <Link to={`?tab=read&page=${c.start}`}>Read this chapter</Link></p>}
        </>
      )}
      {nothing && <div className="notice">Nothing stood out in {c ? 'this chapter' : 'the text'} by these rules. The Read tab has the full text.</div>}
      {takeaways.length > 0 && (
        <Section id="rp-s-kt" title="Key takeaways">
          <ByChapter items={takeaways} one={one} render={(t, i) => <p key={i} className="rp-item">{t.text} <PageLink page={t.page} /> <Save label={t.text} onClick={() => onAdd({ page: t.page, quote: quoteFrom(t.text), title: t.text.slice(0, 120), category: 'attacker_behaviour', evidence_type: 'vendor_conclusion', origin: 'summary' })} /></p>} />
        </Section>
      )}
      {recs.length > 0 && (
        <Section id="rp-s-rec" title="What the report recommends" note={`The publisher's defensive advice in their own words; open one to read it. Advice about ${publisher}'s products is kept apart, at the end.`}>
          <ByChapter items={recs} one={one} render={(r, i) => r.title ? (
            <details key={i} className="rp-rec"><summary><span className="rp-rec-t">{r.title}</span> <span className="xsmall muted">p. {r.page}</span></summary>
              <p className="mb-0">{r.text} <PageLink page={r.page} /> <Save label={r.title} onClick={() => onAdd({ page: r.page, quote: quoteFrom(r.text), title: r.title ?? '', category: 'hardening_recommendation', evidence_type: 'vendor_recommendation', origin: 'summary' })} /></p></details>
          ) : <p key={i} className="rp-rec mb-0">{r.text} <PageLink page={r.page} /> <Save label={r.text} onClick={() => onAdd({ page: r.page, quote: quoteFrom(r.text), title: r.text.slice(0, 100), category: 'hardening_recommendation', evidence_type: 'vendor_recommendation', origin: 'summary' })} /></p>} />
        </Section>
      )}
      {stats.length > 0 && (
        <Section id="rp-s-st" title="Figures quoted in the report" note="As the publisher states them, from their own data. Read the methodology before comparing figures with other reports.">
          <ByChapter items={stats} one={one} render={(s, i) => <p key={i} className="rp-item">{s.text} <PageLink page={s.page} /> <Save label={s.text} onClick={() => onAdd({ page: s.page, quote: quoteFrom(s.text), category: 'statistical_trend', evidence_type: 'aggregate_statistic', origin: 'summary' })} /></p>} />
        </Section>
      )}
      {(actors.length + malware.length + cves.length + tech.length) > 0 && (
        <Section id="rp-s-nm" title="Named in the report" note="Matched against Threat Watch's lists of known names, so unfamiliar names may be missing.">
          <div className="rp-named-grid">
            {actors.length > 0 && <div><h3 className="rp-gh">Threat actors</h3><NamedList items={actors} /></div>}
            {malware.length > 0 && <div><h3 className="rp-gh">Malware and ransomware</h3><NamedList items={malware} /></div>}
            {cves.length > 0 && <div><h3 className="rp-gh">Vulnerabilities</h3><NamedList items={cves} kind="cve" /></div>}
            {tech.length > 0 && <div><h3 className="rp-gh">Products and platforms</h3><NamedList items={tech} /></div>}
          </div>
        </Section>
      )}
      {techniques.length > 0 && (
        <Section id="rp-s-tt" title="ATT&CK techniques" note={techniques.some((t) => t.basis === 'cited') ? 'IDs cited by the report are checked against ATT&CK v20.1. Techniques marked "named" are Threat Watch matching a technique name in the text, not the publisher\'s mapping.' : 'The report does not cite technique IDs. These are Threat Watch matching technique names in the text, not the publisher\'s mapping.'}>
          <ul className="rp-named">
            {techniques.map((t) => (
              <li key={t.id}><ExtLink href={techniqueUrl(t.id) ?? '#'}>{t.id}</ExtLink> <span>{t.name}</span><span className="rp-tag">{t.basis === 'cited' ? 'Cited' : 'Named'}</span><Pages pages={t.pages} /></li>))}
          </ul>
        </Section>
      )}
      {vendor.length > 0 && (
        <details className="card rp-sum rp-vendor-list">
          <summary><span className="rp-h">Product guidance from {publisher}</span> <span className="xsmall muted">({vendor.length} passage{vendor.length === 1 ? '' : 's'})</span></summary>
          <p className="xsmall muted">Advice that names the publisher's own products. Useful if you run them; otherwise read it for the underlying idea.</p>
          {vendor.map((v, i) => <p key={i} className="rp-item small">{v.text} <PageLink page={v.page} /></p>)}
        </details>
      )}
    </div>
  )
}
