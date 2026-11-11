import { useEffect, useMemo, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { ExtLink, Highlight, PageHeader, queryTerms, usePageTitle } from '../components/ui'
import { GROUPS, TERMS } from '../components/glossary'

const byId = Object.fromEntries(TERMS.map((t) => [t.id, t]))

export default function Glossary() {
  usePageTitle('Glossary')
  const loc = useLocation()
  const [q, setQ] = useState('')
  const words = queryTerms(q)
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return TERMS
    return TERMS.filter((t) => [t.term, t.full, t.body, t.inApp].some((x) => x?.toLowerCase().includes(needle)))
  }, [q])

  // Arriving at /glossary#kev: bring that entry into view and let :target highlight it
  useEffect(() => {
    const id = decodeURIComponent(loc.hash.slice(1))
    if (!id) return
    const t = setTimeout(() => {
      const el = document.getElementById(id)
      if (el) { el.scrollIntoView({ block: 'start' }); el.focus({ preventScroll: true }) }
    }, 30)
    return () => clearTimeout(t)
  }, [loc.hash])

  return (
    <>
      <PageHeader title="Glossary" eyebrow={['Help', `${TERMS.length} terms`]}
        sub="Plain explanations of the scores, catalogues and labels used across Threat Watch, and what each one means in this app." />
      <div className="filters glossary-filters">
        <label className="sr-only" htmlFor="gq">Filter terms</label>
        <input id="gq" type="search" className="input" placeholder="Filter, for example KEV or severity" value={q} onChange={(e) => setQ(e.target.value)} />
        {!q && (
          <nav aria-label="Glossary sections" className="chips">
            {GROUPS.map(([g, label]) => <a key={g} className="chip link-chip" href={`#g-${g}`}>{label}</a>)}
          </nav>
        )}
      </div>
      {shown.length === 0 && <p className="muted">No term matches “{q}”. Try a shorter word.</p>}
      {GROUPS.map(([g, label, sub]) => {
        const items = shown.filter((t) => t.group === g)
        if (!items.length) return null
        return (
          <section key={g} className="gloss-group" aria-labelledby={`g-${g}`}>
            <h2 id={`g-${g}`} tabIndex={-1}>{label}</h2>
            <p className="small muted">{sub}</p>
            <dl className="gloss">
              {items.map((t) => (
                <div key={t.id} id={t.id} className="gloss-item" tabIndex={-1}>
                  <dt>
                    <span className="gloss-term"><Highlight text={t.term} terms={words} /></span>
                    {t.full && <span className="gloss-full"><Highlight text={t.full} terms={words} /></span>}
                    <a className="gloss-anchor" href={`#${t.id}`} aria-label={`Link to ${t.term}`}>#</a>
                  </dt>
                  <dd>
                    <p><Highlight text={t.body} terms={words} /></p>
                    {t.inApp && <p className="gloss-app"><strong>In Threat Watch: </strong><Highlight text={t.inApp} terms={words} /></p>}
                    {(t.see?.length || t.link) && (
                      <p className="gloss-see xsmall">
                        {t.see?.length ? <>See also {t.see.filter((id) => byId[id]).map((id, i) => (
                          <span key={id}>{i > 0 && ', '}<Link to={`/glossary#${id}`} onClick={() => setQ('')}>{byId[id].term}</Link></span>
                        ))}</> : null}
                        {t.see?.length && t.link ? ' · ' : ''}
                        {t.link && <>Official source: <ExtLink href={t.link.url}>{t.link.label}</ExtLink></>}
                      </p>
                    )}
                  </dd>
                </div>
              ))}
            </dl>
          </section>
        )
      })}
    </>
  )
}
