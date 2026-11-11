import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

/**
 * Guided tour: walks through each section, highlighting the part being explained.
 * Each step names a route (or derives one from the page, e.g. "the first article")
 * and an ordered list of target selectors; if no target is visible the card is
 * shown centred, so a missing element never blocks the tour.
 */
type Step = {
  section: string
  title: string
  body: ReactNode
  route?: string | (() => string | null)
  target?: string[]
}

/** The article being toured: the current one if already on an article, else the first story in the list on screen. */
const firstArticle = () => location.pathname.startsWith('/article/') ? location.pathname
  : document.querySelector('main .acard .title')?.getAttribute('href') ?? null

export const STEPS: Step[] = [
  { section: 'Welcome', route: '/', title: 'Welcome to Threat Watch',
    body: <>Threat Watch collects security reporting from public sources every 30 minutes, rates each story with stated reasons, and keeps a record of anything you follow. This tour takes about three minutes. Use the buttons or the arrow keys; Esc leaves at any time. You can restart it from Settings.</> },
  { section: 'Today', route: '/', target: ['.tiles'], title: 'The day at a glance',
    body: <>Each number links to the list behind it: new reporting since your last visit, critical and high stories in the last 24 hours, new CISA KEV entries, followed items with news, and how many sources are collecting.</> },
  { section: 'Today', route: '/', target: ['section[aria-labelledby="brief-h"]'], title: 'Daily briefing',
    body: <>Built every morning at 7:00 NZ time from the highest-ranked reporting. Each item names its sources. Select a headline to expand why it matters and what to do about it.</> },
  { section: 'Today', route: '/', target: ['main .bitem .acts', 'main .acts'], title: 'Next steps for the SOC',
    body: <>Tags such as <strong>Patch now</strong>, <strong>Check exposure</strong> or <strong>Hunt for indicators</strong> are derived from the evidence in the report. An orange marker means urgent. The article page explains each step and where it came from.</> },
  { section: 'Today', route: '/', target: ['#since'], title: 'Since your last visit',
    body: <>Everything collected since you last opened Threat Watch. The list stays fixed while you read; <strong>Mark all seen</strong> resets it, and <strong>High+</strong> hides low and medium stories.</> },
  { section: 'Today', route: '/', target: ['section[aria-labelledby="kev-h"]'], title: 'New in CISA KEV',
    body: <>The Known Exploited Vulnerabilities catalogue lists CVEs that CISA has confirmed are exploited in the wild. These are usually the first to patch. The Following panel above it shows news on items you track.</> },
  { section: 'Breaking', route: '/breaking', target: ['main .page-head'], title: 'Breaking',
    body: <>Significant incidents and actively exploited vulnerabilities from the last 72 hours. Important changes to things you follow are pinned to the top.</> },
  { section: 'Topic feeds', route: '/intel', target: ['main .filters'], title: 'Topic feeds and filters',
    body: <>Threat intelligence, SOC & DFIR and NZ & APAC share this layout. Narrow by topic, severity and date, or change the sort. Filters are kept in the address, so a filtered view can be bookmarked in your browser.</> },
  { section: 'Topic feeds', route: '/intel', target: ['main .acard .sev'], title: 'Severity, with reasons',
    body: <>Ratings come from rules, not guesswork: a KEV listing, reported exploitation, an official advisory, the scale of impact. Select the label on any story to see the reasons behind its rating.</> },
  { section: 'Topic feeds', route: '/intel', target: ['main .acard-actions'], title: 'Bookmark or open the source',
    body: <>The bookmark keeps a story in Saved, where you can add a private note. The arrow opens the original on the publisher's site. Select the headline to open the full briefing.</> },
  { section: 'Article', route: firstArticle, target: ['main .doc-actions'], title: 'An article',
    body: <>Each story opens as a briefing: what happened, why it got its rating, what to do, and the source text. From here you can read the original, bookmark it, or follow the subject.</> },
  { section: 'Article', route: firstArticle, target: ['section[aria-labelledby="todo-h"]', 'main .doc-aside'], title: 'What to do',
    body: <>Every step states its basis. Steps marked <strong>CISA KEV</strong> or <strong>CVE record</strong> come straight from those sources. <strong>Playbook</strong> steps are standard practice for this kind of threat, not claims about the incident.</> },
  { section: 'Article', route: firstArticle, target: ['main [data-key="f"]'], title: 'Bookmark or follow?',
    body: <><strong>Bookmark</strong> saves this one article. <strong>Follow</strong> tracks the subject itself (an incident, CVE, actor or topic): new reporting is matched to it automatically, its record is versioned, and you are told about important changes.</> },
  { section: 'Vulnerabilities', route: '/vulns', target: ['main .vlist .vrow'], title: 'Vulnerabilities',
    body: <>Every tracked CVE, product first. <strong>EPSS</strong> is FIRST's estimated probability of exploitation in the next 30 days. <strong>CVSS</strong> is the severity score from the CVE record. <strong>Exploited (KEV)</strong> marks confirmed exploitation.</> },
  { section: 'Following', route: '/watch', target: ['main .page-head'], title: 'Following',
    body: <>Everything you follow, with counts of new reporting. Reports that only partly match wait for your review, so nothing is linked on a guess. Each item has an overview, a timeline, its linked reports and its own settings.</> },
  { section: 'Saved', route: '/saved', target: ['main .page-head'], title: 'Saved',
    body: <>Your bookmarks with their notes and tags, plus a history of what you have read.</> },
  { section: 'Notifications', target: ['.topbar .bell'], title: 'Notifications',
    body: <>The daily briefing and changes to what you follow arrive here. Each followed item has its own setting: important changes, every new finding, a daily digest at 7:05, or none.</> },
  { section: 'Search', target: ['.topbar .desktop-search', '.topbar button[aria-label="Search"]'], title: 'Search',
    body: <>Searches every collected article, tracked CVE and followed item. Press <kbd className="key">/</kbd> from anywhere to jump here.</> },
  { section: 'Settings', route: '/settings', target: ['section[aria-labelledby="col-h"]', 'main .page-head'], title: 'Settings',
    body: <>Collection health and the run schedule, every source with an on/off switch, AI summaries, push notifications for this device, and data retention. This tour can be restarted here.</> },
  { section: 'Done', title: 'That is everything',
    body: <>Press <kbd className="key">?</kbd> at any time for keyboard shortcuts: <kbd className="key">j</kbd> and <kbd className="key">k</kbd> move through lists, <kbd className="key">o</kbd> opens, <kbd className="key">b</kbd> bookmarks. A good first step is to follow a CVE or product you care about.</> },
]

const SEEN = 'tw-tour-seen'
export const tourSeen = () => { try { return !!localStorage.getItem(SEEN) } catch { return true } }
const markSeen = () => { try { localStorage.setItem(SEEN, new Date().toISOString()) } catch { /* unavailable */ } }

const TourCtx = createContext<() => void>(() => {})
export const useStartTour = () => useContext(TourCtx)
export const TourProvider = TourCtx.Provider

function visible(selectors?: string[]): HTMLElement | null {
  for (const s of selectors ?? []) {
    for (const el of document.querySelectorAll<HTMLElement>(s)) if (el.offsetParent !== null || getComputedStyle(el).position === 'fixed') return el
  }
  return null
}

/** Owns tour state; returns `start` and the overlay node to render. */
export function useTour() {
  const [index, setIndex] = useState<number | null>(null)
  const routes = useRef<Record<number, string | null>>({})

  const resolve = (n: number) => {
    if (!(n in routes.current)) {
      const r = STEPS[n].route
      routes.current[n] = typeof r === 'function' ? r() : r ?? null
    }
    return routes.current[n]
  }
  const go = useCallback((n: number, dir: 1 | -1) => {
    while (n >= 0 && n < STEPS.length) {
      // a step whose route cannot be derived (no articles yet) is skipped
      if (typeof STEPS[n].route === 'function' && !resolve(n)) { n += dir; continue }
      resolve(n); setIndex(n); return
    }
    if (n >= STEPS.length) { markSeen(); setIndex(null) }
  }, [])
  const start = useCallback(() => { routes.current = {}; go(0, 1) }, [go])
  const close = useCallback(() => { markSeen(); setIndex(null) }, [])

  const node = index === null ? null
    : <TourOverlay index={index} route={routes.current[index] ?? null} onNext={() => go(index + 1, 1)} onBack={() => go(index - 1, -1)} onClose={close} />
  return { start, node, active: index !== null }
}

function TourOverlay({ index, route, onNext, onBack, onClose }: { index: number; route: string | null; onNext: () => void; onBack: () => void; onClose: () => void }) {
  const step = STEPS[index]
  const nav = useNavigate()
  const loc = useLocation()
  const [rect, setRect] = useState<DOMRect | null>(null)
  const [ready, setReady] = useState(false)
  const target = useRef<HTMLElement | null>(null)
  const card = useRef<HTMLDivElement>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const opener = useRef<HTMLElement | null>(document.activeElement as HTMLElement | null)
  const [cardH, setCardH] = useState(260)
  const last = index === STEPS.length - 1

  // Move to the step's page, wait for its target to render, bring it into view.
  useEffect(() => {
    let cancelled = false
    setReady(false); setRect(null); target.current = null
    if (route && loc.pathname !== route) { nav(route); return }
    let tries = 0
    const find = () => {
      if (cancelled) return
      const el = visible(step.target)
      if (step.target && !el && tries++ < 40) { setTimeout(find, 100); return }
      target.current = el
      if (el) {
        const r = el.getBoundingClientRect()
        if (getComputedStyle(el).position !== 'fixed' && !el.closest('.topbar')) {
          const tall = r.height > innerHeight * 0.55
          const top = scrollY + r.top - (tall ? 84 : Math.max(84, (innerHeight - r.height) / 2 - 80))
          window.scrollTo({ top: Math.max(0, top), behavior: 'auto' })
        }
        requestAnimationFrame(() => { if (!cancelled) { setRect(el.getBoundingClientRect()); setReady(true) } })
      } else setReady(true)
    }
    const t = setTimeout(find, 60)
    return () => { cancelled = true; clearTimeout(t) }
  }, [index, route, loc.pathname]) // eslint-disable-line react-hooks/exhaustive-deps

  // Keep the highlight attached while the page scrolls or resizes.
  useEffect(() => {
    const update = () => { if (target.current) setRect(target.current.getBoundingClientRect()) }
    addEventListener('scroll', update, { passive: true }); addEventListener('resize', update)
    return () => { removeEventListener('scroll', update); removeEventListener('resize', update) }
  }, [])

  useLayoutEffect(() => { if (card.current) setCardH(card.current.offsetHeight) }, [index, ready])
  useEffect(() => { if (ready) heading.current?.focus() }, [ready, index])
  useEffect(() => () => { opener.current?.focus?.() }, [])

  // Keyboard: arrows step, Esc leaves, Tab stays inside the card.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); onClose(); return }
      if (e.key === 'ArrowRight') { e.preventDefault(); onNext(); return }
      if (e.key === 'ArrowLeft' && index > 0) { e.preventDefault(); onBack(); return }
      if (e.key === 'Tab' && card.current) {
        const items = [...card.current.querySelectorAll<HTMLElement>('button')]
        if (!items.length) return
        const [a, b] = [items[0], items[items.length - 1]]
        const inside = card.current.contains(document.activeElement)
        if (!inside) { e.preventDefault(); a.focus() }
        else if (e.shiftKey && document.activeElement === a) { e.preventDefault(); b.focus() }
        else if (!e.shiftKey && document.activeElement === b) { e.preventDefault(); a.focus() }
      }
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [index, onNext, onBack, onClose])

  // Card placement: beside the target when there is room, otherwise docked.
  const pad = 8, gap = 14, margin = 16
  const W = Math.min(380, innerWidth - 2 * margin)
  let pos: React.CSSProperties
  if (!rect) pos = { left: '50%', top: '50%', transform: 'translate(-50%, -50%)', width: W }
  else if (innerWidth < 640) pos = { left: margin, right: margin, bottom: margin }
  else {
    const left = Math.min(Math.max(rect.left, margin), innerWidth - W - margin)
    const below = innerHeight - rect.bottom - pad
    if (below >= cardH + gap + margin) pos = { left, top: rect.bottom + pad + gap, width: W }
    else if (rect.top - pad >= cardH + gap + margin + 60) pos = { left, top: rect.top - pad - gap - cardH, width: W }
    else pos = { right: 24, bottom: 24, width: W }
  }

  return (
    <div className="tour" aria-hidden={false}>
      <div className={`tour-block ${rect ? '' : 'dim'}`} onClick={(e) => e.stopPropagation()} />
      {rect && <div className="tour-spot" aria-hidden="true" style={{ left: rect.left - pad, top: rect.top - pad, width: rect.width + 2 * pad, height: rect.height + 2 * pad }} />}
      <div ref={card} className="tour-card" role="dialog" aria-modal="true" aria-labelledby="tour-h" aria-describedby="tour-b" style={{ ...pos, visibility: ready ? 'visible' : 'hidden' }}>
        <div className="row between nowrap">
          <span className="eyebrow mb-0">{step.section}</span>
          <span className="xsmall muted" aria-label={`Step ${index + 1} of ${STEPS.length}`}>{index + 1} / {STEPS.length}</span>
        </div>
        <div className="tour-progress" aria-hidden="true"><i style={{ width: `${((index + 1) / STEPS.length) * 100}%` }} /></div>
        <h2 id="tour-h" ref={heading} tabIndex={-1}>{step.title}</h2>
        <p id="tour-b">{step.body}</p>
        <div className="row between nowrap">
          <button type="button" className="btn quiet small" onClick={onClose}>{last ? 'Close' : index === 0 ? 'Not now' : 'End tour'}</button>
          <div className="row nowrap">
            {index > 0 && <button type="button" className="btn small" onClick={onBack}>Back</button>}
            <button type="button" className="btn primary small" onClick={last ? onClose : onNext}>{last ? 'Finish' : index === 0 ? 'Start the tour' : 'Next'}</button>
          </div>
        </div>
      </div>
    </div>
  )
}
