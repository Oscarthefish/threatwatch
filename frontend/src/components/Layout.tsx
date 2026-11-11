import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { Sheet } from './Sheet'
import { ShortcutsSheet, useShortcuts } from './Shortcuts'
import { TourProvider, tourSeen, useTour } from './Tour'
import { timeAgo } from './ui'
import { IconBell, IconBolt, IconBookmark, IconBug, IconEye, IconCompass, IconGlobe, IconKeyboard, IconMoon, IconMore, IconSearch, IconSearchDoc, IconSettings, IconSun, IconTarget, IconToday } from './icons'

type NavItem = { to: string; label: string; short?: string; icon: (p: React.SVGProps<SVGSVGElement>) => React.ReactElement; end?: boolean }

export const INTEL: NavItem[] = [
  { to: '/', label: 'Today', icon: IconToday, end: true },
  { to: '/breaking', label: 'Breaking', icon: IconBolt },
  { to: '/intel', label: 'Threat intelligence', short: 'Intel', icon: IconTarget },
  { to: '/vulns', label: 'Vulnerabilities', short: 'Vulns', icon: IconBug },
  { to: '/soc', label: 'SOC & DFIR', icon: IconSearchDoc },
  { to: '/apac', label: 'NZ & APAC', icon: IconGlobe },
]
export const YOURS: NavItem[] = [
  { to: '/watch', label: 'Following', icon: IconEye },
  { to: '/saved', label: 'Saved', icon: IconBookmark },
]
const MOBILE = [INTEL[0], INTEL[1], INTEL[3], YOURS[0]]

export function useTheme() {
  const [theme, setTheme] = useState<string>(() => { try { return localStorage.getItem('tw-theme') || 'system' } catch { return 'system' } })
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', theme)
    try { localStorage.setItem('tw-theme', theme) } catch { /* storage unavailable */ }
    const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#0d0f12' : '#f5f6f8')
  }, [theme])
  return [theme, setTheme] as const
}

interface Status { last_ingest_at: string | null; worker_heartbeat: string | null; sources: { total: number; failing: string[] } }

/** Live collection health: the platform's heartbeat, always visible on desktop and in the More sheet on phones. */
function CollectionStatus() {
  const q = useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/api/status'), refetchInterval: 60_000 })
  if (!q.data) return null
  const d = q.data
  const workerOk = !!d.worker_heartbeat && Date.now() - new Date(d.worker_heartbeat).getTime() < 180_000
  const failing = d.sources.failing.length
  const state = !workerOk ? 'bad' : failing ? 'warn' : 'ok'
  return (
    <Link to="/settings" className={`status ${state}`} aria-label="Collection status, open sources">
      <span className="status-line"><i aria-hidden="true" />{workerOk ? 'Collecting' : 'Collector stopped'}</span>
      <span className="status-meta">
        {d.sources.total - failing}/{d.sources.total} sources · last run {timeAgo(d.last_ingest_at)}
      </span>
    </Link>
  )
}

function SearchForm({ inputRef, onDone, autoFocus }: { inputRef?: React.RefObject<HTMLInputElement | null>; onDone?: () => void; autoFocus?: boolean }) {
  const nav = useNavigate()
  return (
    <form role="search" className="searchbox" onSubmit={(e) => {
      e.preventDefault()
      const q = String(new FormData(e.currentTarget).get('q') ?? '').trim()
      if (q) { nav(`/search?q=${encodeURIComponent(q)}`); onDone?.() }
    }}>
      <IconSearch aria-hidden="true" />
      <label className="sr-only" htmlFor={autoFocus ? 'msearch' : 'topsearch'}>Search intelligence</label>
      <input ref={inputRef} id={autoFocus ? 'msearch' : 'topsearch'} name="q" type="search" autoComplete="off" enterKeyHint="search"
        placeholder="Search CVE, actor, product, keyword" autoFocus={autoFocus}
        onKeyDown={(e) => { if (e.key === 'Escape') { (e.target as HTMLInputElement).blur(); onDone?.() } }} />
      {!autoFocus && <kbd aria-hidden="true">/</kbd>}
    </form>
  )
}

export function Layout({ children }: { children: ReactNode }) {
  const [more, setMore] = useState(false)
  const [searching, setSearching] = useState(false)
  const [theme, setTheme] = useTheme()
  const [online, setOnline] = useState(navigator.onLine)
  const loc = useLocation()
  const searchRef = useRef<HTMLInputElement>(null)
  const me = useQuery({ queryKey: ['me'], queryFn: () => api.get<{ unread_notifications: number }>('/api/auth/me'), refetchInterval: 120_000 })
  const unread = me.data?.unread_notifications ?? 0
  const { help, setHelp } = useShortcuts()
  const tour = useTour()
  const startTour = tour.start
  // First sign-in on this device: offer the tour once.
  useEffect(() => { if (!tourSeen()) { const t = setTimeout(startTour, 900); return () => clearTimeout(t) } }, [startTour])

  useEffect(() => { setMore(false); setSearching(false); window.scrollTo(0, 0) }, [loc.pathname])
  useEffect(() => {
    const on = () => setOnline(true), off = () => setOnline(false)
    window.addEventListener('online', on); window.addEventListener('offline', off)
    return () => { window.removeEventListener('online', on); window.removeEventListener('offline', off) }
  }, [])
  // "/" focuses search from anywhere (except while typing in a field)
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const t = e.target as HTMLElement
      if (e.key !== '/' || e.metaKey || e.ctrlKey || t.closest('input, textarea, select, [contenteditable]') || document.querySelector('[role=dialog]')) return
      e.preventDefault()
      if (searchRef.current && searchRef.current.offsetParent !== null) searchRef.current.focus()
      else setSearching(true)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
  const moreActive = !MOBILE.some((n) => (n.end ? loc.pathname === n.to : loc.pathname.startsWith(n.to)))
  const bellLabel = `Notifications${unread ? `, ${unread} unread` : ''}`

  return (
    <TourProvider value={tour.start}>
    <div className="app">
      <a href="#main" className="skip">Skip to content</a>
      <nav className="sidebar" aria-label="Main">
        <Link to="/" className="brand" aria-label="Threat Watch, today">
          <img src="/pwa-192.png" alt="" />
          <span><b>Threat Watch</b><small>Personal intelligence</small></span>
        </Link>
        <div className="group" id="g-intel">Intelligence</div>
        <ul aria-labelledby="g-intel">{INTEL.map((n) => <li key={n.to}><NavLink to={n.to} end={n.end}><n.icon />{n.label}</NavLink></li>)}</ul>
        <div className="group" id="g-yours">Yours</div>
        <ul aria-labelledby="g-yours">
          {YOURS.map((n) => <li key={n.to}><NavLink to={n.to}><n.icon />{n.label}</NavLink></li>)}
          <li><NavLink to="/notifications"><IconBell />Notifications {unread > 0 && <span className="badge" aria-label={`${unread} unread`}>{unread}</span>}</NavLink></li>
        </ul>
        <div className="sidebar-foot">
          <button type="button" className="navbtn" onClick={tour.start}><IconCompass />Take the tour</button>
          <NavLink to="/settings"><IconSettings />Settings</NavLink>
          <CollectionStatus />
        </div>
      </nav>

      <div className="main">
        {!online && <div className="offline" role="status">Offline. Showing pages saved on this device.</div>}
        <header className={`topbar ${searching ? 'searching' : ''}`}>
          {searching ? (
            <>
              <SearchForm autoFocus onDone={() => setSearching(false)} />
              <button type="button" className="btn quiet" onClick={() => setSearching(false)}>Cancel</button>
            </>
          ) : (
            <>
              <Link to="/" className="brand mobile" aria-label="Threat Watch, today"><img src="/pwa-192.png" alt="" /><span>Threat Watch</span></Link>
              <div className="desktop-search"><SearchForm inputRef={searchRef} /></div>
              <div className="spacer" />
              <button type="button" className="btn icon quiet mobile-only" aria-label="Search" onClick={() => setSearching(true)}><IconSearch /></button>
              <button type="button" className="btn icon quiet desktop-only" aria-label="Keyboard shortcuts" title="Keyboard shortcuts (?)" onClick={() => setHelp(true)}><IconKeyboard /></button>
              <Link to="/notifications" className="btn icon quiet bell" aria-label={bellLabel}>
                <IconBell />{unread > 0 && <span className="badge" aria-hidden="true">{unread}</span>}
              </Link>
              <button type="button" className="btn icon quiet" aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'} onClick={() => setTheme(dark ? 'light' : 'dark')}>
                {dark ? <IconSun /> : <IconMoon />}
              </button>
            </>
          )}
        </header>
        <main className={`content ${loc.pathname === '/' ? 'wide' : /^\/(article|vuln|watch)\//.test(loc.pathname) ? 'doc-wide' : ''}`} id="main" tabIndex={-1}>{children}</main>
      </div>

      <nav className="bottomnav" aria-label="Main">
        {MOBILE.map((n) => <NavLink key={n.to} to={n.to} end={n.end}><n.icon /><span>{n.short ?? n.label}</span></NavLink>)}
        <button type="button" className={moreActive ? 'active' : ''} onClick={() => setMore(true)} aria-haspopup="dialog">
          <IconMore /><span>More</span>{unread > 0 && <span className="badge" aria-label={`${unread} unread notifications`}>{unread}</span>}
        </button>
      </nav>
      {help && <ShortcutsSheet onClose={() => setHelp(false)} onTour={() => { setHelp(false); setTimeout(tour.start, 50) }} />}
      {tour.node}
      {more && (
        <Sheet title="More" onClose={() => setMore(false)}>
          <nav className="navlist" aria-label="More sections">
            {[INTEL[2], INTEL[4], INTEL[5], YOURS[1]].map((n) => <Link key={n.to} to={n.to}><n.icon />{n.label}</Link>)}
            <Link to="/notifications"><IconBell />Notifications {unread > 0 && <span className="badge">{unread}</span>}</Link>
            <Link to="/settings"><IconSettings />Settings</Link>
            <button type="button" onClick={() => { setMore(false); setTimeout(tour.start, 50) }}><IconCompass />Take the tour</button>
          </nav>
          <div className="mt-3"><CollectionStatus /></div>
        </Sheet>
      )}
    </div>
    </TourProvider>
  )
}
