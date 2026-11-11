import { useEffect, useState, type ReactNode } from 'react'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { IconBell, IconBolt, IconBookmark, IconBug, IconEye, IconGlobe, IconMoon, IconMore, IconSearch, IconSearchDoc, IconSettings, IconSun, IconTarget, IconToday } from './icons'

export const NAV = [
  { to: '/', label: 'Today', icon: IconToday, end: true },
  { to: '/breaking', label: 'Breaking', icon: IconBolt },
  { to: '/intel', label: 'Threat Intel', icon: IconTarget },
  { to: '/vulns', label: 'Vulnerabilities', icon: IconBug },
  { to: '/soc', label: 'SOC & DFIR', icon: IconSearchDoc },
  { to: '/apac', label: 'NZ & APAC', icon: IconGlobe },
  { to: '/watch', label: 'Threat Watch', icon: IconEye },
  { to: '/saved', label: 'Saved', icon: IconBookmark },
]

export function useTheme() {
  const [theme, setTheme] = useState<string>(() => { try { return localStorage.getItem('tw-theme') || 'system' } catch { return 'system' } })
  useEffect(() => {
    const root = document.documentElement
    if (theme === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', theme)
    try { localStorage.setItem('tw-theme', theme) } catch { /* storage unavailable */ }
    const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#0f1419' : '#f6f7f9')
  }, [theme])
  return [theme, setTheme] as const
}

export function Layout({ children }: { children: ReactNode }) {
  const [more, setMore] = useState(false)
  const [theme, setTheme] = useTheme()
  const [online, setOnline] = useState(navigator.onLine)
  const loc = useLocation()
  const nav = useNavigate()
  const me = useQuery({ queryKey: ['me'], queryFn: () => api.get<{ unread_notifications: number }>('/api/auth/me'), refetchInterval: 120_000 })
  const unread = me.data?.unread_notifications ?? 0

  useEffect(() => { setMore(false); window.scrollTo(0, 0) }, [loc.pathname])
  useEffect(() => {
    const on = () => setOnline(true), off = () => setOnline(false)
    window.addEventListener('online', on); window.addEventListener('offline', off)
    return () => { window.removeEventListener('online', on); window.removeEventListener('offline', off) }
  }, [])

  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches)
  const mobile = [NAV[0], NAV[1], NAV[3], NAV[6]]
  const moreActive = !mobile.some((n) => (n.end ? loc.pathname === n.to : loc.pathname.startsWith(n.to)))

  return (
    <div className="app">
      <nav className="sidebar" aria-label="Main">
        <Link to="/" className="brand"><img src="/pwa-192.png" alt="" />Threat Watch</Link>
        {NAV.map((n) => <NavLink key={n.to} to={n.to} end={n.end}><n.icon />{n.label}</NavLink>)}
        <div className="group">Tools</div>
        <NavLink to="/search"><IconSearch />Search</NavLink>
        <NavLink to="/notifications"><IconBell />Notifications {unread > 0 && <span className="badge">{unread}</span>}</NavLink>
        <NavLink to="/settings"><IconSettings />Settings & sources</NavLink>
      </nav>
      <div className="main">
        {!online && <div className="offline" role="status">Offline — showing cached content</div>}
        <header className="topbar">
          <Link to="/" className="brand mobile" aria-label="Threat Watch home"><img src="/pwa-192.png" alt="" /><span>Threat Watch</span></Link>
          <div className="spacer" />
          <form role="search" onSubmit={(e) => { e.preventDefault(); const q = new FormData(e.currentTarget).get('q'); if (q) nav(`/search?q=${encodeURIComponent(String(q))}`) }}>
            <label className="sr-only" htmlFor="topsearch">Search</label>
            <input id="topsearch" name="q" className="input" placeholder="Search CVE, actor, keyword…" style={{ minHeight: 36, width: 'min(44vw, 300px)' }} />
          </form>
          <Link to="/notifications" className="btn icon ghost" aria-label={`Notifications${unread ? `, ${unread} unread` : ''}`} style={{ position: 'relative' }}>
            <IconBell />{unread > 0 && <span className="badge" style={{ position: 'absolute', top: 2, right: 0 }}>{unread}</span>}
          </Link>
          <button className="btn icon ghost" aria-label="Toggle dark mode" onClick={() => setTheme(dark ? 'light' : 'dark')}>{dark ? <IconSun /> : <IconMoon />}</button>
        </header>
        <main className={`content ${loc.pathname === '/' ? 'wide' : ''}`} id="main">{children}</main>
      </div>
      <nav className="bottomnav" aria-label="Main">
        {mobile.map((n) => <NavLink key={n.to} to={n.to} end={n.end}><n.icon /><span>{n.label === 'Vulnerabilities' ? 'Vulns' : n.label === 'Threat Watch' ? 'Watch' : n.label}</span></NavLink>)}
        <button className={moreActive ? 'active' : ''} onClick={() => setMore(true)} aria-haspopup="dialog"><IconMore /><span>More</span>{unread > 0 && <span className="badge">{unread}</span>}</button>
      </nav>
      {more && (
        <div className="morenav" onClick={() => setMore(false)} role="presentation">
          <div className="sheet" role="dialog" aria-label="More sections" onClick={(e) => e.stopPropagation()}>
            {[NAV[2], NAV[4], NAV[5], NAV[7]].map((n) => <Link key={n.to} to={n.to}><n.icon width={20} />{n.label}</Link>)}
            <Link to="/search"><IconSearch width={20} />Search</Link>
            <Link to="/notifications"><IconBell width={20} />Notifications {unread > 0 && <span className="badge">{unread}</span>}</Link>
            <Link to="/settings"><IconSettings width={20} />Settings & sources</Link>
          </div>
        </div>
      )}
    </div>
  )
}
