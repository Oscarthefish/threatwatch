import { useCallback, useEffect, useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api, ApiError, setUnauthorizedHandler } from './api'
import { Layout, useTheme } from './components/Layout'
import { Loading, usePageTitle } from './components/ui'
import { Link } from 'react-router-dom'
import Login from './pages/Login'
import { Unreachable } from './components/Unreachable'
import Today from './pages/Today'
import Breaking from './pages/Breaking'
import Section from './pages/Section'
import Vulns from './pages/Vulns'
import VulnDetail from './pages/VulnDetail'
import ArticlePage from './pages/Article'
import Watches from './pages/Watches'
import WatchPage from './pages/WatchDetail'
import Saved from './pages/Saved'
import Search from './pages/Search'
import Notifications from './pages/Notifications'
import Settings from './pages/Settings'
import Trends from './pages/Trends'
import Ransomware from './pages/Ransomware'
import GroupPage from './pages/Group'
import Glossary from './pages/Glossary'
import Landscapes from './pages/Landscapes'
import Landscape from './pages/Landscape'
import Reports from './pages/Reports'
import Report from './pages/Report'
import ReportSources from './pages/ReportSources'

type AuthState = 'checking' | 'in' | 'out' | 'unreachable'

export default function App() {
  useTheme()
  const [auth, setAuth] = useState<AuthState>('checking')
  const qc = useQueryClient()

  const check = useCallback(() => {
    api.get('/api/auth/me').then(() => setAuth('in')).catch((e) => {
      // Only the server saying "not signed in" shows the sign-in form. A failed connection (Tailscale off, server
      // restarting) keeps the session: offline, the service-worker cache serves content; online, we say so and retry.
      if (e instanceof ApiError && e.status === 401) setAuth('out')
      else if (!(e instanceof ApiError) && !navigator.onLine) setAuth('in')
      else setAuth('unreachable')
    })
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => { setAuth('out'); qc.clear() })
    check()
  }, [qc, check])

  if (auth === 'checking') return <div className="login"><div style={{ width: 280 }}><Loading lines={3} /></div></div>
  if (auth === 'unreachable') return <Unreachable onRetry={check} />
  if (auth === 'out') return <Login onLogin={() => { qc.clear(); setAuth('in') }} />

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Today />} />
        <Route path="/breaking" element={<Breaking />} />
        <Route path="/intel" element={<Section section="threat-intel" title="Threat Intelligence"
          sub="Ransomware, malware, threat actors, phishing and ATT&CK-mapped activity"
          tags={[['ransomware', 'Ransomware'], ['malware', 'Malware'], ['threat-actor', 'Threat actors'], ['phishing', 'Phishing & credential theft'], ['ttp', 'TTPs / ATT&CK']]} />} />
        <Route path="/soc" element={<Section section="soc-dfir" title="SOC & DFIR"
          sub="Incident investigations, detection engineering, hunting, Sigma & Splunk content"
          tags={[['detection', 'Detection & hunting'], ['incident', 'Incidents'], ['malware', 'Malware analysis']]} />} />
        <Route path="/apac" element={<Section section="nz-apac" title="New Zealand & APAC"
          sub="NCSC NZ advisories, Australian and regional developments"
          regions={[['NZ', 'New Zealand'], ['AU', 'Australia'], ['APAC', 'Wider APAC']]} />} />
        <Route path="/latest" element={<Section title="Latest" sub="Everything collected, newest first or by importance"
          tags={[['exploited', 'Exploited'], ['incident', 'Incidents'], ['vulnerability', 'Vulnerabilities'], ['ransomware', 'Ransomware'], ['detection', 'Detection & hunting']]} />} />
        <Route path="/vulns" element={<Vulns />} />
        <Route path="/trends" element={<Trends />} />
        <Route path="/ransomware" element={<Ransomware />} />
        <Route path="/landscapes" element={<Landscapes />} />
        <Route path="/landscapes/:id" element={<Landscape />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/reports/series" element={<ReportSources />} />
        <Route path="/reports/:id" element={<Report />} />
        <Route path="/glossary" element={<Glossary />} />
        <Route path="/group/:kind/:name" element={<GroupPage />} />
        <Route path="/vuln/:cve" element={<VulnDetail />} />
        <Route path="/article/:id" element={<ArticlePage />} />
        <Route path="/watch" element={<Watches />} />
        <Route path="/watch/:id" element={<WatchPage />} />
        <Route path="/saved" element={<Saved />} />
        <Route path="/search" element={<Search />} />
        <Route path="/notifications" element={<Notifications />} />
        <Route path="/settings" element={<Settings onLogout={() => setAuth('out')} />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Layout>
  )
}

function NotFound() {
  usePageTitle('Page not found')
  return (
    <div className="empty">
      <h1>Page not found</h1>
      <p>This address does not match any page. The item may have been removed by the retention policy.</p>
      <Link className="btn primary" to="/">Go to Today</Link>
    </div>
  )
}
