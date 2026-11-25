import { useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { BackLink, ErrorBox, Loading, PageHeader } from '../components/ui'
import { lsPath, type ProfileResponse } from '../landscape'
import { Overview } from '../components/landscape/Overview'
import { Threats } from '../components/landscape/Threats'
import { AttackTab } from '../components/landscape/Attack'
import { Defend } from '../components/landscape/Defend'
import { Respond } from '../components/landscape/Respond'
import { Interview } from '../components/landscape/Interview'
import { History } from '../components/landscape/History'

const TABS = [
  ['overview', 'Overview'], ['threats', 'Threats'], ['attack', 'ATT&CK'], ['defend', 'Monitor, hunt, harden'],
  ['respond', 'Readiness and response'], ['interview', 'Interview prep'], ['history', 'History'],
] as const
type Tab = typeof TABS[number][0]

export function useProfile(id: string | number) {
  return useQuery({ queryKey: ['landscape', String(id)], queryFn: () => api.get<ProfileResponse>(lsPath(id)) })
}

export default function Landscape() {
  const { id = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = (TABS.find(([k]) => k === params.get('tab'))?.[0] ?? 'overview') as Tab
  const q = useProfile(id)
  const go = (t: Tab) => setParams((p) => { const n = new URLSearchParams(p); n.set('tab', t); n.delete('sub'); return n }, { replace: true })

  if (q.isLoading) return <Loading />
  if (q.error || !q.data) return <><BackLink fallback="/landscapes" label="Threat landscapes" /><ErrorBox error={q.error} onRetry={() => q.refetch()} /></>
  const { profile, assessment } = q.data
  const needs = !assessment && tab !== 'overview' && tab !== 'history' && tab !== 'respond' && tab !== 'interview'
  return (
    <>
      <BackLink fallback="/landscapes" label="Threat landscapes" />
      <PageHeader title={profile.name} eyebrow={['Threat landscape', profile.kind === 'organisation' ? 'Organisation' : 'Industry', profile.sector_label, profile.countries.join(', ')]} />
      <div className="tabs" role="tablist" aria-label="Profile sections">
        {TABS.map(([k, label]) => (
          <button key={k} type="button" role="tab" id={`tab-${k}`} aria-selected={tab === k} aria-controls="ls-panel" tabIndex={tab === k ? 0 : -1}
            onClick={() => go(k)}
            onKeyDown={(e) => {
              const i = TABS.findIndex(([x]) => x === tab)
              const n = e.key === 'ArrowRight' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' ? (i - 1 + TABS.length) % TABS.length : -1
              if (n >= 0) { e.preventDefault(); go(TABS[n][0]); document.getElementById(`tab-${TABS[n][0]}`)?.focus() }
            }}>{label}</button>
        ))}
      </div>
      <div id="ls-panel" role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {needs ? (
          <div className="notice">Run an assessment on the Overview tab first. <button type="button" className="btn small" onClick={() => go('overview')}>Go to Overview</button></div>
        ) : tab === 'overview' ? <Overview data={q.data} onTab={go} />
          : tab === 'threats' ? <Threats data={q.data} />
            : tab === 'attack' ? <AttackTab data={q.data} />
              : tab === 'defend' ? <Defend data={q.data} />
                : tab === 'respond' ? <Respond data={q.data} />
                  : tab === 'interview' ? <Interview data={q.data} />
                    : <History data={q.data} />}
      </div>
    </>
  )
}
