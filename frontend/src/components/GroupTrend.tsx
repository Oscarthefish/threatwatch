import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api, ApiError } from '../api'
import type { ArticleBrief, AttackEntry } from '../types'
import { ColumnChart, DataTable, type Column } from './charts'
import { groupPath, isGroupKind, longDay, SEV } from './trendsData'
import { Loading } from './ui'
import type { GroupClaims } from './ransom'

export interface GroupProfile {
  kind: 'actor' | 'ransomware' | 'malware'; name: string; aliases: string[]; known: boolean; days: number
  period_start: string; coverage_start: string; current_partial: boolean; comparison_indicative: boolean
  stories: number; previous: number; all_time: number; roundups: number; share: number; previous_share: number | null
  first_seen: string | null; last_seen: string | null; sources: string[]
  weekly: { start: string; end: string; critical: number; high: number; other: number; partial: boolean }[]
  related: Record<string, { type: string; value: string; stories: number; name: string | null; url?: string | null }[]>
  articles: ArticleBrief[]; watch: { id: number; title: string } | null
  attack: AttackEntry | null; attack_synced_at: string | null
  claims: GroupClaims | null
}

export { groupPath, isGroupKind }

export function useGroup(kind: string, name: string, days: number, enabled = true) {
  return useQuery({
    queryKey: ['group', kind, name.toLowerCase(), days],
    queryFn: () => api.get<GroupProfile>(`/api/groups/${kind}/${encodeURIComponent(name)}?days=${days}`),
    enabled: enabled && !!name, placeholderData: (p) => p, retry: (n, e) => !(e instanceof ApiError && e.status === 404) && n < 2,
  })
}

/** Weekly reporting chart for one group, with a range toggle, coverage note and table view. */
export function GroupTrendChart({ g, days, onDays, compact }: { g: GroupProfile; days: number; onDays: (d: number) => void; compact?: boolean }) {
  const cols: Column[] = g.weekly.map((w) => ({
    label: new Date(`${w.start}T00:00:00`).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short' }),
    title: `Week of ${longDay(w.start)}`, partial: w.partial, values: { critical: w.critical, high: w.high, other: w.other },
  }))
  return (
    <section className="panel" aria-labelledby={`gt-${g.name}`}>
      <header>
        <h2 id={`gt-${g.name}`}>Reporting over time</h2>
        <div className="seg" role="group" aria-label="Time range">
          {[90, 180, 365].map((d) => <button key={d} type="button" aria-pressed={days === d} onClick={() => onDays(d)}>{d === 365 ? '1 year' : `${d} days`}</button>)}
        </div>
      </header>
      <div className="body">
        <p className="xsmall muted">
          Stories naming {g.name} per week, by severity. {g.stories} in the last {g.days} days{g.previous_share != null ? `, ${g.share}% of all stories (${g.previous_share}% in the period before)` : ''}.
          {g.roundups > 0 && ` ${g.roundups} roundup mention${g.roundups === 1 ? ' is' : 's are'} not counted.`}
        </p>
        {g.weekly.every((w) => !w.critical && !w.high && !w.other)
          ? <p className="small muted mb-0">No stories named {g.name} in this period{g.all_time ? '' : ' yet'}. Try a longer range{g.all_time ? '' : ', or check back as collection continues'}.</p>
          : <ColumnChart columns={cols} series={SEV} label={`Stories naming ${g.name} per week by severity`} height={compact ? 140 : 190} partialNote="Before collection: incomplete" />}
        {g.current_partial && (
          <p className="xsmall faint mt-2 mb-0">Shaded weeks are before collection began ({longDay(g.coverage_start)}); feeds only keep their newest items, so they are incomplete.</p>
        )}
        <DataTable caption={`Stories naming ${g.name} per week`} head={['Week', 'Critical', 'High', 'Medium and below', 'Complete']}
          rows={g.weekly.map((w, i) => [cols[i].title, w.critical, w.high, w.other, w.partial ? 'No' : 'Yes'])} />
      </div>
    </section>
  )
}

/** For followed actors and malware: the group's chart, if the watch names a known group. */
export function WatchGroupTrend({ kind, names }: { kind: string; names: string[] }) {
  const [days, setDays] = useState(90)
  const gkind = kind === 'malware' ? 'malware' : 'actor'
  const first = useGroup(gkind, names[0] ?? '', days, kind === 'actor' || kind === 'malware')
  // actors may be ransomware groups: try that dictionary when the actor lookup finds nothing
  const alt = useGroup('ransomware', names[0] ?? '', days, kind === 'actor' && first.isError)
  const q = first.isError ? alt : first
  if (!(kind === 'actor' || kind === 'malware') || !names.length || q.isError) return null
  if (!q.data) return <Loading lines={3} />
  return (
    <div>
      <GroupTrendChart g={q.data} days={days} onDays={setDays} compact />
      <p className="xsmall mt-2 mb-0"><Link to={groupPath(q.data.kind, q.data.name)}>Open the {q.data.name} profile</Link></p>
    </div>
  )
}
