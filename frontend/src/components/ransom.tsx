import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ExtLink, TimeAgo } from './ui'
import type { Series } from './charts'
import { groupPath } from './trendsData'

/** Shapes and pieces shared by the Ransomware page and ransomware group profiles. */
export interface Claim {
  id: number; group_name: string; group_raw: string; victim: string; domain: string | null; country: string | null
  sector: string | null; attack_date: string | null; discovered_at: string; record_url: string
  news: { id: number; title: string; source: string }[]
}
export interface RGroup {
  name: string; cur: number; prev: number; share: number; weekly: number[]; tracker_url: string
  sectors: { name: string; n: number }[]; countries: { code: string; n: number }[]
}
export interface RMove extends RGroup { prev_share: number; change: number }
export interface RansomData {
  days: number; bucket_days: number; period_start: string; previous_start: string; coverage_start: string | null
  current_partial: boolean; comparison_indicative: boolean
  source: { enabled: boolean; last_success_at: string | null; status: string | null }
  totals: { current: number; previous: number; groups: number; unknown_sector: number; unknown_country: number }
  volume: { start: string; end: string; count: number; partial: boolean }[]
  weeks: { start: string; end: string }[]
  groups: RGroup[]; rising: RMove[]; falling: RMove[]
  sectors: { name: string; cur: number; prev: number }[]; countries: { code: string; cur: number; prev: number }[]
  regional: Claim[]; regional_days: number; recent: Claim[]
}
export interface GroupClaims {
  current: number; previous: number; tracker_url: string; first_seen: string; last_seen: string
  coverage_start: string | null; comparison_indicative: boolean
  weekly: { start: string; end: string; count: number; partial: boolean }[]
  sectors: { name: string; n: number }[]; countries: { code: string; n: number }[]; recent: Claim[]
}

export const CLAIMS: Series[] = [{ key: 'count', label: 'Leak-site claims', color: 'var(--viz-accent)' }]

let regionNames: Intl.DisplayNames | null = null
try { regionNames = new Intl.DisplayNames(['en-NZ'], { type: 'region' }) } catch { regionNames = null }
export const countryName = (code: string | null) => {
  if (!code) return 'Country not stated'
  try { return regionNames?.of(code) ?? code } catch { return code }
}

export function ClaimList({ claims, hideGroup, initial = 6 }: { claims: Claim[]; hideGroup?: boolean; initial?: number }) {
  const [all, setAll] = useState(false)
  const shown = all ? claims : claims.slice(0, initial)
  return (
    <>
    <ul className="claims">
      {shown.map((c) => (
        <li key={c.id}>
          <div className="row nowrap between top">
            <div className="grow">
              <span className="strong">{c.victim}</span>
              {c.domain && <span className="xsmall muted"> {c.domain}</span>}
            </div>
            <span className="xsmall muted nowrap">claimed <TimeAgo iso={c.discovered_at} /></span>
          </div>
          <div className="xsmall muted">
            {!hideGroup && <><Link to={groupPath('ransomware', c.group_name)}>{c.group_name}</Link> · </>}
            {c.sector ?? 'Sector not stated'} · {countryName(c.country)}
          </div>
          <div className="claim-links xsmall">
            {c.news.length > 0
              ? c.news.map((n) => <span key={n.id}>In the news: <Link to={`/article/${n.id}`}>{n.title}</Link> <span className="muted">({n.source})</span></span>)
              : <span className="muted">No collected reporting names this victim.</span>}
            <ExtLink href={c.record_url}>Tracker record<span className="sr-only"> for {c.victim}</span></ExtLink>
          </div>
        </li>
      ))}
    </ul>
    {claims.length > initial && (
      <button type="button" className="btn small mt-3" aria-expanded={all} onClick={() => setAll(!all)}>
        {all ? 'Show fewer' : `Show all ${claims.length}`}
      </button>
    )}
    </>
  )
}
