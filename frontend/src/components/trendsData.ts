import type { Series } from './charts'

/** Shapes and helpers shared by the Trends page and the Today trends panel. */
export interface Ent { type: string; name: string; query: string | null; tag: string | null; cur: number; prev: number; share: number; weekly: number[] }
export interface Move extends Ent { prev_share: number; change: number }
export interface TrendData {
  days: number; bucket_days: number; period_start: string; previous_start: string; coverage_start: string
  current_partial: boolean; comparison_indicative: boolean
  totals: { current: Record<string, number>; previous: Record<string, number> }
  volume: { start: string; end: string; critical: number; high: number; other: number; partial: boolean }[]
  weeks: { start: string; end: string }[]
  groups: Ent[]; malware: Ent[]; vendors: Ent[]; topics: Ent[]; rising: Move[]; falling: Move[]
  kev: { weekly: { start: string; count: number }[]; current: number; previous: number; ransomware: number; vendors: { name: string; cur: number; prev: number }[] }
}

export const TYPE: Record<string, string> = { actor: 'Threat actor', ransomware: 'Ransomware', malware: 'Malware', vendor: 'Vendor', topic: 'Topic' }
export const SEV: Series[] = [
  { key: 'other', label: 'Medium and below', color: 'var(--viz-other)' },
  { key: 'high', label: 'High', color: 'var(--viz-high)' },
  { key: 'critical', label: 'Critical', color: 'var(--viz-crit)' },
]
export const KEV: Series[] = [{ key: 'count', label: 'KEV additions', color: 'var(--viz-accent)' }]

export const day = (iso: string) => new Date(`${iso}T00:00:00`).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short' })
export const longDay = (iso: string) => new Date(`${iso}T00:00:00`).toLocaleDateString('en-NZ', { day: 'numeric', month: 'short', year: 'numeric' })
export const pct = (n: number, d: number) => (d ? Math.round((100 * n) / d) : 0)
export const href = (e: Ent) => (e.tag ? `/latest?tag=${encodeURIComponent(e.tag)}` : `/search?q=${encodeURIComponent(e.query ?? e.name)}`)

