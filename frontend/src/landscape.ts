// Types and labels for Threat Landscapes (mirrors backend/app/api/landscapes.py).

export type Provenance = 'user' | 'public' | 'inferred' | 'unknown'
export interface Fact {
  id: number; category: string; subtype: string; value: string; status: string; provenance: Provenance
  source_url: string | null; source_title: string | null; verified_at: string | null; note: string; updated_at: string
}
export interface Profile {
  id: number; kind: 'organisation' | 'industry'; name: string; sector: string | null; sector_label?: string | null; countries: string[]
  size: string | null; description: string; domain: string | null; match_terms: string[]; notes: string
  options: { lookback_days: number; use_claims: boolean; excluded_sources: string[]; platforms: string[] }
  facts: Fact[]; created_at: string; updated_at: string
}
export interface Factor { factor: string; detail: string; points: number; basis: string }
export interface Evidence {
  article_id: number; title: string; url: string; source: string; authority: number; published_at: string | null; retrieved_at: string
  severity: number; matched: string[]
}
export interface FindingTechnique { id: string; name: string | null; basis: Basis[]; notes: string[]; groups?: string[]; articles?: number[] }
export type Basis = 'reported' | 'group' | 'keyword' | 'guidance'
export type Classification = 'observed' | 'emerging' | 'plausible' | 'historical'
export interface Vuln {
  cve_id: string; vendor: string; product: string; name: string; date_added: string; due: string | null; ransomware: boolean
  cvss: number | null; epss: number | null; epss_percentile: number | null; match: string; action: string | null
}
export interface ClaimsSummary {
  sector: string; count: number; previous: number; previous_complete: boolean; recent_30d: number
  top_groups: { group: string; claims: number }[]; in_countries: number; countries: string[]; local_groups: { group: string; claims: number }[]; latest: string | null
}
export interface Finding {
  key: string; title: string; category: string; threat: string | null; classification: Classification; summary: string
  priority: { code: 'P1' | 'P2' | 'P3' | 'P4'; label: string; points: number }; factors: Factor[]; evidence: Evidence[]
  confidence: { level: 'high' | 'medium' | 'low' | 'none'; why: string }; unknowns: string[]; techniques: FindingTechnique[]
  vulnerabilities?: Vuln[]; claims?: ClaimsSummary | { group: string; victim: string; country: string | null; discovered_at: string; record_url: string }[] | null
  profile_evidence?: { value: string; source_url: string; source_title: string | null; verified_at: string | null; note: string }[]
  reporting_volume?: { stories: number; last_30: number; previous_30: number }; groups?: string[]
}
export interface Changes {
  first: boolean; summary: string[]; new?: string[]; removed?: string[]; removed_titles?: Record<string, string>
  priority_up?: { key: string; title: string; from: string; to: string }[]; priority_down?: { key: string; title: string; from: string; to: string }[]
  new_evidence?: Record<string, number[]>; new_techniques?: Record<string, string[]>
}
export interface Assessment {
  id: number; profile_id: number; created_at: string; method_version: number; attack_version: string | null
  inputs: { window: { from: string; to: string; days: number }; data: { articles_considered: number; sources: string[]; kev_in_window: number; claims_used: boolean; attack_version: string | null; latest_article: string | null; collection_started: string | null } }
  findings: Finding[]; changes: Changes
}
export interface Review { finding_key: string; decision: 'dismissed' | 'accepted'; reason: string; updated_at: string }
export interface ProfileResponse {
  profile: Profile; assessment: Assessment | null; reviews: Record<string, Review>; assessments: number
  stale: { profile_changed: boolean; new_articles: number; method_changed: boolean } | null
  freshness: { latest_article: string | null; latest_claim: string | null; kev_checked: string | null }
}
export interface Meta {
  sectors: { key: string; label: string }[]; tech_types: Record<string, string>; telemetry: Record<string, string>; hardening: Record<string, string>
  provenance: Record<Provenance, string>; sources: { key: string; name: string }[]; scenarios: Record<string, string>; attack_version: string | null
}

export const PRIORITY_CLASS: Record<string, string> = { P1: 'critical', P2: 'high', P3: 'medium', P4: 'low' }
export const CLASSIFICATION: Record<Classification, { label: string; help: string }> = {
  observed: { label: 'Observed', help: 'Dated evidence ties this to the sector, countries, organisation or a listed technology.' },
  emerging: { label: 'Emerging', help: 'Reporting is increasing, but none ties it to this profile.' },
  plausible: { label: 'Plausible scenario', help: 'Applies to organisations like this one. Not evidence of an active campaign.' },
  historical: { label: 'Historical', help: 'Relevant reporting exists, but nothing recent.' },
}
export const BASIS: Record<Basis, string> = {
  reported: 'Named in reporting', group: 'Documented for a group in the evidence', keyword: 'Inferred from keywords', guidance: 'Guidance, needs review',
}
export const PROVENANCE: Record<Provenance, string> = { user: 'Entered by me', public: 'Public, with source', inferred: 'Inferred', unknown: 'Unknown' }
export const FACT_CATEGORIES: Record<string, { label: string; hint: string }> = {
  service: { label: 'Critical business services', hint: 'For example online ordering, manufacturing, patient care.' },
  asset: { label: 'Critical assets and data', hint: 'For example product designs, patient records, payment systems.' },
  supplier: { label: 'Important suppliers', hint: 'Managed service providers, SaaS platforms, logistics.' },
  regulation: { label: 'Regulatory requirements', hint: 'Only obligations you have confirmed apply.' },
  tech: { label: 'Technology', hint: 'Products in use. Exploited vulnerabilities are matched against these.' },
  telemetry: { label: 'Available logs', hint: 'What the SOC can actually search.' },
  control: { label: 'Security controls', hint: 'Status as you know it. Unknown stays unknown.' },
  context: { label: 'Other context', hint: 'Anything else relevant, such as recent public disclosures.' },
}
export const TELEMETRY_STATUS: Record<string, string> = { available: 'Available', partial: 'Partly available', not_available: 'Not available', unknown: 'Unknown' }
export const CONTROL_STATUS: Record<string, string> = {
  implemented_tested: 'Implemented and tested', implemented: 'Implemented, not tested', partial: 'Partly implemented', not_implemented: 'Not implemented', unknown: 'Unknown',
}
export const DETECTION: Record<string, string> = { unknown: 'Unknown', none: 'No detection', partial: 'Partial', implemented: 'Implemented', validated: 'Validated' }
export const HUNT_STATUS: Record<string, string> = {
  proposed: 'Proposed', ready: 'Ready', in_progress: 'In progress', completed: 'Completed, nothing found', findings: 'Findings identified', blocked: 'Blocked by missing telemetry',
}
export const COUNTRIES: Record<string, string> = { NZ: 'New Zealand', AU: 'Australia', US: 'United States', GB: 'United Kingdom', CA: 'Canada', SG: 'Singapore', JP: 'Japan', DE: 'Germany', FR: 'France', IN: 'India', CN: 'China' }
export const lsPath = (id: number | string, rest = '') => `/api/landscapes/${id}${rest}`
