export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface ArticleBrief {
  id: number
  url: string
  title: string
  excerpt: string
  ai_summary: string | null
  published_at: string
  retrieved_at: string
  source: { name: string; key: string; homepage?: string; authority?: number }
  sections: string[]
  tags: string[]
  severity: number
  severity_label: Severity
  severity_reasons: string[]
  confidence: string
  region: string | null
  related_count: number
  bookmarked: boolean
  read: boolean
  bookmark?: { note: string; tags: string[]; created_at: string } | null
  last_read_at?: string
  link?: EvidenceLink
}

export interface Vuln {
  cve_id: string
  vendor: string | null
  product: string | null
  name: string | null
  description: string | null
  cvss_score: number | null
  cvss_severity: string | null
  cvss_vector: string | null
  cvss_source: string | null
  kev: boolean
  kev_date_added: string | null
  kev_due_date: string | null
  kev_ransomware: string | null
  kev_required_action: string | null
  kev_notes: string | null
  epss: number | null
  epss_percentile: number | null
  epss_date: string | null
  references: string[]
  nvd_url: string
  cve_url: string
  kev_url: string | null
  mentions?: number
  articles?: ArticleBrief[]
  watch_id?: number | null
}

export interface EntityItem { value: string; method: string; name?: string | null }

export interface WatchSuggestion {
  kind: string
  title: string
  identifiers: string[]
  aliases: string[]
  context_terms: string[]
  hint?: string
  existing_watch_id: number | null
}

export interface ArticleDetail extends ArticleBrief {
  summary_text: string
  content_text: string
  author: string | null
  entities: Record<string, EntityItem[]>
  vulnerabilities: Vuln[]
  related: ArticleBrief[]
  ai: { summary: string; why_it_matters: string; technical: string; exploitation_status: string; model: string; generated_at: string } | null
  watches: { id: number; title: string; kind: string; status: string; significance: string }[]
  watch_suggestions: WatchSuggestion[]
  ai_available: boolean
}

export interface BriefingItem {
  title: string
  summary: string
  why_it_matters: string
  priority: string
  article_ids: number[]
  method: string
  sources?: ArticleBrief[]
}

export interface Today {
  briefing: null | {
    id: number; date: string; generated_at: string; method: string; model: string | null; headline: string
    items: BriefingItem[]; kev_new: Partial<Vuln>[]; watch_updates: { id: number; title: string; n: number }[]
  }
  last_visit_at: string | null
  since_last_visit: { count: number; articles: ArticleBrief[] }
  top_threats: ArticleBrief[]
  watch_updates: { id: number; title: string; kind: string; important: number; new_evidence: number; last_updated_at: string }[]
  last_ingest_at: string | null
  ai_enabled: boolean
}

export interface Claim { claim: string; article_ids: number[]; note?: string }

export interface WatchRecord {
  version: number
  created_at: string
  method: string
  model: string | null
  summary: string
  confirmed: Claim[]
  uncertain: Claim[]
  changes: { change: string; article_ids: number[] }[]
  iocs: { type: string; value: string; article_ids: number[] }[]
  techniques: { id: string; name: string | null; article_ids: number[]; inferred: boolean; ai?: boolean }[]
  detection: Claim[]
  evidence_ids: number[]
}

export interface EvidenceLink {
  article_id: number
  status: string
  match_score: number
  match_reasons: string[]
  significance: string
  assessment: string
  linked_by: string
  linked_at: string
}

export interface Watch {
  id: number
  kind: string
  title: string
  canonical_key: string
  description: string
  identifiers: string[]
  aliases: string[]
  context_terms: string[]
  exclude_terms: string[]
  notify_pref: string
  status: string
  tags: string[]
  notes: string
  created_at: string
  last_checked_at: string | null
  last_updated_at: string | null
  evidence_count?: number
  candidate_count?: number
  unseen_count?: number
  latest_evidence_at?: string | null
  summary_excerpt?: string
  summary_version?: number
}

export interface WatchDetail extends Watch {
  record: WatchRecord | null
  versions: { version: number; created_at: string; method: string; model: string | null; changes: { change: string; article_ids: number[] }[] }[]
  evidence: ArticleBrief[]
  candidates: ArticleBrief[]
  timeline: { id: number; occurred_at: string; event_type: string; title: string; detail: string; article_id: number | null; summary_version: number | null }[]
  previous_viewed_at: string | null
}

export interface Notification {
  id: number; created_at: string; kind: string; title: string; body: string; link: string | null; read_at: string | null
}

export interface Source {
  id: number; key: string; name: string; kind: string; url: string; homepage: string; enabled: boolean; interval_minutes: number
  authority: number; region: string; last_fetched_at: string | null; last_success_at: string | null; last_status: string | null
  last_error: string | null; items_last_run: number; consecutive_failures: number; article_count: number; latest_article: string | null
}
