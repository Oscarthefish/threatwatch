import { useQuery } from '@tanstack/react-query'
import { api, ApiError } from './api'

export type ReportStatus = 'discovered' | 'queued' | 'processing' | 'processed' | 'needs_review' | 'failed'

export interface ReportRow {
  id: number; title: string; publisher: string | null; series: string | null; edition: string | null; published_on: string | null
  category: string | null; regions: string[]; industries: string[]; status: ReportStatus; status_detail: string | null
  page_count: number | null; extraction_confidence: string | null; review_status: string; bookmarked: boolean; created_at: string
  has_document: boolean; publication_url: string | null; match?: { pages: number; first_page: number } | null
}
export interface Report extends ReportRow {
  source_id: number | null; period_start: string | null; period_end: string | null; document_url: string | null; frequency: string | null
  methodology: string | null; sample_size: string | null; access_notes: string | null; notes: string | null
  meta_source: Record<string, string>; original_filename: string | null; file_size: number | null; retrieved_at: string | null
  retrieval: string | null; pdf_meta: Record<string, string>; extraction_method: string | null; extraction_version: number | null
  text_pages: number | null; processed_at: string | null; updated_at: string; sha256_prefix: string | null
}
export interface Source {
  id: number; key: string; publisher: string; series: string; page_url: string | null; frequency: string; category: string | null
  region: string; priority: number; discovery_method: string; enabled: boolean; verified_at: string | null; access_notes: string | null
  notes: string | null; seeded: boolean; reports: number; latest: string | null
}
export interface Job {
  id: number; kind: string; status: string; extractor: string | null; extractor_version: number | null; pages: number | null
  text_pages: number | null; chars: number | null; sections: number | null; detail: string | null; started_at: string; finished_at: string | null
}
export interface Block { type: 'h' | 'p' | 'li' | 'figure'; text: string; vendor?: boolean }
export interface Chapter { number: string; title: string; subtitle: string | null; start: number; end: number }
interface Item { page: number; chapter: string | null; text: string }
export interface Named { value: string; pages: number[]; known?: { cvss: number | null; kev: boolean } | null }
export interface Analysis {
  version: number; running_title: string | null; chapters: Chapter[]
  highlights: {
    takeaways: Item[]; recommendations: (Item & { title: string | null })[]; vendor_guidance: { page: number; text: string }[]
    statistics: Item[]; actors: Named[]; malware: Named[]; technologies: Named[]; cves: Named[]
    techniques: { id: string; name: string; basis: 'cited' | 'named'; pages: number[] }[]
  }
}
export interface ReadPage { page_no: number; label: string | null; blocks: Block[] | null; text: string | null }
export interface ReportDetail {
  report: Report; analysis: Analysis | null; source: Source | null; jobs: Job[]
  sections: { ord: number; level: number; title: string; page_start: number; page_end: number; origin: string }[]
  pages: { page_no: number; label: string | null; chars: number }[]
  editions: { id: number; title: string; edition: string | null; published_on: string | null; status: ReportStatus }[]
  suggested_sources: { id: number; publisher: string; series: string; frequency: string }[]
}
export interface ReportsMeta { frequencies: string[]; categories: Record<string, string>; regions: string[]; max_mb: number; max_pages: number }

export const STATUS_LABEL: Record<ReportStatus, string> = {
  discovered: 'Awaiting document', queued: 'Queued', processing: 'Processing', processed: 'Processed', needs_review: 'Needs review', failed: 'Failed',
}
export const STATUS_TONE: Record<ReportStatus, string> = {
  discovered: 'neutral', queued: 'neutral', processing: 'neutral', processed: 'good', needs_review: 'warn', failed: 'bad',
}
export const STATUS_GROUPS: [string, string][] = [
  ['', 'All'], ['processed', 'Processed'], ['processing', 'Queued or processing'], ['review', 'Needs review'], ['failed', 'Failed'], ['awaiting', 'Awaiting document'],
]
export const FREQ_LABEL: Record<string, string> = {
  annual: 'Annual', semiannual: 'Twice a year', quarterly: 'Quarterly', monthly: 'Monthly', weekly: 'Weekly', irregular: 'Irregular', unknown: 'Unknown',
}
export const REGION_LABEL: Record<string, string> = { GLOBAL: 'Global', NZ: 'New Zealand', AU: 'Australia', APAC: 'APAC', US: 'United States', UK: 'United Kingdom', EU: 'Europe' }
export const META_SOURCE_LABEL: Record<string, string> = { user: 'Entered by you', pdf: 'From PDF metadata', filename: 'From file name', series: 'From the series', layout: 'From the page headers' }
export const CONF_LABEL: Record<string, string> = { high: 'Good text layer', medium: 'Partial text layer', low: 'Little usable text' }

export const reportsPath = (id: number | string) => `/api/reports/${id}`

export function useReportsMeta() {
  return useQuery({ queryKey: ['reports-meta'], queryFn: () => api.get<ReportsMeta>('/api/reports/meta'), staleTime: 300_000 })
}

export function fmtSize(n?: number | null) {
  if (!n) return ''
  return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`
}

/** Sends the file as the raw request body (no multipart), with the name in a header as a label only. */
export async function uploadReport(file: File, reportId?: number): Promise<{ id: number }> {
  const res = await fetch(`/api/reports/upload${reportId ? `?report_id=${reportId}` : ''}`, {
    method: 'POST', credentials: 'same-origin', body: file,
    headers: { 'Content-Type': 'application/pdf', 'X-TW-Request': '1', 'X-Filename': encodeURIComponent(file.name), Accept: 'application/json' },
  })
  if (!res.ok) {
    let msg = res.status === 413 ? 'The file is too large.' : res.statusText
    try { const j = await res.json(); if (typeof j.detail === 'string') msg = j.detail } catch { /* not json */ }
    throw new ApiError(res.status, msg)
  }
  return res.json()
}
