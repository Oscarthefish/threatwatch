/** Shared vocabulary for following: plain-language labels instead of internal enum values and scores. */

export const NOTIFY: [string, string, string][] = [
  ['important', 'Important changes', 'New exploitation, victims, attribution, patches or indicators'],
  ['all', 'Every new finding', 'Any linked report that adds detail'],
  ['digest', 'Daily digest', 'One summary each morning at 7:05'],
  ['silent', 'No notifications', 'Keep the record updated quietly'],
]

export const KINDS: [string, string][] = [
  ['incident', 'Incident'], ['vulnerability', 'Vulnerability'], ['actor', 'Threat actor'],
  ['malware', 'Malware'], ['campaign', 'Campaign'], ['product', 'Product'], ['topic', 'Topic'],
]
export const kindLabel = (k: string) => KINDS.find(([v]) => v === k)?.[1] ?? k

export const SIGNIFICANCE: Record<string, string> = {
  important: 'Important', meaningful: 'Adds detail', minor: 'Little new', duplicate: 'Repeat coverage', unassessed: 'Not assessed',
}

export function matchStrength(score: number): string {
  return score >= 1 ? 'Strong match' : score >= 0.6 ? 'Good match' : 'Partial match'
}

/** Turn engine reasons ("'X' in headline", "contextual similarity 0.23") into plain phrases. */
export function humanReason(r: string): string {
  return r
    .replace(/^contextual similarity [\d.]+$/, 'similar wording to earlier reports')
    .replace(/^alias '(.+)' in headline$/, 'also known as “$1”, named in the headline')
    .replace(/^alias '(.+)' in text$/, 'also known as “$1”, named in the text')
    .replace(/^'(.+)' in headline$/, '“$1” in the headline')
    .replace(/^'(.+)' in text$/, '“$1” in the text')
    .replace(/^context '(.+)'$/, 'mentions $1')
    .replace(/^(CVE-\S+) in headline$/, '$1 in the headline')
    .replace(/^(CVE-\S+) mentioned$/, '$1 mentioned')
}

export const splitList = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)
