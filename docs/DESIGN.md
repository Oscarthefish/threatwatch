# Design system

Direction: **calm, precise briefing.** Threat Watch should read like a well-edited intelligence
summary, not a dashboard. Rules, whitespace and type weight separate content; elevation is
reserved for things that float above the page (sheets, toasts, popovers).

Tokens live in `frontend/src/index.css` (`:root`) and switch for dark mode via
`prefers-color-scheme` or the in-app theme toggle (`data-theme`).

## Type
| Token | Value | Use |
|---|---|---|
| `--font` | system UI stack | Native on Android and macOS; no download, no third-party request |
| `--mono` | ui-monospace stack | CVE IDs, hashes, IOCs, vectors: anything copied or compared character by character |
| `--t-xs` … `--t-2xl` | 12 / 13 / 15 / 17 / 20 / 24 px | Six steps only. Body 15, metadata 12–13, headings 17–24 |
| `--lh-body` / `--lh-tight` | 1.5 / 1.3 | Reading text / headings and dense rows |
| `--measure` | 68ch | Max line length for summaries and claims |

## Spacing
4 px base: `--s-1` 4 · `--s-2` 8 · `--s-3` 12 · `--s-4` 16 · `--s-5` 24 · `--s-6` 32 · `--s-7` 48.

## Colour
One primary (teal), slate neutrals, five severity colours, three semantic states.
Every text colour meets **4.5:1** on `--surface`, `--surface-2` and `--bg` in its theme (computed, and
verified with axe-core). Input borders and the focus ring meet **3:1**.

| Token | Light | Dark | Note |
|---|---|---|---|
| `--primary` | #0d7a6c | #3fb5a3 | Primary button text is white in light, near-black in dark (5.2:1 / 7.4:1) |
| `--text` / `--muted` / `--faint` | #17202a / #5d6b7a / #616f7e | #e6e9ee / #9aa6b4 / #818d99 | `--faint` is still AA; never use lighter text |
| `--sev-critical/high/medium/low/info` | #c8242b / #b94c0a / #8d6600 / #2a71ae / #616f7e | #ff5b61 / #ff8a3d / #e3b341 / #5aa9e6 / #818d99 | Always paired with a text label; colour is never the only signal |
| `--ok` / `--warn` / `--danger` | #1a7d47 / #8d6600 / #c8242b | #3fb97a / #e3b341 / #ff5b61 | |

## Shape, elevation, motion
- Radius: `--r-sm` 6 px (controls, tags), `--r-md` 10 px (panels, sheets), `--r-pill` (filter chips and counters only).
- Borders: hairline `--border` for structure, `--border-strong` for form controls.
- Elevation: `--shadow-overlay` on sheets, toasts and popovers only. Panels and cards are flat.
- Motion: `--dur-fast` 150 ms for state changes, `--dur-med` 200 ms for sheets; disabled under `prefers-reduced-motion`.

## Sizing and touch
`--control-h` is 44 px (touch first) and drops to 36 px only for a fine pointer on wide screens.
Icon buttons are always a 44 px target; `.btn.icon.compact` draws 32 px but keeps a 44 px hit area.
Filter chips and the severity label extend their hit area with a pseudo-element.

## Components
| Component | Where | States |
|---|---|---|
| Button `.btn` + `.primary` / default / `.quiet` / `.danger` (`.solid`) / `.on` | everywhere | hover, focus ring, active (1 px press), disabled, loading (`aria-busy` spinner) |
| Icon button `.btn.icon[.compact]` | card actions, toolbars | as above; always has `aria-label` |
| Field `<Field label hint error>` + `.input` | forms | hover, focus, `aria-invalid` error with message, disabled |
| Filter chip `button.chip` / `.filter` | list filters | `aria-pressed` on/off |
| Tag `.chip` | static labels | none (not interactive) |
| Panel `.panel` / Card `.card` | sections / items | link cards get a border hover |
| Sheet `<Sheet>` | Follow, More menu, confirmations | focus trap, Esc, backdrop click, focus return, scroll lock |
| Confirm `useConfirm()` | destructive actions | replaces `window.confirm` |
| Toast `useToast()(msg, 'error'?)` | action feedback | announced via a persistent live region |
| Severity `<Severity reasons>` | cards, article | tap or keyboard opens “Why …” popover; Esc / outside tap closes |
| ErrorBox `<ErrorBox error onRetry>` | failed loads | says what happened and how to fix it, with retry |
| Tabs `.tabs`, segmented `.seg` | watch detail, filters | `aria-selected` / `aria-pressed` |

## Rules
- One primary button per view; everything else is secondary or quiet.
- Use tokens, not literal values. New one-off inline styles need a reason.
- Generated (AI) content is always labelled and never styled as source evidence.
- Copy: plain, specific, no marketing phrasing, no em dashes in UI strings.

## Redesign log (November 2026)

### Changed
| Area | Before | After |
|---|---|---|
| Colour | Primary button 2.5:1 (dark) / 4.0:1 (light); faint text, high/medium severity and OK colours failed AA | Every text colour computed to ≥ 4.5:1 in both themes; inputs and focus ≥ 3:1 |
| System | 21 font sizes, 13 radii, 26 spacing values, 98 inline styles, shadowed card around everything | 6 type steps, 7 spacing steps, 3 radii, tokens only (the few inline styles left set computed values such as meter widths); flat panels, elevation only for overlays |
| Touch | 30–38 px targets | 44 px targets (visual 32 px where dense, hit area kept) |
| Keyboard | Sheets without Esc, focus trap or focus return; browser `confirm()` | Accessible Sheet and Confirm; skip link; `/` search shortcut; visible focus on every stop |
| Shell | Ungrouped nav, no page titles, cramped mobile search, Back on one page | Grouped nav, live collection status, page titles, full-width mobile search, consistent Back |
| Today | Long single column, repeated items | Tiles, compact briefing, stable “since last visit”, KEV / Following / NZ rail |
| Article | Empty “Summary” without AI, long source text first | Briefing document: In brief, What to do, collapsible source, facts sidebar |
| Following | 7-field form, 6 tabs, raw match scores | One-tap follow for CVE/actor/malware, 4 tabs, plain-language match reasons, review banner |
| Lists | Actions wrapped under metadata on phones, one generic empty state | Two-column cards, side-by-side filters, filtered-empty vs empty states, product-first CVE rows |
| SecOps | None | Evidence-based “What to do” steps with stated basis |
| Copy | 26 em dashes, sparkle icon for AI, internal terms (candidate, heuristic, scores) | No em dashes in UI or notifications, plain “AI” label, plain language |
| Sign in / Settings | Bare card; sources table scrolled sideways on phones | Two-column sign-in with factual description; Settings as health, sources with switches, AI, device, data |

### Verified
- axe-core WCAG 2.2 AA: 0 violations across 96 scans (16 routes × 390 / 768 / 1440 px × light / dark) plus the sign-in page.
- No horizontal overflow at any of those widths.
- Keyboard: 60 consecutive Tab stops on Today, all with a visible focus indicator; Follow sheet traps focus, closes on Esc, returns focus.
- Accessibility tree: one h1 per page, banner / navigation / main / search landmarks, no unnamed controls.
- Banned-phrase and em-dash scan of UI and notification copy: clean.

### Deliberately left alone
- No social preview image or Open Graph tags: the app is private and `noindex`.
- No web font: system fonts render instantly and make no third-party request.
- No hover-only information: severity reasons and other explanations are tap-to-reveal.
- Data model, API and matching rules unchanged except the fixes recorded in git history (CVE body mentions, roundups never important).

### Recommended next
- Real-device check on Android once HTTPS (Tailscale Serve) is in place: PWA install, offline reading, push.
- Route-level code splitting (bundle is ~115 kB gzipped; fine today).
- A short user test of the Follow flow after a week of real use, to tune notification defaults.
