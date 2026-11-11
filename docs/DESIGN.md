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
| `--bg` / `--surface` / `--surface-2` | #f5f6f8 / #ffffff / #eff1f4 | #0d0f12 / #14171b / #1c2026 | Neutral graphite in dark; sidebar and top bar sit on `--bg` |
| `--primary` | #0d7a6c | #3fb5a3 | Primary button text is white in light, near-black in dark (5.2:1 / 7.4:1) |
| `--text` / `--muted` / `--faint` | #14191f / #56626f / #5c6875 | #e8eaed / #9da5af / #8f97a1 | `--faint` is still AA; never use lighter text |
| `--sev-critical/high/medium/low/info` | #b81d24 / #a8450a / #7d5a00 / #22679f / #5c6875 | #ff5b61 / #ff8a3d / #e3b341 / #5aa9e6 / #8f97a1 | Shown as a tinted label (10% tint keeps 4.5:1); always text, never colour alone |
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
| Joined list `.alist` / `.vlist` | every article and CVE list | one surface with hairline rows; hover tint; keyboard selection bar |
| Keyboard shortcuts `useShortcuts` | whole app (desktop) | items carry `data-nav`, keyed buttons carry `data-key`; `?` opens the list |

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

## Batch 7: desktop polish (November 2026)
| Area | Before | After |
|---|---|---|
| Palette | Blue-slate dark theme; orange outlined step tags, blue source chips and red underlined severity all competing | Neutral graphite dark theme; severity is the only coloured label; step tags are neutral with an orange marker for urgent |
| Lists | Separate boxed cards, each with a coloured left border | One joined list per page, hairline rows, hover tint |
| Layout | Today wide and left-filled, list pages centred, so the title moved between sections | One left edge on every page, aligned with the search box |
| Today | Six separate stat boxes, sources as link chips | One joined stats strip, sources as plain comma-separated links |
| Buttons | "Bookmarked" and "Following" teal next to the teal primary | Toggled state is neutral with an accent icon; one filled button per view |
| Keyboard | `/` only | `j`/`k` move, `o` open, `b` bookmark, `f` follow, `v` source, `g` + letter to change section, `?` lists them (button in the top bar) |

Verified as before: 96 axe scans with 0 violations and no overflow, 60 Tab stops with visible focus, keyboard shortcuts exercised end to end.

## Guided tour
`frontend/src/components/Tour.tsx` walks through every section in 20 steps (Today, Breaking, topic feeds, an article,
Vulnerabilities, Following, Saved, notifications, search, Settings). Each step names a route and an ordered list of
target selectors; the target is highlighted and the card sits beside it, or docks at the bottom on phones. If a target
is missing (for example no articles yet) the card is shown centred, and steps that need an article are skipped when
there is none, so the tour never stalls.

- Starts once automatically on the first sign-in per device (`tw-tour-seen` in localStorage), and can be restarted from
  the sidebar, the More menu on phones, Settings and the keyboard shortcuts sheet.
- Keyboard: arrow keys step, Esc ends, Tab stays inside the card, focus moves to each step's heading and returns to the
  opener when the tour ends. Card verified with axe at 390 and 1440 px.
- When adding a section, add a step to `STEPS` with plain, specific copy (no em dashes).

## Batch 8: clarity pass (November 2026)
| Area | Change |
|---|---|
| Breaking | Incidents lead the page; followed updates and a 5-item KEV preview ("Show all") sit in a rail on wide screens and stack above/below on phones. CISA KEV catalogue announcements are no longer repeated as incidents, and topic feeds leave them out too (text search still finds them). Priority/Newest toggle with a one-line explanation of the order. |
| Section headings | Kind-labelled headings (Following, Incidents, Newly exploited) with a count, so the three kinds of information never blur. |
| Follow alerts | Each shows what changed, the sentence that matched (terms highlighted) and the report. Broad bulletins and roundups no longer present unrelated CVEs or actors as changes. |
| Cards | Headline 17 px; metadata on one quiet line (severity, source, time, confidence, extra sources, region, date check). Excerpts end on whole words or sentences; publisher fragments are dropped. |
| Search | Matching passage from the full text (FTS5 snippet) with terms highlighted; titles, CVE rows and followed items highlighted too. |
| Article | "Why it is rated …" panel with reasons, confidence explained and source; "What to do" split into evidence-backed steps and standard practice. Date check shown under the title when dates disagree. |
| Identity | Small teal square leads each page's context line; larger page titles on desktop. |

Highlighting uses `<mark>` with full text colour (AA in both themes). The server marks search matches with control
characters, which the client turns into elements; nothing is parsed as HTML.

## Trends page (charts)
`/trends` (`pages/Trends.tsx`, charts in `components/charts.tsx`, data from `GET /api/trends?days=30|90`). No chart library.

- **What is counted:** stories (clustered articles count once) by publisher date; group, malware and vendor counts skip
  roundups. Counts describe reporting, not attacks, and the page says so.
- **Honesty about coverage:** feeds only expose their newest items, so periods before collection began are flagged
  `partial`, shaded in the volume chart and drawn faded in sparklines. Rising/falling compares each subject's *share of
  all stories*, not raw counts, so uneven collection volume does not make everything look like it is rising; while the
  earlier period is partial the comparison is labelled indicative. CISA KEV figures are complete and labelled so.
- **Forms:** stacked columns (volume by severity), ranked bars with a previous-period tick and weekly sparkline
  (groups, malware, vendors, topics, KEV vendors), before/after dumbbells (rising and falling), single-series columns (KEV).
- **Colour:** severity pair validated with the dataviz palette checks in both themes (light `#c4232b`/`#d17a2a` on
  white, dark `#d64545`/`#c98500` on `#14171b`); single series use the brand teal; grey is the de-emphasis neutral.
- **Access:** legends for 2+ series, hover and keyboard tooltips (arrow keys, announced via a live region), and a
  "Show as a table" view under every chart. 0 axe violations at 390 / 768 / 1440 px in both themes.
