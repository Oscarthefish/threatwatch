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
