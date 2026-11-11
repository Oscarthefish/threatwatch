import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Sheet } from './Sheet'

/**
 * Keyboard shortcuts for desktop use. Lists mark their items with `data-nav`;
 * buttons that a key should press carry `data-key="<key>"`. Item-scoped keys act
 * on the selected item; on pages without items (an article) they act on the page.
 */
const GO: Record<string, [string, string]> = {
  t: ['/', 'Today'], b: ['/breaking', 'Breaking'], i: ['/intel', 'Threat intelligence'], v: ['/vulns', 'Vulnerabilities'],
  d: ['/soc', 'SOC & DFIR'], a: ['/apac', 'NZ & APAC'], f: ['/watch', 'Following'], s: ['/saved', 'Saved'],
  n: ['/notifications', 'Notifications'], p: ['/settings', 'Settings'],
}

export const SHORTCUTS: { group: string; keys: [string[], string][] }[] = [
  { group: 'Lists', keys: [[['j'], 'Next item'], [['k'], 'Previous item'], [['o'], 'Open selected item'], [['b'], 'Bookmark selected item']] },
  { group: 'Article', keys: [[['b'], 'Bookmark'], [['f'], 'Follow'], [['v'], 'Read on the source site']] },
  { group: 'Anywhere', keys: [[['/'], 'Search'], [['?'], 'Show this list'], [['Esc'], 'Close a panel or leave search']] },
  { group: 'Go to', keys: Object.entries(GO).map(([k, [, label]]) => [['g', k], label]) },
]

const items = () => [...document.querySelectorAll<HTMLElement>('main [data-nav]')].filter((n) => n.offsetParent !== null)
const primary = (item: HTMLElement) => (item.matches('a[href], button') ? item
  : item.querySelector<HTMLElement>('[data-open]') ?? item.querySelector<HTMLElement>('a[href], button'))

function select(el: HTMLElement) {
  document.querySelectorAll('.kb-sel').forEach((n) => n.classList.remove('kb-sel'))
  el.classList.add('kb-sel')
  const p = primary(el)
  p?.focus({ preventScroll: true })
  el.scrollIntoView({ block: 'nearest', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' })
}

export function useShortcuts() {
  const nav = useNavigate()
  const [help, setHelp] = useState(false)
  const pendingG = useRef(0)

  useEffect(() => {
    const clear = () => document.querySelectorAll('.kb-sel').forEach((n) => n.classList.remove('kb-sel'))
    function onKey(e: KeyboardEvent) {
      const t = e.target as HTMLElement
      if (e.metaKey || e.ctrlKey || e.altKey || t.closest('input, textarea, select, [contenteditable]') || document.querySelector('[role=dialog]')) return
      const k = e.key
      if (Date.now() - pendingG.current < 1200 && GO[k]) { e.preventDefault(); pendingG.current = 0; nav(GO[k][0]); return }
      pendingG.current = 0
      if (k === 'g') { pendingG.current = Date.now(); return }
      if (k === '?') { e.preventDefault(); setHelp(true); return }
      if (k === 'j' || k === 'k') {
        const list = items(); if (!list.length) return
        e.preventDefault()
        const cur = list.findIndex((n) => n.classList.contains('kb-sel') || n.contains(document.activeElement))
        let next: number
        if (cur === -1) {
          // start from the first item in view
          const first = list.findIndex((n) => n.getBoundingClientRect().bottom > 80)
          next = first === -1 ? 0 : first
        } else next = Math.max(0, Math.min(list.length - 1, cur + (k === 'j' ? 1 : -1)))
        select(list[next]); return
      }
      if (k === 'o' || k === 'b' || k === 'f' || k === 'v') {
        const list = items()
        const sel = list.find((n) => n.classList.contains('kb-sel') || n.contains(document.activeElement))
        const scope: ParentNode | null = sel ?? (list.length ? null : document.querySelector('main'))
        if (!scope) return
        const target = k === 'o' && sel ? primary(sel) : scope.querySelector<HTMLElement>(`[data-key="${k}"]`)
        if (!target) return
        e.preventDefault(); target.click()
      }
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('pointerdown', clear)
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener('pointerdown', clear) }
  }, [nav])

  return { help, setHelp }
}

export function ShortcutsSheet({ onClose, onTour }: { onClose: () => void; onTour?: () => void }) {
  return (
    <Sheet title="Keyboard shortcuts" onClose={onClose} actions={onTour && <button type="button" className="btn" onClick={onTour}>Take the guided tour</button>}>
      <div className="kbd-grid">
        {SHORTCUTS.map((g) => (
          <section key={g.group} aria-labelledby={`kb-${g.group}`}>
            <h3 id={`kb-${g.group}`}>{g.group}</h3>
            <dl>
              {g.keys.map(([keys, label]) => (
                <div key={keys.join('') + label} className="kbd-row">
                  <dt>{keys.map((key, i) => <span key={i}>{i > 0 && <span className="faint xsmall"> then </span>}<kbd className="key">{key}</kbd></span>)}</dt>
                  <dd>{label}</dd>
                </div>
              ))}
            </dl>
          </section>
        ))}
      </div>
    </Sheet>
  )
}
