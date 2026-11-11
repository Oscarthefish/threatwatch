import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react'

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * Modal sheet (bottom sheet on phones, centred dialog on desktop).
 * Traps focus, closes on Esc or backdrop, locks page scroll, and returns focus to the trigger.
 */
export function Sheet({ title, onClose, children, narrow, actions }: {
  title: string; onClose: () => void; children: ReactNode; narrow?: boolean; actions?: ReactNode
}) {
  const panel = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const close = useRef(onClose)
  close.current = onClose

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const el = panel.current
    const first = el?.querySelector<HTMLElement>('[autofocus], [data-autofocus]') ?? el?.querySelector<HTMLElement>(FOCUSABLE)
    first?.focus()
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') { e.stopPropagation(); close.current(); return }
      if (e.key !== 'Tab' || !el) return
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((n) => n.offsetParent !== null)
      if (!items.length) return
      const [a, b] = [items[0], items[items.length - 1]]
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); b.focus() }
      else if (!e.shiftKey && document.activeElement === b) { e.preventDefault(); a.focus() }
    }
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('keydown', onKey, true)
      document.body.style.overflow = prevOverflow
      opener?.focus?.()
    }
  }, [])

  return (
    <div className="sheet-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div ref={panel} className={`sheet-panel ${narrow ? 'narrow' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="sheet-head">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="btn quiet small" onClick={onClose}>Close</button>
        </div>
        {children}
        {actions && <div className="sheet-actions">{actions}</div>}
      </div>
    </div>
  )
}

// ----------------------------------------------------------- confirm dialog
interface ConfirmOpts { title: string; body?: string; confirmLabel: string; danger?: boolean }
const ConfirmCtx = createContext<(o: ConfirmOpts) => Promise<boolean>>(async () => false)

/** Replaces window.confirm with an accessible, styled dialog. Usage: `if (await confirm({...})) ...` */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [req, setReq] = useState<(ConfirmOpts & { resolve: (v: boolean) => void }) | null>(null)
  const ask = useCallback((o: ConfirmOpts) => new Promise<boolean>((resolve) => setReq({ ...o, resolve })), [])
  const done = (v: boolean) => { req?.resolve(v); setReq(null) }
  return (
    <ConfirmCtx.Provider value={ask}>
      {children}
      {req && (
        <Sheet title={req.title} narrow onClose={() => done(false)} actions={<>
          <button type="button" className="btn" data-autofocus onClick={() => done(false)}>Cancel</button>
          <button type="button" className={`btn ${req.danger ? 'danger solid' : 'primary'}`} onClick={() => done(true)}>{req.confirmLabel}</button>
        </>}>
          {req.body && <p className="muted mb-0">{req.body}</p>}
        </Sheet>
      )}
    </ConfirmCtx.Provider>
  )
}
export const useConfirm = () => useContext(ConfirmCtx)
