import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

/**
 * Small, dependency-free charts for the Trends page.
 * Marks follow the dataviz spec: bars <= 24px with a 4px rounded data-end and a square
 * baseline, 2px gaps between stacked segments, hairline grid, text in text colours
 * (never the series colour), a legend for 2+ series, hover AND keyboard tooltips,
 * and every chart has a table view so nothing depends on hovering or on colour.
 */

export interface Series { key: string; label: string; color: string }
export interface Column { label: string; title: string; values: Record<string, number>; partial?: boolean }

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null)
  const [w, setW] = useState(0)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, w] as const
}

function niceMax(v: number): number {
  if (v <= 4) return 4
  const step = Math.pow(10, Math.floor(Math.log10(v)))
  for (const m of [1, 2, 2.5, 5, 10]) if (m * step >= v) return m * step
  return 10 * step
}

/** Rect with only the top corners rounded (the data end); the baseline stays square. */
function topRounded(x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.min(r, h, w / 2)
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`
}

export function Legend({ series }: { series: Series[] }) {
  return (
    <ul className="viz-legend">
      {series.map((s) => <li key={s.key}><i style={{ background: s.color }} aria-hidden="true" />{s.label}</li>)}
    </ul>
  )
}

/** Stacked column chart over time. Partial (incomplete) periods sit on a shaded band. */
export function ColumnChart({ columns, series, label, height = 200, partialNote }: {
  columns: Column[]; series: Series[]; label: string; height?: number; partialNote?: string
}) {
  const [ref, width] = useWidth<HTMLDivElement>()
  const [active, setActive] = useState<number | null>(null)
  const pad = { l: 32, r: 8, t: 12, b: 24 }
  const totals = columns.map((c) => series.reduce((n, s) => n + (c.values[s.key] ?? 0), 0))
  const max = niceMax(Math.max(1, ...totals))
  const ticks = Number.isInteger(max / 2) ? [0, max / 2, max] : [0, max]
  const plotW = Math.max(0, width - pad.l - pad.r), plotH = height - pad.t - pad.b
  const band = columns.length ? plotW / columns.length : 0
  const barW = Math.max(2, Math.min(24, band * 0.62))
  const y = (v: number) => pad.t + plotH - (v / max) * plotH
  const partialN = columns.filter((c) => c.partial).length
  const every = Math.max(1, Math.ceil(columns.length / Math.max(1, Math.floor(plotW / 56))))
  const live = active !== null ? `${columns[active].title}: ${series.map((s) => `${s.label} ${columns[active].values[s.key] ?? 0}`).join(', ')}` : ''

  function onKey(e: React.KeyboardEvent) {
    if (!columns.length) return
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault()
      const d = e.key === 'ArrowRight' ? 1 : -1
      setActive((a) => Math.max(0, Math.min(columns.length - 1, (a ?? (d > 0 ? -1 : columns.length)) + d)))
    }
    if (e.key === 'Escape') setActive(null)
  }

  return (
    <div className="viz" ref={ref}>
      {series.length > 1 && <Legend series={series} />}
      {width > 0 && (
        <svg width={width} height={height} role="application" aria-roledescription="chart" aria-label={`${label}. Use the left and right arrow keys to read each period.`}
          tabIndex={0} onKeyDown={onKey} onBlur={() => setActive(null)} onPointerLeave={() => setActive(null)}>
          {partialN > 0 && <>
            <rect x={pad.l} y={pad.t} width={band * partialN} height={plotH} className="viz-partial" />
            {band * partialN > 120 && <text x={pad.l + 6} y={pad.t + 12} className="viz-note">{partialNote ?? 'Incomplete'}</text>}
          </>}
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} className="viz-grid" />
              <text x={pad.l - 6} y={y(t) + 4} className="viz-tick" textAnchor="end">{t}</text>
            </g>
          ))}
          {columns.map((c, i) => {
            const x = pad.l + i * band + (band - barW) / 2
            let base = 0
            const segs = series.map((s) => ({ s, v: c.values[s.key] ?? 0 })).filter((x) => x.v > 0)
            return (
              <g key={i} className={`viz-col ${active === i ? 'on' : ''} ${c.partial ? 'partial' : ''}`}>
                {segs.map(({ s, v }, j) => {
                  const y0 = y(base), y1 = y(base + v)
                  base += v
                  const top = j === segs.length - 1
                  const h = Math.max(0, y0 - y1 - (top ? 0 : 2)) // 2px surface gap above each non-top segment
                  return top ? <path key={s.key} d={topRounded(x, y1, barW, h, 4)} fill={s.color} />
                    : <rect key={s.key} x={x} y={y1 + 2} width={barW} height={h} fill={s.color} />
                })}
                {i % every === 0 && <text x={pad.l + i * band + band / 2} y={height - 6} className="viz-tick" textAnchor="middle">{c.label}</text>}
                <rect x={pad.l + i * band} y={pad.t} width={band} height={plotH} fill="transparent" onPointerEnter={() => setActive(i)} />
              </g>
            )
          })}
          <line x1={pad.l} x2={width - pad.r} y1={y(0)} y2={y(0)} className="viz-axis" />
        </svg>
      )}
      {active !== null && width > 0 && (
        <div className="viz-tip" style={{ left: Math.min(width - 180, Math.max(0, pad.l + active * band + band / 2 - 90)), top: series.length > 1 ? 30 : 4 }} aria-hidden="true">
          <div className="viz-tip-h">{columns[active].title}{columns[active].partial ? ' (incomplete)' : ''}</div>
          {[...series].reverse().map((s) => (
            <div key={s.key} className="viz-tip-row"><i style={{ background: s.color }} /><b>{columns[active].values[s.key] ?? 0}</b><span>{s.label}</span></div>
          ))}
          {series.length > 1 && <div className="viz-tip-row total"><i /><b>{totals[active]}</b><span>Total</span></div>}
        </div>
      )}
      <span className="sr-only" aria-live="polite">{live}</span>
    </div>
  )
}

/** A 12-ish point trend line in the de-emphasis colour, current point in the accent. */
export function Sparkline({ values, partial = 0, label }: { values: number[]; partial?: number; label: string }) {
  const w = 88, h = 24, p = 4
  const max = Math.max(1, ...values)
  const pts = values.map((v, i) => [p + (i * (w - 2 * p)) / Math.max(1, values.length - 1), h - p - (v / max) * (h - 2 * p)] as const)
  const path = (ps: readonly (readonly [number, number])[]) => ps.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join('')
  const last = pts[pts.length - 1]
  return (
    <svg width={w} height={h} className="spark" role="img" aria-label={`${label}: ${values.join(', ')} by week`}>
      {partial > 0 && <path d={path(pts.slice(0, partial + 1))} className="spark-line partial" />}
      <path d={path(pts.slice(Math.max(0, partial)))} className="spark-line" />
      {last && <circle cx={last[0]} cy={last[1]} r={3.5} className="spark-dot" />}
    </svg>
  )
}

export interface RankRow { key: string; name: string; sub?: string; value: number; prev?: number; href?: string; weekly?: number[]; extra?: ReactNode }

/** Ranked horizontal bars, one hue; the previous period is a grey tick on the same axis. */
export function RankBars({ rows, unit, partialWeeks = 0, showPrev = true, nowLabel, prevLabel }: {
  rows: RankRow[]; unit: string; partialWeeks?: number; showPrev?: boolean; nowLabel?: string; prevLabel?: string
}) {
  const max = niceMax(Math.max(1, ...rows.map((r) => Math.max(r.value, showPrev ? r.prev ?? 0 : 0))))
  const hasPrev = showPrev && rows.some((r) => (r.prev ?? 0) > 0)
  return (
    <>
    {(nowLabel || hasPrev) && (
      <ul className="viz-legend rank-legend">
        {nowLabel && <li><i style={{ background: 'var(--viz-accent)' }} aria-hidden="true" />{nowLabel}</li>}
        {hasPrev && prevLabel && <li><i className="tick" aria-hidden="true" />{prevLabel}</li>}
        {rows.some((r) => r.weekly) && <li><i className="line" aria-hidden="true" />Weekly</li>}
      </ul>
    )}
    <ol className="rank">
      {rows.map((r) => (
        <li key={r.key}>
          <div className="rank-name">
            {r.href ? <Link to={r.href}>{r.name}</Link> : <span>{r.name}</span>}
            {r.sub && <span className="rank-sub">{r.sub}</span>}
          </div>
          <div className="rank-bar" role="img" aria-label={`${r.name}: ${r.value} ${unit}${showPrev && r.prev != null ? `, previous period ${r.prev}` : ''}`}>
            <i style={{ width: `${(r.value / max) * 100}%` }} />
            {showPrev && r.prev != null && r.prev > 0 && <b className="rank-prev" style={{ left: `${(r.prev / max) * 100}%` }} />}
          </div>
          <div className="rank-val">{r.value}</div>
          {r.weekly && <Sparkline values={r.weekly} partial={partialWeeks} label={`${r.name} weekly`} />}
          {r.extra}
        </li>
      ))}
    </ol>
    </>
  )
}

export interface MoveRow { key: string; name: string; sub: string; before: number; now: number; href?: string }

/** Before -> after per item (share of stories), on one shared 0..max axis. */
export function Dumbbells({ rows }: { rows: MoveRow[] }) {
  const max = niceMax(Math.max(1, ...rows.flatMap((r) => [r.before, r.now])))
  return (
    <ol className="dumb">
      {rows.map((r) => {
        const a = (r.before / max) * 100, b = (r.now / max) * 100
        const d = r.now - r.before
        return (
          <li key={r.key}>
            <div className="rank-name">
              {r.href ? <Link to={r.href}>{r.name}</Link> : <span>{r.name}</span>}
              <span className="rank-sub">{r.sub}</span>
            </div>
            <div className="dumb-track" role="img" aria-label={`${r.name}: ${r.before}% of stories before, ${r.now}% now`}>
              <span className="dumb-line" style={{ left: `${Math.min(a, b)}%`, width: `${Math.abs(b - a)}%` }} />
              <span className="dumb-dot before" style={{ left: `${a}%` }} />
              <span className="dumb-dot now" style={{ left: `${b}%` }} />
            </div>
            <div className="rank-val">{d > 0 ? '+' : '−'}{Math.abs(d).toFixed(1)} pts</div>
          </li>
        )
      })}
    </ol>
  )
}

/** The table view behind every chart. */
export function DataTable({ caption, head, rows }: { caption: string; head: string[]; rows: (string | number)[][] }) {
  const id = useId()
  return (
    <details className="disclose viz-table">
      <summary aria-controls={id}>Show as a table</summary>
      <div className="table-wrap" id={id}>
        <table className="simple">
          <caption className="sr-only">{caption}</caption>
          <thead><tr>{head.map((h) => <th key={h} scope="col">{h}</th>)}</tr></thead>
          <tbody>{rows.map((r, i) => <tr key={i}>{r.map((c, j) => j === 0 ? <th key={j} scope="row">{c}</th> : <td key={j}>{c}</td>)}</tr>)}</tbody>
        </table>
      </div>
    </details>
  )
}
