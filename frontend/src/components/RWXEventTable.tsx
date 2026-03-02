import { useMemo } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer,
} from 'recharts'
import type { RWXEvent } from '../api/client'

interface Props { rwx_events: RWXEvent[]; total: number }

// Fixed palette for up to 6 distinct processes
const PROC_COLORS = [
  'var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)',
  'var(--chart-4)', 'var(--chart-5)', 'var(--chart-6)',
]

function fmtTime(iso: string) {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function RWXEventTable({ rwx_events }: Props) {
  // Build 10-second bucketed chart data
  const { chartData, colorMap } = useMemo(() => {
    const buckets: Record<string, { count: number; procs: Record<string, number> }> = {}
    for (const ev of rwx_events) {
      const t = Math.floor(new Date(ev.timestamp).getTime() / 10000) * 10000
      const key = new Date(t).toISOString()
      if (!buckets[key]) buckets[key] = { count: 0, procs: {} }
      buckets[key].count++
      buckets[key].procs[ev.process_name] = (buckets[key].procs[ev.process_name] || 0) + 1
    }

    const allProcs = Array.from(new Set(rwx_events.map(e => e.process_name)))
    const cm: Record<string, string> = {}
    allProcs.forEach((p, i) => { cm[p] = PROC_COLORS[i % PROC_COLORS.length] })

    const data = Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, v]) => {
        const dominant = Object.entries(v.procs).sort((a, b) => b[1] - a[1])[0]?.[0] ?? ''
        return { time: fmtTime(key), count: v.count, dominant }
      })

    return { chartData: data, colorMap: cm }
  }, [rwx_events])

  // Table: newest first
  const tableRows = [...rwx_events].reverse()

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '5fr 7fr', gap: 16 }}>
      {/* Left: RWX bar chart */}
      <div className="panel">
        <div className="panel-heading">RWX Events Over Time (10 s buckets)</div>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={chartData} margin={{ top: 4, right: 8, left: -10, bottom: 40 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
            <XAxis dataKey="time" tick={{ fill: '#666', fontSize: 10 }} tickLine={false} angle={-35} textAnchor="end" interval="preserveStartEnd" />
            <YAxis tick={{ fill: '#666', fontSize: 11 }} tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={{ background: '#1c1c1c', border: '1px solid #333', borderRadius: 2, fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', color: '#e8e8e8' }}
              formatter={(v, _n, p) => [v, `top: ${p.payload?.dominant}`]}
              labelStyle={{ color: '#888' }}
              itemStyle={{ color: '#e8e8e8' }}
            />
            <Bar dataKey="count" radius={[2, 2, 0, 0]}>
              {chartData.map((d, i) => (
                <Cell key={i} fill={colorMap[d.dominant] ?? 'var(--chart-1)'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Right: scrollable table */}
      <div className="panel">
        <div className="panel-heading">RWX Event Log</div>
        <div className="scrollable-table">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>PID</th>
                <th>PPID</th>
                <th>Process</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {tableRows.map((ev, i) => (
                <tr key={i}>
                  <td>{fmtTime(ev.timestamp)}</td>
                  <td>{ev.pid}</td>
                  <td>{ev.ppid}</td>
                  <td>{ev.process_name}</td>
                  <td style={{ maxWidth: 180 }}>{ev.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
