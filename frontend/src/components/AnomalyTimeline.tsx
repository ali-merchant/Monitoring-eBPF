import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip,
  ReferenceLine, ResponsiveContainer, Cell,
} from 'recharts'
import type { PerPIDResult } from '../api/client'

interface Props { perPid: PerPIDResult[] }

const RISK_COLORS: Record<string, string> = {
  Low:      'var(--chart-low)',
  Medium:   'var(--chart-medium)',
  High:     'var(--chart-high-r)',
  Critical: 'var(--chart-critical)',
}

function CustomTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload as PerPIDResult & { index: number }
  return (
    <div style={{ background: '#1c1c1c', border: '1px solid #333', padding: '8px 12px', fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', borderRadius: 2 }}>
      <div style={{ color: '#e8e8e8' }}>{d.process}</div>
      <div style={{ color: '#888' }}>PID {d.pid}</div>
      <div style={{ color: '#888' }}>Score: {d.fuzzy_score}</div>
      <div style={{ color: RISK_COLORS[d.risk_level] }}>{d.risk_level}</div>
      <div style={{ color: '#555' }}>{d.rl_action} · {d.confidence.toFixed(0)}% conf</div>
    </div>
  )
}

// Threshold labels placed at the left edge as reference line labels
const THRESHOLDS = [
  { y: 20, label: 'Low' },
  { y: 40, label: 'Medium' },
  { y: 60, label: 'High' },
]

export default function AnomalyTimeline({ perPid }: Props) {
  const data = perPid.map((p, i) => ({ ...p, index: i }))

  return (
    <ResponsiveContainer width="100%" height={260}>
      <ScatterChart margin={{ top: 8, right: 16, left: -10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#222" />
        <XAxis
          type="number"
          dataKey="index"
          name="PID index"
          tick={{ fill: '#666', fontSize: 11 }}
          tickLine={false}
          label={{ value: 'PID index', position: 'insideBottomRight', offset: -4, fill: '#555', fontSize: 10 }}
        />
        <YAxis
          type="number"
          dataKey="fuzzy_score"
          domain={[0, 100]}
          tick={{ fill: '#666', fontSize: 11 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ strokeDasharray: '3 3', stroke: '#444' }} />
        {THRESHOLDS.map(t => (
          <ReferenceLine
            key={t.y}
            y={t.y}
            stroke="#333"
            strokeDasharray="4 2"
            label={{ value: t.label, position: 'insideLeft', fill: '#555', fontSize: 10 }}
          />
        ))}
        <Scatter data={data} name="PIDs">
          {data.map((d, i) => (
            <Cell key={i} fill={RISK_COLORS[d.risk_level] ?? '#888'} />
          ))}
        </Scatter>
      </ScatterChart>
    </ResponsiveContainer>
  )
}
