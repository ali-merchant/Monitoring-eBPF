import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer,
} from 'recharts'
import type { DistributionItem } from '../api/client'

interface Props { distribution: DistributionItem[] }

export default function EventDistributionChart({ distribution }: Props) {
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={distribution} margin={{ top: 4, right: 8, left: -10, bottom: 60 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
        <XAxis
          dataKey="event_name"
          tick={{ fill: '#666', fontSize: 10 }}
          tickLine={false}
          angle={-40}
          textAnchor="end"
          interval={0}
        />
        <YAxis tick={{ fill: '#666', fontSize: 11 }} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={{ background: '#1c1c1c', border: '1px solid #333', borderRadius: 2, fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', color: '#e8e8e8' }}
          labelStyle={{ color: '#888' }}
          itemStyle={{ color: '#e8e8e8' }}
          formatter={(v, _n, props) => [v, props.payload?.severity ?? '']}
        />
        <Bar dataKey="count" radius={[2, 2, 0, 0]}>
          {distribution.map((d, i) => (
            <Cell key={i} fill={d.severity === 'HIGH' ? 'var(--chart-high-r)' : 'var(--chart-1)'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
