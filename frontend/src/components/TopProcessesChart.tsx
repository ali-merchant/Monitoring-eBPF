import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import type { TopProcess } from '../api/client'

interface Props { processes: TopProcess[] }

function CustomTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload as TopProcess
  return (
    <div style={{ background: '#1c1c1c', border: '1px solid #333', padding: '8px 12px', fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', borderRadius: 2 }}>
      <div style={{ color: '#e8e8e8', marginBottom: 4 }}>{d.process_name}</div>
      <div style={{ color: '#888' }}>Total: {d.event_count}</div>
      <div style={{ color: 'var(--chart-high)' }}>HIGH: {d.high_count}</div>
      <div style={{ color: 'var(--chart-med)' }}>MED: {d.med_count}</div>
      <div style={{ color: '#555' }}>PIDs: {d.pid_count}</div>
      <div style={{ color: '#555' }}>Types: {d.event_types.join(', ')}</div>
    </div>
  )
}

export default function TopProcessesChart({ processes }: Props) {
  return (
    <ResponsiveContainer width="100%" height={360}>
      <BarChart data={processes} layout="vertical" margin={{ top: 4, right: 8, left: 8, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#222" horizontal={false} />
        <XAxis type="number" tick={{ fill: '#666', fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis
          type="category"
          dataKey="process_name"
          tick={{ fill: '#888', fontSize: 11 }}
          tickLine={false}
          width={130}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: '#ffffff08' }} />
        <Bar dataKey="high_count" stackId="a" fill="var(--chart-high-r)" name="HIGH" radius={0} />
        <Bar dataKey="med_count" stackId="a" fill="var(--chart-1)" name="MED" radius={[0, 2, 2, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}
