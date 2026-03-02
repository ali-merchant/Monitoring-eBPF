import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import type { TimelineBucket } from '../api/client'

interface Props { buckets: TimelineBucket[] }

function fmtTime(iso: string) {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function TimelineChart({ buckets }: Props) {
  const data = buckets.map(b => ({ ...b, time: fmtTime(b.time) }))

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={data} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#222" />
        <XAxis dataKey="time" tick={{ fill: '#666', fontSize: 11 }} tickLine={false} interval="preserveStartEnd" />
        <YAxis tick={{ fill: '#666', fontSize: 11 }} tickLine={false} axisLine={false} />
        <Tooltip
          contentStyle={{ background: '#1c1c1c', border: '1px solid #333', borderRadius: 2, fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', color: '#e8e8e8' }}
          labelStyle={{ color: '#888' }}
          itemStyle={{ color: '#e8e8e8' }}
        />
        {/* MED underneath, HIGH on top so bursts in HIGH are visually dominant */}
        <Area type="monotone" dataKey="MED" stackId="1" stroke="var(--chart-med)" fill="var(--chart-med)" fillOpacity={0.4} />
        <Area type="monotone" dataKey="HIGH" stackId="1" stroke="var(--chart-high)" fill="var(--chart-high)" fillOpacity={0.5} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
