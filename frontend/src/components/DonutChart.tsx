import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'

interface Props {
  data: Record<string, number>
  // ordered list of segment keys to ensure consistent color assignment
  order: string[]
  colors: string[]
}

function renderLabel({ cx, cy, midAngle, innerRadius, outerRadius, name, percent }: any) {
  const RADIAN = Math.PI / 180
  const r = innerRadius + (outerRadius - innerRadius) * 1.45
  const x = cx + r * Math.cos(-midAngle * RADIAN)
  const y = cy + r * Math.sin(-midAngle * RADIAN)
  if (percent < 0.04) return null   // skip tiny slices to avoid label overlap
  return (
    <text x={x} y={y} fill="#888" textAnchor={x > cx ? 'start' : 'end'} fontSize={10} fontFamily="IBM Plex Mono, monospace">
      {name} {(percent * 100).toFixed(0)}%
    </text>
  )
}

export default function DonutChart({ data, order, colors }: Props) {
  const chartData = order
    .filter(k => data[k] != null)
    .map((k, i) => ({ name: k, value: data[k], color: colors[i % colors.length] }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={80}
          dataKey="value"
          labelLine={false}
          label={renderLabel}
        >
          {chartData.map((d, i) => (
            <Cell key={i} fill={d.color} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: '#1c1c1c', border: '1px solid #333', borderRadius: 2, fontSize: 12, fontFamily: 'IBM Plex Mono, monospace', color: '#e8e8e8' }}
          labelStyle={{ color: '#888' }}
          itemStyle={{ color: '#e8e8e8' }}
          formatter={(v: number, name: string) => {
            const total = chartData.reduce((s, d) => s + d.value, 0)
            return [`${v} (${((v / total) * 100).toFixed(1)}%)`, name]
          }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}
