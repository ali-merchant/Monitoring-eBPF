interface Props {
  value: string | number
  label: string
}

export default function StatCard({ value, label }: Props) {
  return (
    <div className="panel stat-card">
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  )
}
