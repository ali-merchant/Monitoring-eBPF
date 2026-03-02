import StatCard from './StatCard'
import DonutChart from './DonutChart'
import AnomalyTimeline from './AnomalyTimeline'
import PerPIDTable from './PerPIDTable'
import type { ModelResultsResponse } from '../api/client'

const RISK_ORDER  = ['Low', 'Medium', 'High', 'Critical']
const RISK_COLORS = ['var(--chart-low)', 'var(--chart-medium)', 'var(--chart-high-r)', 'var(--chart-critical)']

const ACTION_ORDER  = ['Ignore', 'Log', 'Alert', 'Block']
const ACTION_COLORS = ['var(--chart-2)', 'var(--chart-1)', 'var(--chart-3)', 'var(--chart-critical)']

interface Props { data: ModelResultsResponse }

export default function ModelResultsPanel({ data }: Props) {
  if (!data.available) {
    return (
      <div className="panel model-placeholder">
        Run the notebook to see model results
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Metric cards */}
      <div className="bento-4">
        <StatCard value={`${data.accuracy}%`} label="Accuracy" />
        <StatCard value={`${data.precision}%`} label="Precision" />
        <StatCard value={`${data.recall}%`} label="Recall" />
        <StatCard value={`${data.f1}%`} label="F1 Score" />
      </div>

      {/* Donut charts */}
      <div className="bento-equal">
        <div className="panel">
          <div className="panel-heading">Risk Level Distribution</div>
          <DonutChart data={data.risk_distribution!} order={RISK_ORDER} colors={RISK_COLORS} />
        </div>
        <div className="panel">
          <div className="panel-heading">RL Action Distribution</div>
          <DonutChart data={data.action_distribution!} order={ACTION_ORDER} colors={ACTION_COLORS} />
        </div>
      </div>

      {/* Fuzzy score scatter */}
      <div className="panel">
        <div className="panel-heading">Fuzzy Score per PID</div>
        <AnomalyTimeline perPid={data.per_pid!} />
      </div>

      {/* Per-PID sortable/filterable table */}
      <div className="panel">
        <div className="panel-heading">Per-PID Results</div>
        <PerPIDTable rows={data.per_pid!} />
      </div>
    </div>
  )
}
