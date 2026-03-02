import { useSSE } from './hooks/useSSE'
import { useData } from './hooks/useData'
import { api } from './api/client'

import StatCard from './components/StatCard'
import TimelineChart from './components/TimelineChart'
import TopProcessesChart from './components/TopProcessesChart'
import EventDistributionChart from './components/EventDistributionChart'
import RWXEventTable from './components/RWXEventTable'
import ProcessTree from './components/ProcessTree'
import LiveEventFeed from './components/LiveEventFeed'
import ModelResultsPanel from './components/ModelResultsPanel'

function fmtSpan(s: number) {
  const m = Math.floor(s / 60)
  const sec = Math.floor(s % 60)
  return m > 0 ? `${m}m ${sec}s` : `${sec}s`
}

export default function App() {
  const { connected, lastUpdated } = useSSE()

  const { data: summary }     = useData(['summary'],      api.summary)
  const { data: timeline }    = useData(['timeline'],     api.timeline)
  const { data: distribution} = useData(['distribution'], api.distribution)
  const { data: topProcs }    = useData(['topProcesses'], api.topProcesses)
  const { data: rwx }         = useData(['rwxEvents'],    api.rwxEvents)
  const { data: tree }        = useData(['processTree'],  api.processTree)
  const { data: feed }        = useData(['eventFeed'],    api.eventFeed)
  const { data: model }       = useData(['modelResults'], api.modelResults)

  return (
    <>
      {/* Header */}
      <header className="header">
        <span className="header-title">HIDS Monitor</span>
        <div className="status-pill">
          <span className={`status-dot${connected ? ' live' : ''}`} />
          {connected ? 'Live' : 'Disconnected'}
        </div>
        <span className="header-timestamp">
          {lastUpdated ? `Last updated: ${lastUpdated}` : 'Waiting for data...'}
        </span>
      </header>

      {/* Section 1 — Summary stat cards */}
      <section className="section">
        <div className="section-heading">Summary</div>
        <div className="bento-6">
          <StatCard value={summary?.total_events ?? '—'}          label="Total Events" />
          <StatCard value={summary?.high_severity_count ?? '—'}   label="HIGH Severity" />
          <StatCard value={summary?.med_severity_count ?? '—'}    label="MED Severity" />
          <StatCard value={summary?.unique_pids ?? '—'}           label="Unique PIDs" />
          <StatCard value={summary?.unique_processes ?? '—'}      label="Unique Processes" />
          <StatCard
            value={summary ? fmtSpan(summary.monitoring_span_seconds) : '—'}
            label="Monitoring Span"
          />
        </div>
      </section>

      {/* Section 2 — Timeline */}
      <section className="section">
        <div className="section-heading">Event Activity Timeline</div>
        <div className="panel">
          {timeline?.buckets?.length
            ? <TimelineChart buckets={timeline.buckets} />
            : <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: 16 }}>No data yet</div>
          }
        </div>
      </section>

      {/* Section 3 — Process activity (2-col bento) */}
      <section className="section">
        <div className="section-heading">Process Activity</div>
        <div className="bento-2">
          <div className="panel">
            <div className="panel-heading">Top Processes by Event Count</div>
            {topProcs?.processes?.length
              ? <TopProcessesChart processes={topProcs.processes} />
              : <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No data yet</div>
            }
          </div>
          <div className="panel">
            <div className="panel-heading">Event Type Distribution</div>
            {distribution?.distribution?.length
              ? <EventDistributionChart distribution={distribution.distribution} />
              : <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No data yet</div>
            }
          </div>
        </div>
      </section>

      {/* Section 4 — RWX memory events */}
      <section className="section">
        <div className="section-heading">RWX Memory Events</div>
        {rwx?.rwx_events?.length
          ? <RWXEventTable rwx_events={rwx.rwx_events} total={rwx.total} />
          : <div className="panel" style={{ color: 'var(--text-muted)', fontSize: 12 }}>No mmap_rwx events</div>
        }
      </section>

      {/* Section 5 — Process ancestry tree */}
      <section className="section">
        <div className="section-heading">Process Ancestry Tree</div>
        <div className="panel">
          {tree?.trees?.length
            ? <ProcessTree trees={tree.trees} />
            : <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No data yet</div>
          }
        </div>
      </section>

      {/* Section 6 — Anomaly detection model */}
      <section className="section">
        <div className="section-heading">Anomaly Detection Model</div>
        {model
          ? <ModelResultsPanel data={model} />
          : <div className="panel model-placeholder">Loading model results...</div>
        }
      </section>

      {/* Section 7 — Live event feed */}
      <section className="section">
        <div className="section-heading">Live Event Feed</div>
        <div className="panel">
          {feed?.events?.length
            ? <LiveEventFeed events={feed.events} />
            : <div style={{ color: 'var(--text-muted)', fontSize: 12 }}>No events yet</div>
          }
        </div>
      </section>
    </>
  )
}

