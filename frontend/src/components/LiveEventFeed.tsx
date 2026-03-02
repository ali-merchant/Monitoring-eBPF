import type { FeedEvent } from '../api/client'

interface Props { events: FeedEvent[] }

function fmtTime(iso: string) {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function LiveEventFeed({ events }: Props) {
  return (
    <div className="feed-container">
      {events.map((ev, i) => (
        <div className="feed-row" key={i}>
          <span className="feed-time">[{fmtTime(ev.timestamp)}]</span>
          <span className="feed-badge">[{ev.severity}]</span>
          <span className="feed-pid">PID {ev.pid}</span>
          <span className="feed-proc">{ev.process_name}</span>
          <span className="feed-event">{ev.event_name}</span>
          <span className="feed-detail">{ev.detail}</span>
        </div>
      ))}
    </div>
  )
}
