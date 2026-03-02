/** Typed fetch wrappers for all backend endpoints. */

export interface Summary {
  total_events: number
  high_severity_count: number
  med_severity_count: number
  unique_pids: number
  unique_processes: number
  monitoring_span_seconds: number
  last_updated: string
}

export interface TimelineBucket {
  time: string
  HIGH: number
  MED: number
}

export interface TimelineResponse {
  buckets: TimelineBucket[]
}

export interface DistributionItem {
  event_name: string
  count: number
  severity: string
}

export interface DistributionResponse {
  distribution: DistributionItem[]
}

export interface TopProcess {
  process_name: string
  pid_count: number
  event_count: number
  high_count: number
  med_count: number
  event_types: string[]
}

export interface TopProcessesResponse {
  processes: TopProcess[]
}

export interface RWXEvent {
  timestamp: string
  pid: number
  ppid: number
  process_name: string
  detail: string
}

export interface RWXEventsResponse {
  rwx_events: RWXEvent[]
  total: number
}

export interface TreeNode {
  pid: number
  process_name: string
  event_count: number
  has_high: boolean
  children: TreeNode[]
}

export interface ProcessTreeResponse {
  trees: TreeNode[]
}

export interface PerPIDResult {
  pid: number
  process: string
  risk_level: string
  fuzzy_score: number
  rl_action: string
  expected_action: string
  correct: boolean
  confidence: number
  baseline: string
}

export interface ModelResultsResponse {
  available: boolean
  accuracy?: number
  precision?: number
  recall?: number
  f1?: number
  risk_distribution?: Record<string, number>
  action_distribution?: Record<string, number>
  per_pid?: PerPIDResult[]
}

export interface FeedEvent {
  timestamp: string
  pid: number
  process_name: string
  event_name: string
  severity: string
  detail: string
}

export interface EventFeedResponse {
  events: FeedEvent[]
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path)
  if (!res.ok) throw new Error(`${path} → ${res.status}`)
  return res.json()
}

export const api = {
  summary: () => get<Summary>('/api/summary'),
  timeline: (bucket = 5) => get<TimelineResponse>(`/api/events/timeline?bucket=${bucket}`),
  distribution: () => get<DistributionResponse>('/api/events/distribution'),
  topProcesses: (n = 15) => get<TopProcessesResponse>(`/api/processes/top?n=${n}`),
  rwxEvents: () => get<RWXEventsResponse>('/api/events/rwx'),
  processTree: () => get<ProcessTreeResponse>('/api/processes/tree'),
  modelResults: () => get<ModelResultsResponse>('/api/model/results'),
  eventFeed: () => get<EventFeedResponse>('/api/events/feed'),
}
