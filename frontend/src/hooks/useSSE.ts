/** SSE connection with exponential-backoff reconnect and query invalidation. */
import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'

const LOG_QUERY_KEYS = [
  ['summary'], ['timeline'], ['distribution'], ['topProcesses'],
  ['rwxEvents'], ['eventFeed'], ['processTree'],
]

export function useSSE() {
  const queryClient = useQueryClient()
  const [connected, setConnected] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<string | null>(null)
  const retryDelay = useRef(1000)
  const es = useRef<EventSource | null>(null)

  useEffect(() => {
    let cancelled = false

    function connect() {
      if (cancelled) return
      es.current?.close()
      const source = new EventSource('/api/stream')
      es.current = source

      source.onopen = () => {
        setConnected(true)
        retryDelay.current = 1000   // reset backoff on successful connection
      }

      source.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          setLastUpdated(new Date().toLocaleTimeString())
          if (msg.type === 'log_updated') {
            LOG_QUERY_KEYS.forEach(k => queryClient.invalidateQueries({ queryKey: k }))
          } else if (msg.type === 'model_updated') {
            queryClient.invalidateQueries({ queryKey: ['modelResults'] })
          }
        } catch { /* ignore malformed messages */ }
      }

      source.onerror = () => {
        setConnected(false)
        source.close()
        if (!cancelled) {
          setTimeout(connect, retryDelay.current)
          retryDelay.current = Math.min(retryDelay.current * 2, 30000)
        }
      }
    }

    connect()
    return () => {
      cancelled = true
      es.current?.close()
    }
  }, [queryClient])

  return { connected, lastUpdated }
}
