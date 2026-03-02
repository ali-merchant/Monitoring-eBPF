import { useState, useMemo } from 'react'
import type { PerPIDResult } from '../api/client'

interface Props { rows: PerPIDResult[] }

type SortKey = keyof PerPIDResult
type Dir = 'asc' | 'desc'

export default function PerPIDTable({ rows }: Props) {
  const [filter, setFilter] = useState('')
  const [sort, setSort] = useState<{ key: SortKey; dir: Dir }>({ key: 'fuzzy_score', dir: 'desc' })

  const displayed = useMemo(() => {
    let data = filter
      ? rows.filter(r => r.process.toLowerCase().includes(filter.toLowerCase()))
      : rows

    data = [...data].sort((a, b) => {
      const av = a[sort.key]
      const bv = b[sort.key]
      const cmp = av < bv ? -1 : av > bv ? 1 : 0
      return sort.dir === 'asc' ? cmp : -cmp
    })
    return data
  }, [rows, filter, sort])

  function toggleSort(key: SortKey) {
    setSort(prev => prev.key === key
      ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
      : { key, dir: 'desc' }
    )
  }

  function arrow(key: SortKey) {
    if (sort.key !== key) return ''
    return sort.dir === 'asc' ? ' ↑' : ' ↓'
  }

  return (
    <div>
      <input
        className="filter-input"
        type="text"
        placeholder="Filter by process name..."
        value={filter}
        onChange={e => setFilter(e.target.value)}
      />
      <div className="scrollable-table" style={{ maxHeight: 400 }}>
        <table>
          <thead>
            <tr>
              {([ ['process','Process'], ['pid','PID'], ['risk_level','Risk'], ['fuzzy_score','Score'],
                  ['rl_action','RL Action'], ['expected_action','Expected'], ['correct','Match'],
                  ['confidence','Confidence'], ['baseline','Baseline'] ] as [SortKey, string][])
                .map(([key, label]) => (
                  <th key={key} onClick={() => toggleSort(key)}>{label}{arrow(key)}</th>
                ))}
            </tr>
          </thead>
          <tbody>
            {displayed.map((r, i) => (
              <tr key={i}>
                <td>{r.process}</td>
                <td>{r.pid}</td>
                <td>{r.risk_level}</td>
                <td>{r.fuzzy_score}</td>
                <td>{r.rl_action}</td>
                <td>{r.expected_action}</td>
                {/* Plain text check/cross — no color per spec */}
                <td>{r.correct ? '✓' : '✗'}</td>
                <td>{r.confidence.toFixed(1)}%</td>
                <td>{r.baseline}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
