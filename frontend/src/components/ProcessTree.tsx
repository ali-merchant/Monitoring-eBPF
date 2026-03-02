import { useState } from 'react'
import type { TreeNode } from '../api/client'

interface NodeProps {
  node: TreeNode
  defaultOpen: boolean
}

function TreeNodeView({ node, defaultOpen }: NodeProps) {
  const [open, setOpen] = useState(defaultOpen)
  const hasChildren = node.children.length > 0

  return (
    <div className="tree-node">
      <div className="tree-row" onClick={() => hasChildren && setOpen(o => !o)}>
        <span className="tree-toggle">
          {hasChildren ? (open ? '▾' : '▸') : ' '}
        </span>
        <span className={`tree-label${node.has_high ? ' has-high' : ''}`}>
          {node.process_name}
        </span>
        <span className="tree-meta">PID {node.pid} · {node.event_count} events</span>
      </div>
      {open && hasChildren && (
        <div className="tree-children">
          {node.children.map(child => (
            <TreeNodeView key={child.pid} node={child} defaultOpen={false} />
          ))}
        </div>
      )}
    </div>
  )
}

interface Props { trees: TreeNode[] }

export default function ProcessTree({ trees }: Props) {
  return (
    <div>
      {trees.map((root, i) => (
        // Top 3 roots open by default so the busiest chains are visible immediately
        <TreeNodeView key={root.pid} node={root} defaultOpen={i < 3} />
      ))}
    </div>
  )
}
