import cytoscape from 'cytoscape'
import { useEffect, useRef, useState } from 'react'

type ResourceType = 'internet' | 'compute' | 'database'

type GraphNode = {
  id: string
  name: string
  type: ResourceType
  public: boolean
  sensitive: boolean
}

type GraphEdge = {
  source: string
  target: string
  protocol: string
  port: number
  reason: string
}

export type GraphData = {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

type GraphCanvasProps = {
  graph: GraphData
}

function GraphCanvas({ graph }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)

  useEffect(() => {
    if (!containerRef.current) {
      return
    }

    setSelectedNode(null)

    const instance = cytoscape({
      container: containerRef.current,
      elements: [
        ...graph.nodes.map((node) => ({ data: node })),
        ...graph.edges.map((edge, index) => ({
          data: { id: `edge-${index}`, ...edge },
        })),
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        direction: 'rightward',
        roots: graph.nodes
          .filter((node) => node.type === 'internet')
          .map((node) => node.id),
        padding: 32,
        spacingFactor: 1.35,
      },
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(name)',
            width: 52,
            height: 52,
            color: '#344054',
            'font-size': 12,
            'font-weight': 600,
            'text-valign': 'bottom',
            'text-margin-y': 10,
            'background-color': '#667085',
            'border-color': '#ffffff',
            'border-width': 3,
          },
        },
        {
          selector: 'node[type = "internet"]',
          style: { 'background-color': '#2f6fed' },
        },
        {
          selector: 'node[type = "compute"]',
          style: { 'background-color': '#7f56d9' },
        },
        {
          selector: 'node[type = "database"]',
          style: { 'background-color': '#039855' },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#172033',
            'border-width': 4,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#98a2b3',
            'target-arrow-color': '#667085',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
          },
        },
      ],
    })

    instance.on('tap', 'node', (event) => {
      const node = event.target
      setSelectedNode({
        id: node.id(),
        name: node.data('name'),
        type: node.data('type'),
        public: node.data('public'),
        sensitive: node.data('sensitive'),
      })
    })

    return () => instance.destroy()
  }, [graph])

  return (
    <div className="graph-content">
      <div
        ref={containerRef}
        className="graph-canvas"
        aria-label="Interactive cloud infrastructure graph"
      />

      <div className="node-details" aria-live="polite">
        {selectedNode ? (
          <>
            <h3>{selectedNode.name}</h3>
            <dl>
              <div>
                <dt>Resource type</dt>
                <dd>{selectedNode.type}</dd>
              </div>
              <div>
                <dt>Public</dt>
                <dd>{selectedNode.public ? 'Yes' : 'No'}</dd>
              </div>
              <div>
                <dt>Sensitive</dt>
                <dd>{selectedNode.sensitive ? 'Yes' : 'No'}</dd>
              </div>
            </dl>
          </>
        ) : (
          <p>Select a node to inspect its resource details.</p>
        )}
      </div>
    </div>
  )
}

export default GraphCanvas
