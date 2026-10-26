import cytoscape, { type Core } from 'cytoscape'
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

export type ScanEvent =
  | { type: 'scan_started' }
  | { type: 'node_visited'; node_id: string }
  | { type: 'edge_traversed'; source: string; target: string }
  | {
      type: 'finding_detected'
      resource: string
      severity: 'high' | 'critical'
    }
  | { type: 'path_found'; path: string[] }
  | { type: 'scan_completed' }

type GraphCanvasProps = {
  graph: GraphData
  scanEvent: ScanEvent | null
  selectedResourceId: string | null
  attackPath: string[] | null
  attackPathStep: number
}

function GraphCanvas({
  graph,
  scanEvent,
  selectedResourceId,
  attackPath,
  attackPathStep,
}: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const instanceRef = useRef<Core | null>(null)
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
          selector: 'node.scan-visited',
          style: { opacity: 0.65 },
        },
        {
          selector: 'node.scan-current',
          style: {
            opacity: 1,
            'border-color': '#fdb022',
            'border-width': 5,
          },
        },
        {
          selector: 'node.scan-vulnerable',
          style: {
            opacity: 1,
            'border-color': '#d92d20',
            'border-width': 5,
          },
        },
        {
          selector: 'node.result-selected',
          style: {
            'underlay-color': '#2f6fed',
            'underlay-opacity': 0.3,
            'underlay-padding': 10,
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
        {
          selector: 'edge.scan-explored',
          style: {
            width: 4,
            'line-color': '#2f6fed',
            'target-arrow-color': '#2f6fed',
          },
        },
        {
          selector: 'node.attack-path-dimmed',
          style: { opacity: 0.22 },
        },
        {
          selector: 'edge.attack-path-dimmed',
          style: { opacity: 0.18 },
        },
        {
          selector: 'node.attack-path-current',
          style: {
            opacity: 1,
            'border-color': '#fdb022',
            'border-width': 6,
          },
        },
        {
          selector: 'node.attack-path-completed',
          style: {
            opacity: 1,
            'border-color': '#d92d20',
            'border-width': 5,
          },
        },
        {
          selector: 'node.attack-path-destination',
          style: {
            opacity: 1,
            'border-color': '#d92d20',
            'border-width': 6,
            'underlay-color': '#d92d20',
            'underlay-opacity': 0.2,
            'underlay-padding': 10,
          },
        },
        {
          selector: 'edge.attack-path-traversed',
          style: {
            opacity: 1,
            width: 5,
            'line-color': '#d92d20',
            'target-arrow-color': '#d92d20',
          },
        },
      ],
    })

    instanceRef.current = instance

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

    return () => {
      instanceRef.current = null
      instance.destroy()
    }
  }, [graph])

  useEffect(() => {
    const instance = instanceRef.current
    if (!instance) {
      return
    }

    if (!scanEvent || scanEvent.type === 'scan_started') {
      instance
        .elements()
        .removeClass(
          'scan-current scan-visited scan-explored scan-vulnerable',
        )
      return
    }

    switch (scanEvent.type) {
      case 'node_visited': {
        instance
          .nodes('.scan-current')
          .removeClass('scan-current')
          .addClass('scan-visited')
        instance
          .getElementById(scanEvent.node_id)
          .removeClass('scan-visited')
          .addClass('scan-current')
        break
      }
      case 'edge_traversed':
        instance
          .edges()
          .filter(
            (edge) =>
              edge.data('source') === scanEvent.source &&
              edge.data('target') === scanEvent.target,
          )
          .addClass('scan-explored')
        break
      case 'finding_detected':
        instance
          .getElementById(scanEvent.resource)
          .addClass('scan-vulnerable')
        break
      case 'scan_completed':
        instance
          .nodes('.scan-current')
          .removeClass('scan-current')
          .addClass('scan-visited')
        break
      case 'path_found':
        break
    }
  }, [scanEvent])

  useEffect(() => {
    const instance = instanceRef.current
    if (!instance) {
      return
    }

    instance.nodes().removeClass('result-selected')
    if (selectedResourceId) {
      instance.getElementById(selectedResourceId).addClass('result-selected')
    }
  }, [graph, selectedResourceId])

  useEffect(() => {
    const instance = instanceRef.current
    if (!instance) {
      return
    }

    instance
      .elements()
      .removeClass(
        'attack-path-dimmed attack-path-current attack-path-completed attack-path-destination attack-path-traversed',
      )

    if (!attackPath || attackPathStep < 0) {
      return
    }

    instance.elements().addClass('attack-path-dimmed')

    const completionStep = attackPath.length * 2 - 1
    const isComplete = attackPathStep >= completionStep
    const currentNodeIndex = Math.floor(attackPathStep / 2)
    const visibleNodeCount = isComplete
      ? attackPath.length
      : currentNodeIndex + 1
    const traversedEdgeCount = isComplete
      ? attackPath.length - 1
      : Math.ceil(attackPathStep / 2)

    attackPath.slice(0, visibleNodeCount).forEach((nodeId, index) => {
      instance
        .getElementById(nodeId)
        .removeClass('attack-path-dimmed')
        .addClass(
          isComplete || index < currentNodeIndex
            ? 'attack-path-completed'
            : 'attack-path-current',
        )
    })

    for (let index = 0; index < traversedEdgeCount; index += 1) {
      instance
        .edges()
        .filter(
          (edge) =>
            edge.data('source') === attackPath[index] &&
            edge.data('target') === attackPath[index + 1],
        )
        .removeClass('attack-path-dimmed')
        .addClass('attack-path-traversed')
    }

    if (isComplete) {
      instance
        .getElementById(attackPath[attackPath.length - 1])
        .addClass('attack-path-destination')
    }
  }, [attackPath, attackPathStep, graph])

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
