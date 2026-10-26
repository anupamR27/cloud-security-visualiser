import { useEffect, useRef, useState, type ChangeEvent } from 'react'
import GraphCanvas, { type GraphData, type ScanEvent } from './GraphCanvas'

type Scenario = 'secure' | 'vulnerable'
type ScanStatus = 'idle' | 'loading' | 'scanning' | 'completed' | 'error'

type ScanResponse = {
  events: ScanEvent[]
}

const SCAN_EVENT_DELAY_MS = 500

function describeScanEvent(event: ScanEvent | null): string {
  if (!event) {
    return 'Scanning infrastructure.'
  }

  switch (event.type) {
    case 'scan_started':
      return 'Starting infrastructure scan.'
    case 'node_visited':
      return `Inspecting resource ${event.node_id}.`
    case 'edge_traversed':
      return `Checking connection from ${event.source} to ${event.target}.`
    case 'finding_detected':
      return `Security finding detected on ${event.resource}.`
    case 'path_found':
      return `Potential path discovered: ${event.path.join(' → ')}.`
    case 'scan_completed':
      return 'Scan Complete'
  }
}

function App() {
  const [selectedScenario, setSelectedScenario] = useState<Scenario>('secure')
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [graphError, setGraphError] = useState('')
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
  const [scanResponse, setScanResponse] = useState<ScanResponse | null>(null)
  const [currentEventIndex, setCurrentEventIndex] = useState(-1)
  const [scanError, setScanError] = useState('')
  const scanControllerRef = useRef<AbortController | null>(null)

  const currentScanEvent =
    scanResponse?.events[currentEventIndex] ?? null

  useEffect(() => {
    const controller = new AbortController()
    let cancelled = false

    async function loadGraph() {
      setGraph(null)
      setGraphError('')

      try {
        const response = await fetch(`/api/scenarios/${selectedScenario}`, {
          signal: controller.signal,
        })

        if (!response.ok) {
          throw new Error('The infrastructure graph could not be loaded.')
        }

        const graphData: GraphData = await response.json()
        if (!cancelled) {
          setGraph(graphData)
        }
      } catch (error) {
        if (!cancelled) {
          setGraphError(
            error instanceof Error
              ? error.message
              : 'The infrastructure graph could not be loaded.',
          )
        }
      }
    }

    void loadGraph()

    return () => {
      cancelled = true
      controller.abort()
      scanControllerRef.current?.abort()
    }
  }, [selectedScenario])

  useEffect(() => {
    if (
      scanStatus !== 'scanning' ||
      !scanResponse ||
      currentEventIndex < 0
    ) {
      return
    }

    const event = scanResponse.events[currentEventIndex]
    if (!event || event.type === 'scan_completed') {
      setScanStatus('completed')
      return
    }

    const timer = window.setTimeout(() => {
      setCurrentEventIndex((index) => index + 1)
    }, SCAN_EVENT_DELAY_MS)

    return () => window.clearTimeout(timer)
  }, [currentEventIndex, scanResponse, scanStatus])

  function handleScenarioChange(event: ChangeEvent<HTMLSelectElement>) {
    scanControllerRef.current?.abort()
    setScanStatus('idle')
    setScanResponse(null)
    setCurrentEventIndex(-1)
    setScanError('')
    setSelectedScenario(event.target.value as Scenario)
  }

  async function handleStartScan() {
    if (!graph || scanStatus === 'loading' || scanStatus === 'scanning') {
      return
    }

    const controller = new AbortController()
    scanControllerRef.current?.abort()
    scanControllerRef.current = controller
    setScanStatus('loading')
    setScanResponse(null)
    setCurrentEventIndex(-1)
    setScanError('')

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: selectedScenario }),
        signal: controller.signal,
      })

      if (!response.ok) {
        throw new Error('The security scan could not be started.')
      }

      const result: ScanResponse = await response.json()
      if (controller.signal.aborted) {
        return
      }

      setScanResponse(result)
      if (result.events.length === 0) {
        setScanStatus('completed')
      } else {
        setCurrentEventIndex(0)
        setScanStatus('scanning')
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        setScanStatus('error')
        setScanError(
          error instanceof Error
            ? error.message
            : 'The security scan could not be started.',
        )
      }
    } finally {
      if (scanControllerRef.current === controller) {
        scanControllerRef.current = null
      }
    }
  }

  let scanMessage = graph
    ? 'Ready to scan the selected infrastructure.'
    : 'The graph must load before scanning.'
  let scanButtonLabel = 'Start Scan'
  let resultsStatusLabel = 'Awaiting scan'

  if (scanStatus === 'loading') {
    scanMessage = 'Preparing scan...'
    scanButtonLabel = 'Preparing scan...'
    resultsStatusLabel = 'Scan running'
  } else if (scanStatus === 'scanning') {
    scanMessage = describeScanEvent(currentScanEvent)
    scanButtonLabel = 'Scanning...'
    resultsStatusLabel = 'Scan running'
  } else if (scanStatus === 'completed') {
    scanMessage = 'Scan Complete'
    resultsStatusLabel = 'Scan complete'
  } else if (scanStatus === 'error') {
    scanMessage = scanError
    resultsStatusLabel = 'Scan failed'
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-content">
          <p className="eyebrow">Infrastructure risk analysis</p>
          <h1>Cloud Security Visualiser</h1>
          <p className="app-description">
            Explore cloud infrastructure and understand how network exposure can
            create security risks.
          </p>
        </div>
      </header>

      <main className="dashboard">
        <section className="panel scenario-panel" aria-labelledby="scenario-title">
          <div>
            <p className="section-label">Scenario</p>
            <h2 id="scenario-title">Choose an environment</h2>
            <p className="section-description">
              Select a predefined cloud configuration to inspect.
            </p>
          </div>

          <div className="scenario-controls">
            <label htmlFor="scenario-select">Infrastructure scenario</label>
            <select
              id="scenario-select"
              value={selectedScenario}
              onChange={handleScenarioChange}
            >
              <option value="secure">Secure</option>
              <option value="vulnerable">Vulnerable</option>
            </select>
            <p className="current-scenario" aria-live="polite">
              Selected scenario: <strong>{selectedScenario}</strong>
            </p>
            <button
              type="button"
              disabled={
                !graph || scanStatus === 'loading' || scanStatus === 'scanning'
              }
              onClick={handleStartScan}
            >
              {scanButtonLabel}
            </button>
            <p
              className={`button-note${scanStatus === 'error' ? ' scan-error' : ''}`}
              aria-live="polite"
            >
              {scanMessage}
            </p>
          </div>
        </section>

        <section className="panel graph-panel" aria-labelledby="graph-title">
          <div className="section-heading">
            <div>
              <p className="section-label">Infrastructure</p>
              <h2 id="graph-title">Infrastructure Graph</h2>
            </div>
            <span className="status-badge">
              {graphError ? 'Unavailable' : graph ? 'Interactive' : 'Loading'}
            </span>
          </div>
          {graphError ? (
            <div className="placeholder graph-message" role="alert">
              <h3>Unable to load infrastructure</h3>
              <p>{graphError} Check that the FastAPI server is running.</p>
            </div>
          ) : graph ? (
            <GraphCanvas graph={graph} scanEvent={currentScanEvent} />
          ) : (
            <div className="placeholder graph-message" aria-live="polite">
              <h3>Loading infrastructure…</h3>
              <p>Fetching resources and network connections.</p>
            </div>
          )}
        </section>

        <section className="panel results-panel" aria-labelledby="results-title">
          <div className="section-heading">
            <div>
              <p className="section-label">Analysis</p>
              <h2 id="results-title">Scan Results</h2>
            </div>
            <span className="status-badge">{resultsStatusLabel}</span>
          </div>
          <div className="placeholder results-placeholder">
            <h3>No scan results yet</h3>
            <p>
              Security findings and potential attack paths will appear here after
              scanning.
            </p>
          </div>
        </section>
      </main>
    </div>
  )
}

export default App

