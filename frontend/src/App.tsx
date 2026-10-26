import { useEffect, useRef, useState, type ChangeEvent } from 'react'
import GraphCanvas, { type GraphData, type ScanEvent } from './GraphCanvas'

type Scenario = 'secure' | 'vulnerable' | 'custom'
type ScanStatus = 'idle' | 'loading' | 'scanning' | 'completed' | 'error'

type CustomScenario = {
  id: string
  name: string
  description: string
  nodes: GraphData['nodes']
  edges: GraphData['edges']
}

type ScanSummary = {
  total_resources: number
  total_findings: number
  high: number
  critical: number
  attack_paths: number
}

type SecurityFinding = {
  resource: string
  severity: 'high' | 'critical'
  explanation: string
  remediation: string
}

type ScanResponse = {
  summary: ScanSummary
  findings: SecurityFinding[]
  attack_paths: string[][]
  events: ScanEvent[]
}

const SCAN_EVENT_DELAY_MS = 500
const ATTACK_PATH_DELAY_MS = 700

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

function getResourceName(graph: GraphData | null, resourceId: string): string {
  return graph?.nodes.find((node) => node.id === resourceId)?.name ?? resourceId
}

function describeValidationError(responseBody: unknown): string {
  if (
    !responseBody ||
    typeof responseBody !== 'object' ||
    !('detail' in responseBody) ||
    !Array.isArray(responseBody.detail)
  ) {
    return 'The infrastructure configuration is invalid.'
  }

  const messages = responseBody.detail.flatMap((issue) => {
    if (!issue || typeof issue !== 'object' || !('msg' in issue)) {
      return []
    }

    const message = String(issue.msg)
    const location =
      'loc' in issue && Array.isArray(issue.loc)
        ? issue.loc.filter((part: unknown) => part !== 'body').join('.')
        : ''

    return [location ? `${location}: ${message}` : message]
  })

  return messages.length > 0
    ? `Invalid infrastructure configuration: ${messages.join(' ')}`
    : 'The infrastructure configuration is invalid.'
}

function App() {
  const [selectedScenario, setSelectedScenario] = useState<Scenario>('secure')
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [graphError, setGraphError] = useState('')
  const [uploadedFilename, setUploadedFilename] = useState('')
  const [customScenario, setCustomScenario] = useState<CustomScenario | null>(
    null,
  )
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
  const [scanResponse, setScanResponse] = useState<ScanResponse | null>(null)
  const [currentEventIndex, setCurrentEventIndex] = useState(-1)
  const [scanError, setScanError] = useState('')
  const [selectedFindingResource, setSelectedFindingResource] = useState<
    string | null
  >(null)
  const [selectedAttackPath, setSelectedAttackPath] = useState<string[] | null>(
    null,
  )
  const [attackPathStep, setAttackPathStep] = useState(-1)
  const [isAttackPathPlaying, setIsAttackPathPlaying] = useState(false)
  const graphControllerRef = useRef<AbortController | null>(null)
  const graphRequestVersionRef = useRef(0)
  const scanControllerRef = useRef<AbortController | null>(null)

  const currentScanEvent =
    scanResponse?.events[currentEventIndex] ?? null

  useEffect(() => {
    if (selectedScenario === 'custom') {
      return
    }

    const controller = new AbortController()
    const requestVersion = graphRequestVersionRef.current
    graphControllerRef.current = controller

    async function loadGraph() {
      try {
        const response = await fetch(`/api/scenarios/${selectedScenario}`, {
          signal: controller.signal,
        })

        if (!response.ok) {
          throw new Error('The infrastructure graph could not be loaded.')
        }

        const graphData: GraphData = await response.json()
        if (
          !controller.signal.aborted &&
          graphRequestVersionRef.current === requestVersion
        ) {
          setGraph(graphData)
        }
      } catch (error) {
        if (
          !controller.signal.aborted &&
          graphRequestVersionRef.current === requestVersion
        ) {
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
      controller.abort()
      if (graphControllerRef.current === controller) {
        graphControllerRef.current = null
      }
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

  useEffect(() => {
    if (!isAttackPathPlaying || !selectedAttackPath) {
      return
    }

    const timer = window.setTimeout(() => {
      const finalNodeStep = selectedAttackPath.length * 2 - 2
      if (attackPathStep >= finalNodeStep) {
        setAttackPathStep(finalNodeStep + 1)
        setIsAttackPathPlaying(false)
      } else {
        setAttackPathStep((step) => step + 1)
      }
    }, ATTACK_PATH_DELAY_MS)

    return () => window.clearTimeout(timer)
  }, [attackPathStep, isAttackPathPlaying, selectedAttackPath])

  function clearAttackPathPlayback() {
    setSelectedAttackPath(null)
    setAttackPathStep(-1)
    setIsAttackPathPlaying(false)
  }

  function clearAnalysisState() {
    scanControllerRef.current?.abort()
    scanControllerRef.current = null
    setScanStatus('idle')
    setScanResponse(null)
    setCurrentEventIndex(-1)
    setScanError('')
    setSelectedFindingResource(null)
    clearAttackPathPlayback()
  }

  function clearSelectedInput() {
    graphRequestVersionRef.current += 1
    graphControllerRef.current?.abort()
    graphControllerRef.current = null
    setGraph(null)
    setGraphError('')
    setUploadedFilename('')
    setCustomScenario(null)
    clearAnalysisState()
  }

  function handleScenarioChange(event: ChangeEvent<HTMLSelectElement>) {
    clearSelectedInput()
    setSelectedScenario(event.target.value as Scenario)
  }

  async function handleFileUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (!file) {
      return
    }

    clearSelectedInput()
    const requestVersion = graphRequestVersionRef.current
    setUploadedFilename(file.name)

    if (!file.name.toLowerCase().endsWith('.json')) {
      setGraphError('Choose a file with a .json extension.')
      return
    }

    let parsedScenario: unknown
    try {
      parsedScenario = JSON.parse(await file.text())
    } catch (error) {
      if (graphRequestVersionRef.current !== requestVersion) {
        return
      }

      setGraphError(
        error instanceof SyntaxError
          ? `${file.name} contains malformed JSON. Check its syntax and try again.`
          : `${file.name} could not be read. Choose the file again.`,
      )
      return
    }

    if (graphRequestVersionRef.current !== requestVersion) {
      return
    }

    const controller = new AbortController()
    graphControllerRef.current = controller

    try {
      const response = await fetch('/api/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsedScenario),
        signal: controller.signal,
      })

      if (!response.ok) {
        if (response.status === 422) {
          throw new Error(describeValidationError(await response.json()))
        }
        throw new Error(
          'The infrastructure configuration could not be validated. Check that the FastAPI server is running.',
        )
      }

      const validatedGraph: GraphData = await response.json()
      if (
        controller.signal.aborted ||
        graphRequestVersionRef.current !== requestVersion
      ) {
        return
      }

      setCustomScenario({
        ...(parsedScenario as CustomScenario),
        nodes: validatedGraph.nodes,
        edges: validatedGraph.edges,
      })
      setGraph(validatedGraph)
    } catch (error) {
      if (
        !controller.signal.aborted &&
        graphRequestVersionRef.current === requestVersion
      ) {
        const isValidationMessage =
          error instanceof Error &&
          (error.message.startsWith('Invalid infrastructure configuration:') ||
            error.message === 'The infrastructure configuration is invalid.' ||
            error.message.startsWith(
              'The infrastructure configuration could not be validated.',
            ))
        setGraphError(
          isValidationMessage && error instanceof Error
            ? error.message
            : 'The validation service could not be reached. Check that the FastAPI server is running.',
        )
      }
    } finally {
      if (graphControllerRef.current === controller) {
        graphControllerRef.current = null
      }
    }
  }

  function handleFindingSelect(resourceId: string) {
    clearAttackPathPlayback()
    setSelectedFindingResource(resourceId)
  }

  function handleAttackPathPlayback(path: string[]) {
    setSelectedFindingResource(null)
    setSelectedAttackPath(path)
    setAttackPathStep(0)
    setIsAttackPathPlaying(path.length > 0)
  }

  async function handleStartScan() {
    if (
      selectedScenario === 'custom' ||
      !graph ||
      scanStatus === 'loading' ||
      scanStatus === 'scanning'
    ) {
      return
    }

    const controller = new AbortController()
    scanControllerRef.current?.abort()
    scanControllerRef.current = controller
    setScanStatus('loading')
    setScanResponse(null)
    setCurrentEventIndex(-1)
    setScanError('')
    setSelectedFindingResource(null)
    clearAttackPathPlayback()

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
  let scanButtonLabel =
    selectedScenario === 'custom' ? 'Custom scan unavailable' : 'Start Scan'
  let resultsStatusLabel = 'Awaiting scan'
  let resultsPlaceholderTitle = 'No scan results yet'
  let resultsPlaceholderMessage =
    'Security findings and potential attack paths will appear here after scanning.'

  if (selectedScenario === 'custom') {
    scanMessage = customScenario
      ? 'Custom infrastructure is validated for preview. Custom scanning is not available yet.'
      : 'Upload and validate a JSON file to preview its infrastructure.'
  }

  if (scanStatus === 'loading') {
    scanMessage = 'Preparing scan...'
    scanButtonLabel = 'Preparing scan...'
    resultsStatusLabel = 'Scan running'
    resultsPlaceholderTitle = 'Preparing scan'
    resultsPlaceholderMessage = 'Waiting for the backend analysis to complete.'
  } else if (scanStatus === 'scanning') {
    scanMessage = describeScanEvent(currentScanEvent)
    scanButtonLabel = 'Scanning...'
    resultsStatusLabel = 'Scan running'
    resultsPlaceholderTitle = 'Scanning infrastructure'
    resultsPlaceholderMessage = scanMessage
  } else if (scanStatus === 'completed') {
    scanMessage = 'Scan Complete'
    resultsStatusLabel = 'Scan complete'
  } else if (scanStatus === 'error') {
    scanMessage = scanError
    resultsStatusLabel = 'Scan failed'
    resultsPlaceholderTitle = 'Scan failed'
    resultsPlaceholderMessage = scanError
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
              Select a predefined cloud configuration or upload your own JSON.
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
              <option value="custom">Upload JSON</option>
            </select>
            {selectedScenario === 'custom' ? (
              <div className="upload-control">
                <label htmlFor="scenario-file">Infrastructure JSON file</label>
                <input
                  id="scenario-file"
                  type="file"
                  accept=".json,application/json"
                  onChange={handleFileUpload}
                />
              </div>
            ) : null}
            <p className="current-scenario" aria-live="polite">
              {selectedScenario === 'custom' ? (
                <>
                  Uploaded file:{' '}
                  <strong className="uploaded-filename">
                    {uploadedFilename || 'None selected'}
                  </strong>
                </>
              ) : (
                <>
                  Selected scenario: <strong>{selectedScenario}</strong>
                </>
              )}
            </p>
            <button
              type="button"
              disabled={
                selectedScenario === 'custom' ||
                !graph ||
                scanStatus === 'loading' ||
                scanStatus === 'scanning'
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
              {graphError
                ? 'Unavailable'
                : graph
                  ? 'Interactive'
                  : selectedScenario === 'custom' && !uploadedFilename
                    ? 'Awaiting upload'
                    : selectedScenario === 'custom'
                      ? 'Validating'
                      : 'Loading'}
            </span>
          </div>
          {graphError ? (
            <div className="placeholder graph-message" role="alert">
              <h3>
                {selectedScenario === 'custom'
                  ? 'Unable to preview uploaded infrastructure'
                  : 'Unable to load infrastructure'}
              </h3>
              <p>
                {graphError}
                {selectedScenario === 'custom'
                  ? ''
                  : ' Check that the FastAPI server is running.'}
              </p>
            </div>
          ) : graph ? (
            <GraphCanvas
              graph={graph}
              scanEvent={currentScanEvent}
              selectedResourceId={selectedFindingResource}
              attackPath={selectedAttackPath}
              attackPathStep={attackPathStep}
            />
          ) : (
            <div className="placeholder graph-message" aria-live="polite">
              <h3>
                {selectedScenario === 'custom' && !uploadedFilename
                  ? 'Upload infrastructure JSON'
                  : selectedScenario === 'custom'
                    ? 'Validating infrastructure…'
                    : 'Loading infrastructure…'}
              </h3>
              <p>
                {selectedScenario === 'custom' && !uploadedFilename
                  ? 'Choose a local .json file to validate and preview.'
                  : selectedScenario === 'custom'
                    ? 'Checking resources and network connections.'
                    : 'Fetching resources and network connections.'}
              </p>
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
          {scanStatus === 'completed' && scanResponse ? (
            <div className="scan-results">
              <div className="summary-grid" aria-label="Scan summary">
                <div className="summary-item">
                  <strong>{scanResponse.summary.total_resources}</strong>
                  <span>Resources</span>
                </div>
                <div className="summary-item">
                  <strong>{scanResponse.summary.total_findings}</strong>
                  <span>Findings</span>
                </div>
                <div className="summary-item">
                  <strong>{scanResponse.summary.high}</strong>
                  <span>High</span>
                </div>
                <div className="summary-item">
                  <strong>{scanResponse.summary.critical}</strong>
                  <span>Critical</span>
                </div>
                <div className="summary-item">
                  <strong>{scanResponse.summary.attack_paths}</strong>
                  <span>Attack paths</span>
                </div>
              </div>

              <section className="results-section" aria-labelledby="findings-title">
                <h3 id="findings-title">Misconfigured Resources</h3>
                {scanResponse.findings.length === 0 ? (
                  <p className="results-empty">
                    No security misconfigurations detected by the implemented
                    rules.
                  </p>
                ) : (
                  <div className="finding-list">
                    {scanResponse.findings.map((finding, index) => (
                      <button
                        type="button"
                        className={`finding-card severity-${finding.severity}${
                          selectedFindingResource === finding.resource
                            ? ' is-selected'
                            : ''
                        }`}
                        aria-pressed={
                          selectedFindingResource === finding.resource
                        }
                        key={`${finding.resource}-${index}`}
                        onClick={() => handleFindingSelect(finding.resource)}
                      >
                        <span className="finding-heading">
                          <strong>
                            {getResourceName(graph, finding.resource)}
                          </strong>
                          <span className="severity-badge">
                            {finding.severity}
                          </span>
                        </span>
                        <span className="finding-resource-id">
                          Resource ID: {finding.resource}
                        </span>
                        <span className="finding-explanation">
                          {finding.explanation}
                        </span>
                        <span className="finding-remediation">
                          <strong>Remediation:</strong> {finding.remediation}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </section>

              <section className="results-section" aria-labelledby="paths-title">
                <h3 id="paths-title">Attack Paths</h3>
                {scanResponse.attack_paths.length === 0 ? (
                  <p className="results-empty">
                    No public-to-private sensitive path detected.
                  </p>
                ) : (
                  <div className="attack-path-list">
                    {scanResponse.attack_paths.map((path, index) => (
                      <div
                        className="attack-path-card"
                        key={`${path.join('-')}-${index}`}
                      >
                        <p className="path-sequence">
                          {path
                            .map((resourceId) =>
                              getResourceName(graph, resourceId),
                            )
                            .join(' → ')}
                        </p>
                        <p>
                          This path represents potential network reachability to a
                          sensitive resource, not proof of successful exploitation.
                        </p>
                        <button
                          type="button"
                          className="attack-path-button"
                          aria-pressed={selectedAttackPath === path}
                          onClick={() => handleAttackPathPlayback(path)}
                        >
                          {selectedAttackPath === path
                            ? 'Replay Attack Path'
                            : 'Visualise Attack Path'}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
          ) : (
            <div className="placeholder results-placeholder">
              <h3>{resultsPlaceholderTitle}</h3>
              <p>{resultsPlaceholderMessage}</p>
            </div>
          )}
        </section>
      </main>
    </div>
  )
}

export default App

