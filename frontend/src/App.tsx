import { useEffect, useRef, useState, type ChangeEvent } from 'react'
import GraphCanvas, { type GraphData, type ScanEvent } from './GraphCanvas'

type Scenario = 'secure' | 'vulnerable' | 'custom'
type ScanStatus = 'idle' | 'loading' | 'scanning' | 'completed' | 'error'
type SecurityStatus = 'vulnerable' | 'no_detected_risks'
type RemediationStatus = 'idle' | 'loading' | 'completed' | 'error'
type RemediationSecurityStatus = 'residual_risks' | 'no_detected_risks'

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
  security_status?: SecurityStatus
}

type RemediationConnection = {
  source_id: string
  source_name: string
  target_id: string
  target_name: string
  protocol: string
  port: number
  reason: string
}

type RemediationChange = {
  source_node_id: string
  target_node_id: string
  protocol: string
  port: number
  proposed_action: string
  associated_security_risk: string
  reason: string
  potential_operational_impact: string
}

type ResidualExplanation = {
  risk_classification: string
  affected_resource: {
    id: string
    name: string
  }
  severity: SecurityFinding['severity']
  finding_explanation: string
  connection_evidence: RemediationConnection[]
  why_risk_remains: string
  why_not_remediated: string
  recommended_manual_mitigation: string
  potential_operational_impact: string
}

type RemainingPathExplanation = {
  node_ids: string[]
  resource_names: string[]
  display_path: string
  hops: {
    source_id: string
    source_name: string
    target_id: string
    target_name: string
    connections: RemediationConnection[]
  }[]
  why_path_remains: string
  why_remediation_stopped: string
  manual_mitigation: string
  potential_operational_impact: string
}

type RemediationResponse = {
  original_scan: ScanResponse
  proposed_configuration: CustomScenario
  changes: RemediationChange[]
  verification_scan: ScanResponse
  before_after: {
    initial_findings: number
    remaining_findings: number
  }
  remaining_findings: SecurityFinding[]
  remaining_attack_paths: string[][]
  security_status: RemediationSecurityStatus
  residual_explanations: ResidualExplanation[]
  remaining_path_explanations: RemainingPathExplanation[]
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

function formatIdentifier(value: string): string {
  return value.replaceAll('_', ' ')
}

function ConnectionEvidenceList({
  connections,
}: {
  connections: RemediationConnection[]
}) {
  if (connections.length === 0) {
    return <p className="results-empty">No connection evidence available.</p>
  }

  return (
    <ul className="connection-list">
      {connections.map((connection, index) => (
        <li
          key={`${connection.source_id}-${connection.target_id}-${connection.protocol}-${connection.port}-${index}`}
        >
          <strong>
            {connection.source_name} ({connection.source_id}) →{' '}
            {connection.target_name} ({connection.target_id})
          </strong>
          <span>
            {connection.protocol}/{connection.port} · {connection.reason}
          </span>
        </li>
      ))}
    </ul>
  )
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
  const [remediationStatus, setRemediationStatus] =
    useState<RemediationStatus>('idle')
  const [remediationResponse, setRemediationResponse] =
    useState<RemediationResponse | null>(null)
  const [remediationError, setRemediationError] = useState('')
  const [isReportPending, setIsReportPending] = useState(false)
  const [reportError, setReportError] = useState('')
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
  const remediationControllerRef = useRef<AbortController | null>(null)
  const reportControllerRef = useRef<AbortController | null>(null)

  const currentScanEvent =
    scanResponse?.events[currentEventIndex] ?? null
  const securityStatus =
    scanResponse?.security_status ??
    (scanResponse
      ? scanResponse.findings.length > 0
        ? 'vulnerable'
        : 'no_detected_risks'
      : null)

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

  function clearReportState() {
    reportControllerRef.current?.abort()
    reportControllerRef.current = null
    setIsReportPending(false)
    setReportError('')
  }

  function clearRemediationState() {
    clearReportState()
    remediationControllerRef.current?.abort()
    remediationControllerRef.current = null
    setRemediationStatus('idle')
    setRemediationResponse(null)
    setRemediationError('')
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
    clearRemediationState()
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
      !graph ||
      (selectedScenario === 'custom' && !customScenario) ||
      scanStatus === 'loading' ||
      scanStatus === 'scanning' ||
      remediationStatus === 'loading' ||
      remediationControllerRef.current
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
    clearRemediationState()

    try {
      const isCustomScenario = selectedScenario === 'custom'
      const response = await fetch(
        isCustomScenario ? '/api/scan-custom' : '/api/scan',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(
            isCustomScenario
              ? customScenario
              : { scenario_id: selectedScenario },
          ),
          signal: controller.signal,
        },
      )

      if (!response.ok) {
        if (response.status === 422) {
          throw new Error(describeValidationError(await response.json()))
        }
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

  async function handleGenerateRemediation() {
    if (
      selectedScenario !== 'custom' ||
      !customScenario ||
      scanStatus !== 'completed' ||
      remediationStatus === 'loading' ||
      remediationControllerRef.current
    ) {
      return
    }

    clearReportState()
    const controller = new AbortController()
    const requestVersion = graphRequestVersionRef.current
    remediationControllerRef.current = controller
    setRemediationStatus('loading')
    setRemediationResponse(null)
    setRemediationError('')

    try {
      const response = await fetch('/api/remediate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(customScenario),
        signal: controller.signal,
      })

      if (!response.ok) {
        if (response.status === 422) {
          throw new Error(describeValidationError(await response.json()))
        }
        throw new Error('The remediation proposal could not be generated.')
      }

      const result: RemediationResponse = await response.json()
      if (
        controller.signal.aborted ||
        graphRequestVersionRef.current !== requestVersion
      ) {
        return
      }

      setRemediationResponse(result)
      setRemediationStatus('completed')
    } catch (error) {
      if (
        !controller.signal.aborted &&
        graphRequestVersionRef.current === requestVersion
      ) {
        setRemediationStatus('error')
        setRemediationError(
          error instanceof TypeError
            ? 'The remediation service could not be reached. Check that the FastAPI server is running.'
            : error instanceof Error
            ? error.message
            : 'The remediation proposal could not be generated.',
        )
      }
    } finally {
      if (remediationControllerRef.current === controller) {
        remediationControllerRef.current = null
      }
    }
  }

  function handleDownloadProposedConfiguration() {
    if (remediationStatus !== 'completed' || !remediationResponse) {
      return
    }

    const contents = JSON.stringify(
      remediationResponse.proposed_configuration,
      null,
      2,
    )
    const blob = new Blob([contents], { type: 'application/json' })
    const objectUrl = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = objectUrl
    link.download = 'proposed-infrastructure.json'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(objectUrl)
  }

  async function handleDownloadSecurityReport() {
    if (
      selectedScenario !== 'custom' ||
      !customScenario ||
      scanStatus !== 'completed' ||
      remediationStatus !== 'completed' ||
      !remediationResponse ||
      isReportPending ||
      reportControllerRef.current
    ) {
      return
    }

    const controller = new AbortController()
    const requestVersion = graphRequestVersionRef.current
    reportControllerRef.current = controller
    setIsReportPending(true)
    setReportError('')

    try {
      const response = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(customScenario),
        signal: controller.signal,
      })

      if (!response.ok) {
        if (response.status === 422) {
          throw new Error(describeValidationError(await response.json()))
        }
        throw new Error('The security report could not be generated.')
      }

      const contentType = response.headers.get('content-type')?.toLowerCase()
      if (!contentType?.includes('application/pdf')) {
        throw new Error('The report service returned an unexpected file type.')
      }

      let reportBlob: Blob
      try {
        reportBlob = await response.blob()
      } catch {
        throw new Error('The security report response could not be read.')
      }

      if (
        controller.signal.aborted ||
        graphRequestVersionRef.current !== requestVersion
      ) {
        return
      }

      const objectUrl = URL.createObjectURL(reportBlob)
      const link = document.createElement('a')
      link.href = objectUrl
      link.download = 'cloud-security-assessment.pdf'
      document.body.appendChild(link)
      try {
        link.click()
      } finally {
        link.remove()
        URL.revokeObjectURL(objectUrl)
      }
    } catch (error) {
      if (
        !controller.signal.aborted &&
        graphRequestVersionRef.current === requestVersion
      ) {
        setReportError(
          error instanceof TypeError
            ? 'The report service could not be reached. Check that the FastAPI server is running.'
            : error instanceof Error
              ? error.message
              : 'The security report could not be downloaded.',
        )
      }
    } finally {
      if (reportControllerRef.current === controller) {
        reportControllerRef.current = null
        setIsReportPending(false)
      }
    }
  }

  let scanMessage = graph
    ? 'Ready to scan the selected infrastructure.'
    : 'The graph must load before scanning.'
  let scanButtonLabel = 'Start Scan'
  let resultsStatusLabel = 'Awaiting scan'
  let resultsPlaceholderTitle = 'No scan results yet'
  let resultsPlaceholderMessage =
    'Security findings and potential attack paths will appear here after scanning.'

  if (selectedScenario === 'custom') {
    scanMessage = customScenario
      ? 'Ready to scan the validated custom infrastructure.'
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
    resultsStatusLabel =
      securityStatus === 'vulnerable' ? 'Vulnerable' : 'No detected risks'
  } else if (scanStatus === 'error') {
    scanMessage = scanError
    resultsStatusLabel = 'Scan failed'
    resultsPlaceholderTitle = 'Scan failed'
    resultsPlaceholderMessage = scanError
  }

  const remediationButtonLabel =
    remediationStatus === 'loading'
      ? 'Generating Proposal...'
      : 'Generate Remediation Proposal'
  let remediationMessage =
    scanStatus === 'completed'
      ? 'Generate a review-only proposal from the validated configuration.'
      : 'Complete the custom infrastructure scan before generating a proposal.'

  if (remediationStatus === 'completed') {
    remediationMessage =
      'Proposal generated. The original graph and configuration remain unchanged.'
  } else if (remediationStatus === 'error') {
    remediationMessage = remediationError
  }

  let remediationStatusLabel = 'Awaiting proposal'
  if (remediationStatus === 'loading') {
    remediationStatusLabel = 'Generating proposal'
  } else if (remediationStatus === 'error') {
    remediationStatusLabel = 'Proposal failed'
  } else if (remediationResponse?.security_status === 'residual_risks') {
    remediationStatusLabel = 'Residual risks remain'
  } else if (
    remediationResponse?.security_status === 'no_detected_risks'
  ) {
    remediationStatusLabel = 'No detected risks remain'
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
                !graph ||
                (selectedScenario === 'custom' && !customScenario) ||
                scanStatus === 'loading' ||
                scanStatus === 'scanning' ||
                remediationStatus === 'loading'
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
            {selectedScenario === 'custom' && customScenario ? (
              <div className="remediation-action">
                <button
                  type="button"
                  className="secondary-button"
                  disabled={
                    scanStatus !== 'completed' ||
                    remediationStatus === 'loading'
                  }
                  onClick={handleGenerateRemediation}
                >
                  {remediationButtonLabel}
                </button>
                <p
                  className={`button-note${
                    remediationStatus === 'error' ? ' scan-error' : ''
                  }`}
                  aria-live="polite"
                >
                  {remediationMessage}
                </p>
              </div>
            ) : null}
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

        {selectedScenario === 'custom' && scanStatus === 'completed' ? (
          <section
            className="panel remediation-panel"
            aria-labelledby="remediation-title"
          >
            <div className="section-heading">
              <div>
                <p className="section-label">Remediation review</p>
                <h2 id="remediation-title">Remediation Proposal</h2>
              </div>
              <span className="status-badge">{remediationStatusLabel}</span>
            </div>

            {remediationStatus === 'completed' && remediationResponse ? (
              <div className="remediation-results">
                <p className="proposal-notice">
                  This proposal is a recommendation generated from a copied JSON
                  configuration. It does not modify real cloud infrastructure or
                  replace the original graph shown above.
                </p>

                <div className="download-action">
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={handleDownloadProposedConfiguration}
                  >
                    Download Proposed JSON
                  </button>
                  <p>
                    Download the proposed modified configuration for review,
                    editing, or upload through the existing validation and scan
                    workflow. Downloading does not change real cloud
                    infrastructure.
                  </p>
                </div>

                <div className="download-action">
                  <button
                    type="button"
                    className="secondary-button"
                    disabled={isReportPending}
                    onClick={handleDownloadSecurityReport}
                  >
                    {isReportPending
                      ? 'Generating PDF...'
                      : 'Download Security Report (PDF)'}
                  </button>
                  <div>
                    <p>
                      Download a security assessment containing initial findings,
                      proposed changes, verification results, and remaining risks.
                    </p>
                    {reportError ? (
                      <p className="download-error" role="alert">
                        {reportError}
                      </p>
                    ) : null}
                  </div>
                </div>

                <div
                  className="remediation-summary-grid"
                  aria-label="Remediation summary"
                >
                  <div className="summary-item">
                    <strong>
                      {remediationResponse.before_after.initial_findings}
                    </strong>
                    <span>Initial findings</span>
                  </div>
                  <div className="summary-item">
                    <strong>
                      {remediationResponse.before_after.remaining_findings}
                    </strong>
                    <span>Remaining findings</span>
                  </div>
                  <div className="summary-item">
                    <strong>{remediationResponse.changes.length}</strong>
                    <span>Proposed changes</span>
                  </div>
                  <div className="summary-item remediation-status-summary">
                    <strong>
                      {remediationResponse.security_status === 'residual_risks'
                        ? 'Residual risks remain'
                        : 'No detected risks remain'}
                    </strong>
                    <span>Final security status</span>
                  </div>
                </div>

                <section
                  className="remediation-section"
                  aria-labelledby="changes-title"
                >
                  <h3 id="changes-title">Proposed Changes</h3>
                  {remediationResponse.changes.length === 0 ? (
                    <p className="results-empty">
                      No changes were proposed by the supported one-pass
                      remediation.
                    </p>
                  ) : (
                    <div className="remediation-card-list">
                      {remediationResponse.changes.map((change, index) => (
                        <article
                          className="remediation-card"
                          key={`${change.source_node_id}-${change.target_node_id}-${change.protocol}-${change.port}-${index}`}
                        >
                          <div className="remediation-card-heading">
                            <strong>
                              {change.source_node_id} → {change.target_node_id}
                            </strong>
                            <span className="change-action">
                              {formatIdentifier(change.proposed_action)}
                            </span>
                          </div>
                          <dl className="remediation-details">
                            <div>
                              <dt>Connection</dt>
                              <dd>
                                {change.protocol}/{change.port}
                              </dd>
                            </div>
                            <div>
                              <dt>Security risk</dt>
                              <dd>
                                {formatIdentifier(
                                  change.associated_security_risk,
                                )}
                              </dd>
                            </div>
                          </dl>
                          <p>
                            <strong>Reason:</strong> {change.reason}
                          </p>
                          <p>
                            <strong>Potential operational impact:</strong>{' '}
                            {change.potential_operational_impact}
                          </p>
                        </article>
                      ))}
                    </div>
                  )}
                </section>

                <section
                  className="remediation-section"
                  aria-labelledby="residual-findings-title"
                >
                  <h3 id="residual-findings-title">
                    Detailed Residual Findings
                  </h3>
                  {remediationResponse.residual_explanations.length === 0 ? (
                    <p className="results-empty">
                      No residual findings were reported by the verification
                      scan.
                    </p>
                  ) : (
                    <div className="remediation-card-list">
                      {remediationResponse.residual_explanations.map(
                        (explanation, index) => (
                          <article
                            className={`remediation-card severity-${explanation.severity}`}
                            key={`${explanation.affected_resource.id}-${explanation.risk_classification}-${index}`}
                          >
                            <div className="remediation-card-heading">
                              <div>
                                <strong>
                                  {explanation.affected_resource.name}
                                </strong>
                                <span className="remediation-resource-id">
                                  Resource ID:{' '}
                                  {explanation.affected_resource.id}
                                </span>
                              </div>
                              <span className="severity-badge">
                                {explanation.severity}
                              </span>
                            </div>
                            <p className="risk-classification">
                              {formatIdentifier(
                                explanation.risk_classification,
                              )}
                            </p>
                            <p>{explanation.finding_explanation}</p>
                            <p>
                              <strong>Why the risk remains:</strong>{' '}
                              {explanation.why_risk_remains}
                            </p>
                            <p>
                              <strong>Why it was not automatically remediated:</strong>{' '}
                              {explanation.why_not_remediated}
                            </p>
                            <p>
                              <strong>Recommended manual mitigation:</strong>{' '}
                              {explanation.recommended_manual_mitigation}
                            </p>
                            <p>
                              <strong>Potential operational impact:</strong>{' '}
                              {explanation.potential_operational_impact}
                            </p>
                            <h4>Relevant connection evidence</h4>
                            <ConnectionEvidenceList
                              connections={explanation.connection_evidence}
                            />
                          </article>
                        ),
                      )}
                    </div>
                  )}
                </section>

                <section
                  className="remediation-section"
                  aria-labelledby="remaining-paths-title"
                >
                  <h3 id="remaining-paths-title">
                    Remaining Potential Attack Paths
                  </h3>
                  {remediationResponse.remaining_path_explanations.length ===
                  0 ? (
                    <p className="results-empty">
                      No remaining public-to-private sensitive path was reported.
                    </p>
                  ) : (
                    <div className="remediation-card-list">
                      {remediationResponse.remaining_path_explanations.map(
                        (path, pathIndex) => (
                          <article
                            className="remediation-card path-explanation-card"
                            key={`${path.node_ids.join('-')}-${pathIndex}`}
                          >
                            <p className="path-sequence">
                              {path.display_path}
                            </p>
                            <p className="path-node-ids">
                              Node IDs: {path.node_ids.join(' → ')}
                            </p>
                            <p>{path.why_path_remains}</p>
                            <p>
                              <strong>Why remediation stopped:</strong>{' '}
                              {path.why_remediation_stopped}
                            </p>
                            <p>
                              <strong>Recommended manual mitigation:</strong>{' '}
                              {path.manual_mitigation}
                            </p>
                            <p>
                              <strong>Potential operational impact:</strong>{' '}
                              {path.potential_operational_impact}
                            </p>
                            <div className="path-hop-list">
                              {path.hops.map((hop, hopIndex) => (
                                <section
                                  className="path-hop"
                                  key={`${hop.source_id}-${hop.target_id}-${hopIndex}`}
                                >
                                  <h4>
                                    {hop.source_name} ({hop.source_id}) →{' '}
                                    {hop.target_name} ({hop.target_id})
                                  </h4>
                                  <ConnectionEvidenceList
                                    connections={hop.connections}
                                  />
                                </section>
                              ))}
                            </div>
                          </article>
                        ),
                      )}
                    </div>
                  )}
                </section>
              </div>
            ) : (
              <div
                className="placeholder remediation-placeholder"
                role={remediationStatus === 'error' ? 'alert' : undefined}
              >
                <h3>
                  {remediationStatus === 'loading'
                    ? 'Generating remediation proposal…'
                    : remediationStatus === 'error'
                      ? 'Unable to generate remediation proposal'
                      : 'No remediation proposal yet'}
                </h3>
                <p>
                  {remediationStatus === 'loading'
                    ? 'Waiting for the backend remediation and verification workflow.'
                    : remediationStatus === 'error'
                      ? remediationError
                      : 'Use Generate Remediation Proposal to review recommended changes without modifying the original graph.'}
                </p>
              </div>
            )}
          </section>
        ) : null}
      </main>
    </div>
  )
}

export default App

