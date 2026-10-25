import { useState, type ChangeEvent } from 'react'

type Scenario = 'secure' | 'vulnerable'

function App() {
  const [selectedScenario, setSelectedScenario] = useState<Scenario>('secure')

  function handleScenarioChange(event: ChangeEvent<HTMLSelectElement>) {
    setSelectedScenario(event.target.value as Scenario)
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
            <button type="button" disabled>
              Start Scan
            </button>
            <p className="button-note">Scan integration will be added in Task 9.</p>
          </div>
        </section>

        <section className="panel graph-panel" aria-labelledby="graph-title">
          <div className="section-heading">
            <div>
              <p className="section-label">Infrastructure</p>
              <h2 id="graph-title">Infrastructure Graph</h2>
            </div>
            <span className="status-badge">Not loaded</span>
          </div>
          <div className="placeholder graph-placeholder">
            <div className="placeholder-icon" aria-hidden="true">◎</div>
            <h3>Interactive graph coming in Task 8</h3>
            <p>Cloud resources and their network connections will appear here.</p>
          </div>
        </section>

        <section className="panel results-panel" aria-labelledby="results-title">
          <div className="section-heading">
            <div>
              <p className="section-label">Analysis</p>
              <h2 id="results-title">Scan Results</h2>
            </div>
            <span className="status-badge">Awaiting scan</span>
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

