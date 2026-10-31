# Cloud Security Visualiser

Cloud Security Visualiser is a teaching and demonstration application for analyzing simplified cloud infrastructure models. Users can select a predefined scenario or upload Scenario JSON, inspect the directed resource graph, run deterministic security checks, animate a potential attack path, generate a one-pass remediation proposal, verify that proposal, and download the proposed JSON or a PDF assessment.

The application analyzes only the submitted model. It does not connect to a cloud account or change deployed infrastructure.

## Features

- Predefined **Secure** and **Vulnerable** scenarios.
- Pydantic validation and graph preview for custom Scenario JSON.
- Interactive Cytoscape.js graph with node details and parallel connections.
- Deterministic checks for supported public SSH and database exposures.
- NetworkX breadth-first search (BFS) for one potential Internet-to-sensitive-resource path.
- Animated scan events and attack-path playback.
- One-pass proposals that remove only supported risky connections from a copy.
- Verification scan of the proposed configuration.
- Evidence-based explanations for residual findings and remaining paths.
- Proposed Scenario JSON download for review or re-upload.
- Stateless PDF security assessment generation.

## Tech stack

| Layer | Technologies |
| --- | --- |
| Backend | Python 3.11+, FastAPI, Pydantic, NetworkX |
| Reporting | ReportLab |
| Frontend | React, TypeScript, Vite |
| Graph UI | Cytoscape.js |
| Tests | Python `unittest`, FastAPI `TestClient` |

## Architecture overview

```text
Scenario JSON
    -> Pydantic validation
    -> NetworkX MultiDiGraph
    -> deterministic rules + multi-source BFS
    -> findings, potential path, and scan events
    -> React and Cytoscape.js presentation

Validated Scenario
    -> one-pass remediation on a copy
    -> verification analysis
    -> residual-risk explanations
    -> proposed JSON and PDF outputs
```

The React frontend calls the FastAPI endpoints through Vite's local `/api` proxy. The backend validates every custom Scenario before building a directed multigraph, allowing multiple connections between the same two resources. Remediation and reporting reuse the same analysis pipeline so their before/after results follow the same rule and path semantics.

See [Architecture](docs/ARCHITECTURE.md) for module responsibilities and request lifecycles, and [Demo guide](docs/DEMO.md) for a 5–7 minute walkthrough.

## Installation and local development

The commands below target macOS or Linux. Run them from a project checkout.

### 1. Install backend dependencies

```bash
cd /path/to/Cloud_Security
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 2. Install frontend dependencies with Node 24

Install [NVM](https://github.com/nvm-sh/nvm) first if it is not already available.

```bash
cd /path/to/Cloud_Security/frontend
source "$NVM_DIR/nvm.sh"
nvm install 24
nvm use 24
npm ci
```

### 3. Start FastAPI

In the first terminal:

```bash
cd /path/to/Cloud_Security
source .venv/bin/activate
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The health endpoint is available at `http://127.0.0.1:8000/api/health`.

### 4. Start Vite

In a second terminal:

```bash
cd /path/to/Cloud_Security/frontend
source "$NVM_DIR/nvm.sh"
nvm use 24
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` requests to FastAPI at `http://127.0.0.1:8000`.

### 5. Run checks

Backend unit tests:

```bash
cd /path/to/Cloud_Security
.venv/bin/python -m unittest discover -s tests -v
```

Frontend type-check and production build:

```bash
cd /path/to/Cloud_Security/frontend
source "$NVM_DIR/nvm.sh"
nvm use 24
npx tsc --noEmit
npm run build
```

## Custom JSON format

A custom upload must be one complete Scenario object. This minimal example is valid:

```json
{
  "id": "minimal-web",
  "name": "Minimal web scenario",
  "description": "An Internet-facing web service.",
  "nodes": [
    {
      "id": "internet",
      "name": "Internet",
      "type": "internet",
      "public": true,
      "sensitive": false
    },
    {
      "id": "web-server",
      "name": "Web server",
      "type": "compute",
      "public": true,
      "sensitive": false
    }
  ],
  "edges": [
    {
      "source": "internet",
      "target": "web-server",
      "protocol": "TCP",
      "port": 443,
      "reason": "Public HTTPS access"
    }
  ]
}
```

Required fields:

- **Scenario:** `id`, `name`, `description`, `nodes`, `edges`.
- **Node:** `id`, `name`, `type`, `public`, `sensitive`.
- **Edge:** `source`, `target`, `protocol`, `port`, `reason`.

Validation rules:

- Node `type` must be `internet`, `compute`, or `database`.
- A Scenario may contain at most 100 nodes and 500 edges.
- Ports must be integers from 1 through 65535.
- Node IDs must be unique.
- Every edge `source` and `target` must reference an existing node ID.
- Parallel edges are supported: repeated source/target pairs can represent different protocols, ports, or purposes.

The application does not accept arbitrary AWS exports, Terraform, or CloudFormation files.

## API overview

| Method | Endpoint | Request | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/health` | None | Return `{"status":"ok"}`. |
| `GET` | `/api/scenarios/{scenario_id}` | Path ID: `secure` or `vulnerable` | Return graph nodes and edges for a predefined scenario. |
| `POST` | `/api/scan` | `{"scenario_id":"secure"}` | Analyze a predefined scenario. |
| `POST` | `/api/validate` | Scenario JSON | Validate custom JSON and return graph data plus resource/edge counts. |
| `POST` | `/api/scan-custom` | Scenario JSON | Analyze a custom Scenario and include its supported-risk status. |
| `POST` | `/api/remediate` | Scenario JSON | Return the original analysis, proposed copy, changes, verification, and residual explanations. |
| `POST` | `/api/report` | Scenario JSON | Run the remediation/verification pipeline and return an `application/pdf` attachment. |

Example predefined scan:

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"scenario_id":"vulnerable"}'
```

FastAPI returns HTTP 422 when submitted Scenario JSON fails Pydantic validation.

## Supported security checks

| Check | Current condition | Severity |
| --- | --- | --- |
| Public SSH exposure | An `internet` node has a directed TCP connection on port 22 to a `compute` node. Protocol matching is case-insensitive. | High |
| Direct public database exposure | An `internet` node has a directed TCP connection on port 3306 or 5432 to a `database` node. | Critical when the database is sensitive; otherwise high |
| Potential attack path | A directed path starts at any `internet` node, passes through a `compute` node, and reaches a node that is sensitive and not public. | Critical finding on the destination |

The path check uses multi-source BFS and returns at most the first qualifying path. It establishes modeled network reachability, not exploitation or compromise. The project does not implement a comprehensive cloud-security rule catalog.

## Remediation and verification

The remediation engine performs exactly one pass over a validated Scenario copy. It proposes removal only for:

- Internet-to-compute TCP/22 connections.
- Internet-to-database TCP/3306 or TCP/5432 connections.

All other connections are preserved, including Internet-facing HTTPS and application-to-database traffic. The original Scenario is not mutated. One verification scan analyzes the proposed copy, after which the API explains remaining findings and paths with connection evidence and manual mitigation guidance. Residual risk can therefore remain, and no changes are applied to real infrastructure.

## Downloads

- **Proposed JSON:** created in the browser from the remediation response. It can be reviewed, edited, or uploaded again through the same validation workflow.
- **PDF assessment:** generated by ReportLab in memory for each request. It contains the infrastructure overview, initial findings, proposed changes, verification results, remaining risks and paths, evidence, and security limitations.

No report database or persistent report storage is used.

## Limitations

- The input is a simplified JSON model, not a live cloud inventory.
- There is no cloud-account integration and no deployed infrastructure is modified.
- Only three resource types and a small deterministic rule set are supported.
- At most one potential attack path is reported.
- BFS reachability does not prove successful exploitation or compromise.
- Remediation is targeted and one-pass, so residual risks may remain.
- “No detected risks” means only that the current rules found none; it is not a security guarantee.
- Large valid graphs can become visually crowded.
