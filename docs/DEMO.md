# Demonstration Guide

This guide prepares a 5–7 minute demonstration of the implemented application. The sequence and expected results are based on the source and automated tests; rehearse the browser interactions and downloads in the presentation environment before the evaluation.

## Preparation

Start both services as described in the [README](../README.md#installation-and-local-development), then open `http://localhost:5173`.

Save the custom Scenario from [Custom residual-risk scenario](#custom-residual-risk-scenario) as `residual-risk-demo.json`. Keep a PDF viewer available for the final step.

## 5–7 minute sequence

### 0:00–0:35 — Introduce the problem

Say:

> Cloud infrastructure risk is often about relationships, not isolated resources. This application turns a simplified infrastructure model into a directed graph, applies deterministic checks, and shows how exposure can create potential reachability to sensitive resources.

Set the boundary immediately: this is model analysis, not a live AWS scanner, exploit detector, or deployment tool.

### 0:35–1:10 — Explain the JSON model

Briefly show that a Scenario contains:

- Resources with an ID, name, type, public flag, and sensitive flag.
- Directed connections with source, target, protocol, port, and reason.
- Three resource types: `internet`, `compute`, and `database`.

Explain that the backend validates the JSON before constructing a NetworkX directed multigraph. Multiple connections between the same resources are preserved.

### 1:10–1:50 — Display the Secure scenario

1. Select **Secure**.
2. Point out the Internet, compute, and database resources in the graph.
3. Select a node to show its metadata.
4. Run the scan.

Expected result:

- Zero supported findings.
- Zero potential attack paths.
- The Internet reaches the public web server over HTTPS, but the private application server and sensitive database are not reachable from that Internet branch.

Say that “no detected risks” applies only to the implemented rules and is not a universal security guarantee.

### 1:50–2:50 — Display the Vulnerable scenario

1. Select **Vulnerable**.
2. Run the scan and let the scan animation complete.
3. Select the SSH finding to highlight the web server.
4. Choose **Visualise Attack Path**.

Expected result:

- One high finding: Internet-to-compute TCP/22 public SSH exposure.
- One critical finding: a potential path from Internet through the web server to the private sensitive database.
- One path: `Internet → Public Web Server → Private Database`.

Explain that BFS establishes directed reachability in the submitted model. It does not prove exploitation or compromise.

### 2:50–3:45 — Upload the custom parallel-connection scenario

1. Select **Upload JSON**.
2. Upload `residual-risk-demo.json`.
3. Point out that the file is validated before the graph preview appears.
4. Point out the two curved connections between Internet and the web server. The uploaded JSON identifies them as TCP/22 and TCP/443; the graph preserves both but does not label individual edges.
5. Run the custom scan.

Expected initial result:

- 3 resources.
- 2 findings: high public SSH plus critical potential attack path.
- 1 potential attack path.
- No direct public database exposure, because the database connection begins at the web server rather than the Internet node.

### 3:45–4:50 — Generate and verify remediation

1. Select **Generate Remediation Proposal**.
2. Emphasize that this operates on a copied Scenario and does not change real infrastructure.
3. Review the single proposed change.
4. Compare initial and remaining findings.

Expected result:

- The TCP/22 Internet-to-web-server edge is proposed for removal.
- The TCP/443 HTTPS edge is preserved.
- The web-server-to-database TCP/5432 application edge is preserved.
- Findings change from 2 initially to 1 remaining.
- The verification scan still reports `Internet → Web server → Private database`.

Explain why the remaining path matters: removing the supported SSH exposure does not eliminate reachability because required HTTPS still reaches the compute resource, which still reaches the database. The engine intentionally does not remove every reachable connection because that could break the application.

### 4:50–5:40 — Review residual evidence

Show the residual finding and remaining-path sections. Point out:

- The affected private database.
- TCP/443 as evidence for the Internet-to-web-server hop.
- TCP/5432 as evidence for the web-server-to-database hop.
- The distinction between potential network reachability and confirmed compromise.
- The manual least-privilege and segmentation recommendation.

### 5:40–6:20 — Download the outputs

1. Select **Download Proposed JSON**.
2. Explain that the downloaded file contains the proposed Scenario without TCP/22 and can be re-uploaded for review.
3. Select **Download Security Report (PDF)**.
4. Open the PDF and briefly show the initial findings, proposed change, verification counts, residual evidence, and limitations.

The JSON download is created from the API response in the browser. The PDF is generated in memory by the backend; the application does not store reports.

### 6:20–7:00 — Close with scope and future direction

Summarize the current boundaries:

- Simplified JSON rather than live cloud discovery.
- Three resource types and a limited deterministic rule set.
- At most one reported potential attack path.
- One remediation pass with no infrastructure changes.
- Reachability is evidence of potential exposure, not proof of compromise.

Possible future work—not current functionality—could include additional resource and rule types, enumeration of multiple paths, provider-specific import adapters, and richer graph filtering for large models.

## Custom residual-risk scenario

This Scenario is valid under the current schema and matches the residual-risk case covered by the API tests:

```json
{
  "id": "residual-risk-demo",
  "name": "Residual risk demonstration",
  "description": "Contains parallel SSH and HTTPS access with a remaining database path.",
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
    },
    {
      "id": "database",
      "name": "Private database",
      "type": "database",
      "public": false,
      "sensitive": true
    }
  ],
  "edges": [
    {
      "source": "internet",
      "target": "web-server",
      "protocol": "TCP",
      "port": 22,
      "reason": "Public SSH"
    },
    {
      "source": "internet",
      "target": "web-server",
      "protocol": "TCP",
      "port": 443,
      "reason": "Public HTTPS"
    },
    {
      "source": "web-server",
      "target": "database",
      "protocol": "TCP",
      "port": 5432,
      "reason": "Application database access"
    }
  ]
}
```

## Expected custom-scenario results

| Stage | Findings | Paths | Connections changed |
| --- | ---: | ---: | --- |
| Initial scan | 2: one high, one critical | 1 | None |
| Proposal | Not a scan | Not applicable | Remove Internet → web server TCP/22 |
| Verification | 1 critical | 1 | HTTPS and application database access remain |

## Presenter accuracy checklist

- Call findings “supported” or “detected by the current rules.”
- Call attack paths “potential reachability,” not successful attacks.
- Call remediation a “proposal on a copy,” not an applied cloud change.
- Do not describe the upload as AWS, Terraform, or CloudFormation ingestion.
- Do not claim multiple attack paths are enumerated.
- Do not claim the browser demonstration is verified until the rehearsal is complete.
