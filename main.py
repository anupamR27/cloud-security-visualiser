import networkx as nx
from fastapi import FastAPI, HTTPException

from attack_paths import find_sensitive_attack_path
from graph_builder import build_graph
from models import Finding, ScanRequest, Scenario
from scenarios import load_scenario
from security_rules import (
    find_public_database_exposures,
    find_public_ssh_exposures,
)


app = FastAPI()


def serialize_graph(
    graph: nx.DiGraph,
) -> dict[str, list[dict[str, object]]]:
    return {
        "nodes": [
            {"id": node_id, **attributes}
            for node_id, attributes in graph.nodes(data=True)
        ],
        "edges": [
            {"source": source, "target": target, **attributes}
            for source, target, attributes in graph.edges(data=True)
        ],
    }


@app.get("/api/health")
def get_health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/scenarios/{scenario_id}")
def get_scenario_graph(
    scenario_id: str,
) -> dict[str, list[dict[str, object]]]:
    try:
        scenario = load_scenario(scenario_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    graph = build_graph(scenario)

    return serialize_graph(graph)


@app.post("/api/validate")
def validate_scenario(scenario: Scenario) -> dict[str, object]:
    graph = build_graph(scenario)
    return {
        **serialize_graph(graph),
        "summary": {
            "total_resources": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
        },
    }


def analyze_scenario(scenario: Scenario) -> dict[str, object]:
    events: list[dict[str, object]] = [{"type": "scan_started"}]
    graph = build_graph(scenario)
    findings: list[Finding] = []

    for rule in (find_public_ssh_exposures, find_public_database_exposures):
        rule_findings = rule(graph)
        findings.extend(rule_findings)
        events.extend(
            {
                "type": "finding_detected",
                "resource": finding.resource,
                "severity": finding.severity,
            }
            for finding in rule_findings
        )

    path = find_sensitive_attack_path(graph, events)
    attack_paths = []
    if path is not None:
        attack_paths.append(path)
        path_finding = Finding(
            resource=path[-1],
            severity="critical",
            explanation=(
                "A network path from the Internet reaches a private sensitive "
                "resource through a compute resource."
            ),
            remediation=(
                "Restrict network access along the path to only required sources."
            ),
        )
        findings.append(path_finding)
        events.append(
            {
                "type": "finding_detected",
                "resource": path_finding.resource,
                "severity": path_finding.severity,
            }
        )

    events.append({"type": "scan_completed"})

    return {
        "summary": {
            "total_resources": graph.number_of_nodes(),
            "total_findings": len(findings),
            "high": sum(finding.severity == "high" for finding in findings),
            "critical": sum(
                finding.severity == "critical" for finding in findings
            ),
            "attack_paths": len(attack_paths),
        },
        "findings": findings,
        "attack_paths": attack_paths,
        "events": events,
    }


@app.post("/api/scan")
def scan_scenario(request: ScanRequest) -> dict[str, object]:
    try:
        scenario = load_scenario(request.scenario_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

    return analyze_scenario(scenario)


@app.post("/api/scan-custom")
def scan_custom_scenario(scenario: Scenario) -> dict[str, object]:
    result = analyze_scenario(scenario)
    return {
        **result,
        "security_status": (
            "vulnerable" if result["findings"] else "no_detected_risks"
        ),
    }
