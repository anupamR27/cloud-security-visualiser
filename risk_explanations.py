from models import Edge, Finding, Node, Scenario
from security_rules import DATABASE_PORTS


def _connection_details(
    edge: Edge,
    nodes: dict[str, Node],
) -> dict[str, object]:
    return {
        "source_id": edge.source,
        "source_name": nodes[edge.source].name,
        "target_id": edge.target,
        "target_name": nodes[edge.target].name,
        "protocol": edge.protocol,
        "port": edge.port,
        "reason": edge.reason,
    }


def explain_residual_risks(
    scenario: Scenario,
    remaining_findings: list[Finding],
    remaining_attack_paths: list[list[str]],
) -> dict[str, list[dict[str, object]]]:
    nodes = {node.id: node for node in scenario.nodes}
    edges = sorted(
        scenario.edges,
        key=lambda edge: (
            edge.source,
            edge.target,
            edge.protocol.upper(),
            edge.port,
            edge.reason,
        ),
    )
    path_explanations = []

    for path in remaining_attack_paths:
        hops = []
        preserved_connections = []

        for source_id, target_id in zip(path, path[1:]):
            connections = [
                _connection_details(edge, nodes)
                for edge in edges
                if edge.source == source_id and edge.target == target_id
            ]
            hops.append(
                {
                    "source_id": source_id,
                    "source_name": nodes[source_id].name,
                    "target_id": target_id,
                    "target_name": nodes[target_id].name,
                    "connections": connections,
                }
            )
            preserved_connections.extend(connections)

        reasons = ", ".join(
            dict.fromkeys(
                connection["reason"] for connection in preserved_connections
            )
        )
        path_explanations.append(
            {
                "node_ids": path,
                "resource_names": [nodes[node_id].name for node_id in path],
                "display_path": " → ".join(
                    nodes[node_id].name for node_id in path
                ),
                "hops": hops,
                "preserved_connections": preserved_connections,
                "why_path_remains": (
                    "Every directed hop reported by the existing graph model "
                    "still exists in the proposed configuration. This establishes "
                    "potential network reachability, but does not confirm that any "
                    "resource has been compromised."
                ),
                "why_remediation_stopped": (
                    "The remediation engine completed its one permitted pass and "
                    "only removes supported direct public SSH and database "
                    "exposures. These connections were deliberately preserved "
                    "because they do not match those removals and may support their "
                    "stated application purposes. Automatically deleting every "
                    "reachable connection could break application functionality; "
                    "additional changes require manual architectural or security "
                    "review."
                ),
                "manual_mitigation": (
                    "Review each hop and apply least-privilege source restrictions, "
                    "network segmentation, and service-level access controls while "
                    "preserving only required traffic."
                ),
                "potential_operational_impact": (
                    "Restricting or removing these connections may interrupt traffic "
                    f"described as: {reasons}. Test and coordinate changes with the "
                    "affected service owners."
                ),
            }
        )

    residual_explanations = []
    for finding in remaining_findings:
        path_explanation = next(
            (
                explanation
                for explanation in path_explanations
                if explanation["node_ids"][-1] == finding.resource
            ),
            None,
        )

        if path_explanation is not None:
            risk_classification = "public_to_private_sensitive_attack_path"
            connection_evidence = path_explanation["preserved_connections"]
            why_risk_remains = (
                "The proposed configuration still contains a directed path from "
                "the Internet through a compute resource to this private sensitive "
                "resource, so it remains potentially network-reachable. This "
                "reachability evidence does not confirm compromise."
            )
            why_not_remediated = path_explanation["why_remediation_stopped"]
        else:
            resource = nodes[finding.resource]
            ssh_edges = [
                edge
                for edge in edges
                if nodes[edge.source].type == "internet"
                and edge.target == finding.resource
                and resource.type == "compute"
                and edge.protocol.upper() == "TCP"
                and edge.port == 22
            ]
            database_edges = [
                edge
                for edge in edges
                if nodes[edge.source].type == "internet"
                and edge.target == finding.resource
                and resource.type == "database"
                and edge.protocol.upper() == "TCP"
                and edge.port in DATABASE_PORTS
            ]
            relevant_edges = ssh_edges or database_edges
            risk_classification = (
                "public_ssh_exposure"
                if ssh_edges
                else "public_database_exposure"
            )
            connection_evidence = [
                _connection_details(edge, nodes) for edge in relevant_edges
            ]
            why_risk_remains = (
                "The proposed configuration still contains the direct public "
                "connection identified by the existing security finding. This "
                "network exposure does not by itself confirm compromise."
            )
            why_not_remediated = (
                "The remediation engine completed its one permitted pass, but this "
                "supported direct exposure remains in the proposed configuration. "
                "Further changes require manual security review rather than an "
                "additional automatic remediation pass."
            )

        reasons = ", ".join(
            dict.fromkeys(
                connection["reason"] for connection in connection_evidence
            )
        )
        residual_explanations.append(
            {
                "risk_classification": risk_classification,
                "affected_resource": {
                    "id": finding.resource,
                    "name": nodes[finding.resource].name,
                },
                "severity": finding.severity,
                "finding_explanation": finding.explanation,
                "connection_evidence": connection_evidence,
                "why_risk_remains": why_risk_remains,
                "why_not_remediated": why_not_remediated,
                "recommended_manual_mitigation": (
                    f"{finding.remediation} Apply least-privilege controls and "
                    "review the listed connections before making manual changes."
                ),
                "potential_operational_impact": (
                    "Restricting or removing these connections may interrupt traffic "
                    f"described as: {reasons}. Test and coordinate changes with the "
                    "affected service owners."
                ),
            }
        )

    return {
        "residual_explanations": residual_explanations,
        "remaining_path_explanations": path_explanations,
    }
