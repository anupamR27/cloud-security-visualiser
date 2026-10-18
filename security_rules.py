import networkx as nx

from models import Finding


DATABASE_PORTS = {3306, 5432}


def find_public_ssh_exposures(graph: nx.DiGraph) -> list[Finding]:
    findings = []

    for source, target, edge in graph.edges(data=True):
        if (
            graph.nodes[source]["type"] == "internet"
            and graph.nodes[target]["type"] == "compute"
            and edge["protocol"].upper() == "TCP"
            and edge["port"] == 22
        ):
            findings.append(
                Finding(
                    resource=target,
                    severity="high",
                    explanation=(
                        f'{graph.nodes[target]["name"]} accepts SSH connections '
                        "directly from the Internet."
                    ),
                    remediation=(
                        "Restrict TCP port 22 to trusted administrative networks."
                    ),
                )
            )

    return findings


def find_public_database_exposures(graph: nx.DiGraph) -> list[Finding]:
    findings = []

    for source, target, edge in graph.edges(data=True):
        if (
            graph.nodes[source]["type"] == "internet"
            and graph.nodes[target]["type"] == "database"
            and edge["protocol"].upper() == "TCP"
            and edge["port"] in DATABASE_PORTS
        ):
            severity = (
                "critical" if graph.nodes[target]["sensitive"] else "high"
            )
            findings.append(
                Finding(
                    resource=target,
                    severity=severity,
                    explanation=(
                        f'{graph.nodes[target]["name"]} is directly accessible '
                        f'from the Internet on TCP port {edge["port"]}.'
                    ),
                    remediation=(
                        "Remove public database access and restrict the port to "
                        "approved application resources."
                    ),
                )
            )

    return findings
