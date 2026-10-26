from models import Scenario
from security_rules import DATABASE_PORTS


def remediate_scenario(
    scenario: Scenario,
) -> tuple[Scenario, list[dict[str, object]]]:
    node_types = {node.id: node.type for node in scenario.nodes}
    retained_edges = []
    changes: list[dict[str, object]] = []

    for edge in scenario.edges:
        is_direct_internet_connection = node_types[edge.source] == "internet"
        is_tcp = edge.protocol.upper() == "TCP"
        target_type = node_types[edge.target]

        if (
            is_direct_internet_connection
            and target_type == "compute"
            and is_tcp
            and edge.port == 22
        ):
            security_risk = "public_ssh_exposure"
            reason = "SSH on TCP port 22 is directly exposed to the Internet."
            operational_impact = (
                "Direct Internet-based SSH access to the compute resource will "
                "no longer use this connection."
            )
        elif (
            is_direct_internet_connection
            and target_type == "database"
            and is_tcp
            and edge.port in DATABASE_PORTS
        ):
            security_risk = "public_database_exposure"
            reason = (
                f"The database is directly exposed to the Internet on TCP port "
                f"{edge.port}."
            )
            operational_impact = (
                "Direct Internet-based database access will no longer use this "
                "connection."
            )
        else:
            retained_edges.append(edge.model_dump())
            continue

        changes.append(
            {
                "source_node_id": edge.source,
                "target_node_id": edge.target,
                "protocol": edge.protocol,
                "port": edge.port,
                "original_connection": edge.model_dump(),
                "proposed_action": "remove_connection",
                "associated_security_risk": security_risk,
                "reason": reason,
                "potential_operational_impact": operational_impact,
            }
        )

    proposed_data = scenario.model_dump(exclude={"edges"})
    proposed_data["edges"] = retained_edges
    proposed_scenario = Scenario.model_validate(proposed_data)

    return proposed_scenario, changes
