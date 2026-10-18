import networkx as nx

from models import Scenario


def build_graph(scenario: Scenario) -> nx.DiGraph:
    graph = nx.DiGraph()

    for node in scenario.nodes:
        graph.add_node(
            node.id,
            name=node.name,
            type=node.type,
            public=node.public,
            sensitive=node.sensitive,
        )

    for edge in scenario.edges:
        graph.add_edge(
            edge.source,
            edge.target,
            protocol=edge.protocol,
            port=edge.port,
            reason=edge.reason,
        )

    return graph
