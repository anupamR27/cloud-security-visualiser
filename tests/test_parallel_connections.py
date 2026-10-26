import unittest

from attack_paths import find_sensitive_attack_path
from graph_builder import build_graph
from models import Scenario
from security_rules import (
    find_public_database_exposures,
    find_public_ssh_exposures,
)


class ParallelConnectionTests(unittest.TestCase):
    def scenario_with_edges(self, edges: list[dict[str, object]]) -> Scenario:
        return Scenario.model_validate(
            {
                "id": "parallel-connections",
                "name": "Parallel connections",
                "description": "Exercises multiple connections per node pair.",
                "nodes": [
                    {
                        "id": "internet",
                        "name": "Internet",
                        "type": "internet",
                        "public": True,
                        "sensitive": False,
                    },
                    {
                        "id": "web-server",
                        "name": "Web server",
                        "type": "compute",
                        "public": True,
                        "sensitive": False,
                    },
                    {
                        "id": "database",
                        "name": "Private database",
                        "type": "database",
                        "public": False,
                        "sensitive": True,
                    },
                ],
                "edges": edges,
            }
        )

    def internet_edge(self, target: str, port: int) -> dict[str, object]:
        return {
            "source": "internet",
            "target": target,
            "protocol": "TCP",
            "port": port,
            "reason": f"Internet access on port {port}",
        }

    def test_graph_preserves_parallel_connections(self) -> None:
        scenario = self.scenario_with_edges(
            [
                self.internet_edge("web-server", 22),
                self.internet_edge("web-server", 443),
            ]
        )

        graph = build_graph(scenario)

        self.assertEqual(graph.number_of_edges("internet", "web-server"), 2)
        self.assertEqual(
            [edge["port"] for _, _, edge in graph.edges(data=True)],
            [22, 443],
        )

    def test_ssh_detection_is_independent_of_parallel_edge_order(self) -> None:
        for ports in ([22, 443], [443, 22]):
            with self.subTest(ports=ports):
                scenario = self.scenario_with_edges(
                    [self.internet_edge("web-server", port) for port in ports]
                )

                findings = find_public_ssh_exposures(build_graph(scenario))

                self.assertEqual(
                    [(finding.resource, finding.severity) for finding in findings],
                    [("web-server", "high")],
                )

    def test_database_detection_is_independent_of_parallel_edge_order(self) -> None:
        for ports in ([3306, 5432], [5432, 3306]):
            with self.subTest(ports=ports):
                scenario = self.scenario_with_edges(
                    [self.internet_edge("database", port) for port in ports]
                )

                findings = find_public_database_exposures(build_graph(scenario))

                self.assertEqual(len(findings), 2)
                self.assertEqual(
                    {finding.resource for finding in findings},
                    {"database"},
                )
                self.assertTrue(
                    all(finding.severity == "critical" for finding in findings)
                )

    def test_parallel_edges_keep_bfs_event_contract(self) -> None:
        scenario = self.scenario_with_edges(
            [
                self.internet_edge("web-server", 22),
                self.internet_edge("web-server", 443),
                {
                    "source": "web-server",
                    "target": "database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Application database access",
                },
            ]
        )
        events: list[dict[str, object]] = []

        path = find_sensitive_attack_path(build_graph(scenario), events)

        self.assertEqual(path, ["internet", "web-server", "database"])
        self.assertEqual(
            [event for event in events if event["type"] == "edge_traversed"],
            [
                {
                    "type": "edge_traversed",
                    "source": "internet",
                    "target": "web-server",
                },
                {
                    "type": "edge_traversed",
                    "source": "web-server",
                    "target": "database",
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
