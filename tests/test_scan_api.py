import unittest

from fastapi.testclient import TestClient

from attack_paths import find_sensitive_attack_path
from graph_builder import build_graph
from main import app
from scenarios import load_scenario


class ScanApiTests(unittest.TestCase):
    client = TestClient(app)

    def test_scenario_graph_returns_nodes_and_edges(self) -> None:
        for scenario_id in ("secure", "vulnerable"):
            with self.subTest(scenario_id=scenario_id):
                scenario = load_scenario(scenario_id)

                response = self.client.get(f"/api/scenarios/{scenario_id}")

                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.json(),
                    {
                        "nodes": [node.model_dump() for node in scenario.nodes],
                        "edges": [edge.model_dump() for edge in scenario.edges],
                    },
                )

    def test_unknown_scenario_graph_returns_not_found(self) -> None:
        response = self.client.get("/api/scenarios/missing")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Unknown scenario: missing"})

    def test_secure_scenario_has_no_high_or_critical_findings(self) -> None:
        response = self.client.post("/api/scan", json={"scenario_id": "secure"})

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["attack_paths"], [])
        self.assertEqual(result["summary"]["high"], 0)
        self.assertEqual(result["summary"]["critical"], 0)

    def test_vulnerable_scenario_has_ssh_and_attack_path_findings(self) -> None:
        response = self.client.post(
            "/api/scan", json={"scenario_id": "vulnerable"}
        )

        self.assertEqual(response.status_code, 200)
        findings = response.json()["findings"]
        self.assertEqual(
            [(finding["resource"], finding["severity"]) for finding in findings],
            [("web-server", "high"), ("database", "critical")],
        )

    def test_returned_attack_path_matches_bfs_result(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))
        expected_path = find_sensitive_attack_path(graph, [])

        response = self.client.post(
            "/api/scan", json={"scenario_id": "vulnerable"}
        )

        self.assertEqual(response.json()["attack_paths"], [expected_path])

    def test_summary_counts_actual_results(self) -> None:
        response = self.client.post(
            "/api/scan", json={"scenario_id": "vulnerable"}
        )

        self.assertEqual(
            response.json()["summary"],
            {
                "total_resources": 3,
                "total_findings": 2,
                "high": 1,
                "critical": 1,
                "attack_paths": 1,
            },
        )

    def test_events_follow_execution_order(self) -> None:
        response = self.client.post(
            "/api/scan", json={"scenario_id": "vulnerable"}
        )

        self.assertEqual(
            response.json()["events"],
            [
                {"type": "scan_started"},
                {
                    "type": "finding_detected",
                    "resource": "web-server",
                    "severity": "high",
                },
                {"type": "node_visited", "node_id": "internet"},
                {
                    "type": "edge_traversed",
                    "source": "internet",
                    "target": "web-server",
                },
                {"type": "node_visited", "node_id": "web-server"},
                {
                    "type": "edge_traversed",
                    "source": "web-server",
                    "target": "database",
                },
                {"type": "node_visited", "node_id": "database"},
                {
                    "type": "path_found",
                    "path": ["internet", "web-server", "database"],
                },
                {
                    "type": "finding_detected",
                    "resource": "database",
                    "severity": "critical",
                },
                {"type": "scan_completed"},
            ],
        )

    def test_unknown_scenario_returns_not_found(self) -> None:
        response = self.client.post(
            "/api/scan", json={"scenario_id": "missing"}
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"detail": "Unknown scenario: missing"})


if __name__ == "__main__":
    unittest.main()
