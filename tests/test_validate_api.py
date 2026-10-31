import unittest

from fastapi.testclient import TestClient

from main import app
from models import MAX_SCENARIO_EDGES, MAX_SCENARIO_NODES


class ValidateApiTests(unittest.TestCase):
    client = TestClient(app)

    def setUp(self) -> None:
        self.scenario = {
            "id": "custom",
            "name": "Custom infrastructure",
            "description": "A user-provided scenario.",
            "nodes": [
                {
                    "id": "internet",
                    "name": "Internet",
                    "type": "internet",
                    "public": True,
                    "sensitive": False,
                },
                {
                    "id": "database",
                    "name": "Database",
                    "type": "database",
                    "public": False,
                    "sensitive": True,
                },
            ],
            "edges": [
                {
                    "source": "internet",
                    "target": "database",
                    "protocol": "tcp",
                    "port": 5432,
                    "reason": "Database access",
                }
            ],
        }

    def test_valid_configuration_returns_graph_preview_and_counts(self) -> None:
        response = self.client.post("/api/validate", json=self.scenario)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "nodes": self.scenario["nodes"],
                "edges": self.scenario["edges"],
                "summary": {"total_resources": 2, "total_edges": 1},
            },
        )

    def test_graph_preview_preserves_parallel_connections(self) -> None:
        self.scenario["edges"].append(
            {
                "source": "internet",
                "target": "database",
                "protocol": "TCP",
                "port": 3306,
                "reason": "MySQL database access",
            }
        )

        response = self.client.post("/api/validate", json=self.scenario)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["edges"], self.scenario["edges"])
        self.assertEqual(response.json()["summary"]["total_edges"], 2)

    def test_rejects_invalid_node_type(self) -> None:
        self.scenario["nodes"][0]["type"] = "bucket"

        response = self.client.post("/api/validate", json=self.scenario)

        self.assertEqual(response.status_code, 422)
        self.assertIn("type", response.text)

    def test_rejects_missing_required_field(self) -> None:
        del self.scenario["nodes"][0]["name"]

        response = self.client.post("/api/validate", json=self.scenario)

        self.assertEqual(response.status_code, 422)
        self.assertIn("Field required", response.text)

    def test_rejects_duplicate_node_ids(self) -> None:
        self.scenario["nodes"].append(
            {
                **self.scenario["nodes"][0],
                "name": "Duplicate Internet",
            }
        )

        response = self.client.post("/api/validate", json=self.scenario)

        self.assertEqual(response.status_code, 422)
        self.assertIn("Duplicate node IDs are not allowed: internet", response.text)

    def test_rejects_edge_referencing_nonexistent_node(self) -> None:
        self.scenario["edges"][0]["target"] = "missing-database"

        response = self.client.post("/api/validate", json=self.scenario)

        self.assertEqual(response.status_code, 422)
        self.assertIn(
            "Edges reference nonexistent node IDs: missing-database",
            response.text,
        )

    def test_rejects_malformed_and_out_of_range_ports(self) -> None:
        for port in ("postgres", 0, 65536):
            with self.subTest(port=port):
                self.scenario["edges"][0]["port"] = port

                response = self.client.post("/api/validate", json=self.scenario)

                self.assertEqual(response.status_code, 422)
                self.assertIn("port", response.text)

    def test_rejects_oversized_configurations(self) -> None:
        oversized_nodes = {
            **self.scenario,
            "nodes": [
                {
                    "id": f"node-{index}",
                    "name": f"Node {index}",
                    "type": "compute",
                    "public": False,
                    "sensitive": False,
                }
                for index in range(MAX_SCENARIO_NODES + 1)
            ],
            "edges": [],
        }
        oversized_edges = {
            **self.scenario,
            "edges": self.scenario["edges"] * (MAX_SCENARIO_EDGES + 1),
        }

        for payload, field in (
            (oversized_nodes, "nodes"),
            (oversized_edges, "edges"),
        ):
            with self.subTest(field=field):
                response = self.client.post("/api/validate", json=payload)

                self.assertEqual(response.status_code, 422)
                self.assertIn(field, response.text)


if __name__ == "__main__":
    unittest.main()
