import copy
import unittest

from fastapi.testclient import TestClient

from main import app


class ScanCustomApiTests(unittest.TestCase):
    client = TestClient(app)

    def setUp(self) -> None:
        self.vulnerable_scenario = {
            "id": "custom-vulnerable",
            "name": "Custom vulnerable infrastructure",
            "description": "Exercises every existing security check.",
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
                    "id": "private-database",
                    "name": "Private database",
                    "type": "database",
                    "public": False,
                    "sensitive": True,
                },
                {
                    "id": "public-database",
                    "name": "Public database",
                    "type": "database",
                    "public": True,
                    "sensitive": True,
                },
            ],
            "edges": [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "reason": "Public SSH access",
                },
                {
                    "source": "web-server",
                    "target": "private-database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Application database access",
                },
                {
                    "source": "internet",
                    "target": "public-database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Public database access",
                },
            ],
        }
        self.secure_scenario = {
            "id": "custom-secure",
            "name": "Custom secure infrastructure",
            "description": "Contains no detected risks.",
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
            "edges": [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 443,
                    "reason": "Public HTTPS access",
                }
            ],
        }

    def test_valid_vulnerable_configuration_returns_scan_result(self) -> None:
        response = self.client.post(
            "/api/scan-custom", json=self.vulnerable_scenario
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(response.json()),
            {"summary", "findings", "attack_paths", "events", "security_status"},
        )

    def test_valid_secure_configuration_has_no_detected_risks(self) -> None:
        response = self.client.post(
            "/api/scan-custom", json=self.secure_scenario
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["findings"], [])
        self.assertEqual(response.json()["attack_paths"], [])
        self.assertEqual(response.json()["security_status"], "no_detected_risks")

    def test_returns_correct_findings_and_attack_path(self) -> None:
        response = self.client.post(
            "/api/scan-custom", json=self.vulnerable_scenario
        )

        result = response.json()
        self.assertEqual(
            [
                (finding["resource"], finding["severity"])
                for finding in result["findings"]
            ],
            [
                ("web-server", "high"),
                ("public-database", "critical"),
                ("private-database", "critical"),
            ],
        )
        self.assertEqual(
            result["attack_paths"],
            [["internet", "web-server", "private-database"]],
        )
        self.assertEqual(
            result["summary"],
            {
                "total_resources": 4,
                "total_findings": 3,
                "high": 1,
                "critical": 2,
                "attack_paths": 1,
            },
        )

    def test_returns_traversal_events_in_execution_order(self) -> None:
        response = self.client.post(
            "/api/scan-custom", json=self.vulnerable_scenario
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
                {
                    "type": "finding_detected",
                    "resource": "public-database",
                    "severity": "critical",
                },
                {"type": "node_visited", "node_id": "internet"},
                {
                    "type": "edge_traversed",
                    "source": "internet",
                    "target": "web-server",
                },
                {
                    "type": "edge_traversed",
                    "source": "internet",
                    "target": "public-database",
                },
                {"type": "node_visited", "node_id": "web-server"},
                {
                    "type": "edge_traversed",
                    "source": "web-server",
                    "target": "private-database",
                },
                {"type": "node_visited", "node_id": "public-database"},
                {"type": "node_visited", "node_id": "private-database"},
                {
                    "type": "path_found",
                    "path": ["internet", "web-server", "private-database"],
                },
                {
                    "type": "finding_detected",
                    "resource": "private-database",
                    "severity": "critical",
                },
                {"type": "scan_completed"},
            ],
        )

    def test_invalid_configuration_returns_unprocessable_entity(self) -> None:
        invalid_scenario = copy.deepcopy(self.vulnerable_scenario)
        del invalid_scenario["nodes"][0]["name"]

        response = self.client.post("/api/scan-custom", json=invalid_scenario)

        self.assertEqual(response.status_code, 422)
        self.assertIn("Field required", response.text)

    def test_existing_scan_endpoint_keeps_its_response_structure(self) -> None:
        response = self.client.post(
            "/api/scan", json={"scenario_id": "vulnerable"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(response.json()),
            {"summary", "findings", "attack_paths", "events"},
        )

    def test_vulnerable_status_matches_nonempty_findings(self) -> None:
        response = self.client.post(
            "/api/scan-custom", json=self.vulnerable_scenario
        )

        self.assertTrue(response.json()["findings"])
        self.assertEqual(response.json()["security_status"], "vulnerable")


if __name__ == "__main__":
    unittest.main()
