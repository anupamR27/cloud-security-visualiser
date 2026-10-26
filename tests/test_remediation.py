import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app
from models import Scenario
from remediation import remediate_scenario


class RemediationTests(unittest.TestCase):
    client = TestClient(app)

    def scenario_with_edges(self, edges: list[dict[str, object]]) -> Scenario:
        return Scenario.model_validate(
            {
                "id": "remediation-test",
                "name": "Remediation test",
                "description": "Infrastructure used to test one-pass remediation.",
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
                        "id": "app-server",
                        "name": "Application server",
                        "type": "compute",
                        "public": False,
                        "sensitive": False,
                    },
                    {
                        "id": "database",
                        "name": "PostgreSQL database",
                        "type": "database",
                        "public": False,
                        "sensitive": True,
                    },
                    {
                        "id": "mysql-database",
                        "name": "MySQL database",
                        "type": "database",
                        "public": True,
                        "sensitive": False,
                    },
                ],
                "edges": edges,
            }
        )

    def test_original_scenario_remains_unchanged_and_independent(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "reason": "Public SSH",
                },
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 443,
                    "reason": "Public HTTPS",
                },
            ]
        )
        original_data = scenario.model_dump()

        proposed, _ = remediate_scenario(scenario)
        proposed.nodes[0].name = "Changed proposed node"
        proposed.edges[0].reason = "Changed proposed edge"

        self.assertEqual(scenario.model_dump(), original_data)

    def test_removes_direct_public_ssh_connection(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "tcp",
                    "port": 22,
                    "reason": "Public SSH",
                }
            ]
        )

        proposed, changes = remediate_scenario(scenario)

        self.assertEqual(proposed.edges, [])
        self.assertEqual(changes[0]["associated_security_risk"], "public_ssh_exposure")

    def test_removes_direct_public_mysql_connection(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "mysql-database",
                    "protocol": "TCP",
                    "port": 3306,
                    "reason": "Public MySQL",
                }
            ]
        )

        proposed, changes = remediate_scenario(scenario)

        self.assertEqual(proposed.edges, [])
        self.assertEqual(
            changes[0]["associated_security_risk"],
            "public_database_exposure",
        )

    def test_removes_direct_public_postgresql_connection(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Public PostgreSQL",
                }
            ]
        )

        proposed, _ = remediate_scenario(scenario)

        self.assertEqual(proposed.edges, [])

    def test_preserves_internet_to_compute_https(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "reason": "Public SSH",
                },
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 443,
                    "reason": "Public HTTPS",
                },
            ]
        )

        proposed, _ = remediate_scenario(scenario)

        self.assertEqual(
            [edge.model_dump() for edge in proposed.edges],
            [scenario.edges[1].model_dump()],
        )

    def test_preserves_application_to_database_connection(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Public PostgreSQL",
                },
                {
                    "source": "app-server",
                    "target": "database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Application database access",
                },
            ]
        )

        proposed, _ = remediate_scenario(scenario)

        self.assertEqual(
            [edge.model_dump() for edge in proposed.edges],
            [scenario.edges[1].model_dump()],
        )

    def test_secure_scenario_produces_no_changes(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 443,
                    "reason": "Public HTTPS",
                },
                {
                    "source": "app-server",
                    "target": "database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Application database access",
                },
            ]
        )

        proposed, changes = remediate_scenario(scenario)

        self.assertEqual(proposed.model_dump(), scenario.model_dump())
        self.assertEqual(changes, [])

    def test_removes_multiple_exposures_in_input_order(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Public PostgreSQL",
                },
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "reason": "Public SSH",
                },
                {
                    "source": "internet",
                    "target": "mysql-database",
                    "protocol": "TCP",
                    "port": 3306,
                    "reason": "Public MySQL",
                },
            ]
        )

        proposed, changes = remediate_scenario(scenario)

        self.assertEqual(proposed.edges, [])
        self.assertEqual(
            [change["target_node_id"] for change in changes],
            ["database", "web-server", "mysql-database"],
        )

    def test_change_log_describes_removed_connection(self) -> None:
        edge = {
            "source": "internet",
            "target": "web-server",
            "protocol": "TCP",
            "port": 22,
            "reason": "Public SSH",
        }
        scenario = self.scenario_with_edges([edge])

        _, changes = remediate_scenario(scenario)

        self.assertEqual(
            changes,
            [
                {
                    "source_node_id": "internet",
                    "target_node_id": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "original_connection": edge,
                    "proposed_action": "remove_connection",
                    "associated_security_risk": "public_ssh_exposure",
                    "reason": (
                        "SSH on TCP port 22 is directly exposed to the Internet."
                    ),
                    "potential_operational_impact": (
                        "Direct Internet-based SSH access to the compute resource "
                        "will no longer use this connection."
                    ),
                }
            ],
        )

    def test_proposed_scenario_passes_pydantic_validation(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "reason": "Public SSH",
                }
            ]
        )

        proposed, _ = remediate_scenario(scenario)

        self.assertEqual(
            Scenario.model_validate(proposed.model_dump()),
            proposed,
        )

    def test_existing_scan_endpoints_remain_unchanged(self) -> None:
        predefined_response = self.client.post(
            "/api/scan", json={"scenario_id": "vulnerable"}
        )
        custom_scenario = self.scenario_with_edges([])
        custom_response = self.client.post(
            "/api/scan-custom", json=custom_scenario.model_dump()
        )

        self.assertEqual(predefined_response.status_code, 200)
        self.assertNotIn("security_status", predefined_response.json())
        self.assertEqual(custom_response.status_code, 200)
        self.assertEqual(
            custom_response.json()["security_status"],
            "no_detected_risks",
        )

    def test_remediation_does_not_scan_or_repeat(self) -> None:
        scenario = self.scenario_with_edges(
            [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "reason": "Public SSH",
                },
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 443,
                    "reason": "Public HTTPS",
                },
                {
                    "source": "web-server",
                    "target": "database",
                    "protocol": "TCP",
                    "port": 5432,
                    "reason": "Application database access",
                },
            ]
        )

        with (
            patch("main.analyze_scenario") as analyze_scenario,
            patch("attack_paths.find_sensitive_attack_path") as find_attack_path,
        ):
            proposed, changes = remediate_scenario(scenario)

        analyze_scenario.assert_not_called()
        find_attack_path.assert_not_called()
        self.assertEqual(len(changes), 1)
        self.assertEqual(
            [(edge.source, edge.target, edge.port) for edge in proposed.edges],
            [
                ("internet", "web-server", 443),
                ("web-server", "database", 5432),
            ],
        )


if __name__ == "__main__":
    unittest.main()
