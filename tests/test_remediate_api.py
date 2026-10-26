import copy
import unittest
from unittest.mock import ANY, Mock, call, patch

from fastapi.testclient import TestClient

from main import analyze_scenario, app
from remediation import remediate_scenario
from risk_explanations import explain_residual_risks


class RemediateApiTests(unittest.TestCase):
    client = TestClient(app)

    def setUp(self) -> None:
        self.vulnerable_scenario = {
            "id": "custom-vulnerable",
            "name": "Custom vulnerable infrastructure",
            "description": "Contains targeted and residual risks.",
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
            ],
        }
        self.secure_scenario = {
            "id": "custom-secure",
            "name": "Custom secure infrastructure",
            "description": "Contains no supported risks.",
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
            ],
            "edges": [
                {
                    "source": "internet",
                    "target": "web-server",
                    "protocol": "TCP",
                    "port": 443,
                    "reason": "Public HTTPS",
                }
            ],
        }

    def test_valid_vulnerable_configuration_returns_combined_result(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(response.json()),
            {
                "original_scan",
                "proposed_configuration",
                "changes",
                "verification_scan",
                "before_after",
                "remaining_findings",
                "remaining_attack_paths",
                "residual_explanations",
                "remaining_path_explanations",
                "security_status",
            },
        )

    def test_returns_correct_original_scan_findings(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        findings = response.json()["original_scan"]["findings"]
        self.assertEqual(
            [(finding["resource"], finding["severity"]) for finding in findings],
            [("web-server", "high"), ("database", "critical")],
        )

    def test_returns_correct_proposed_configuration(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        expected = {
            **self.vulnerable_scenario,
            "edges": [
                self.vulnerable_scenario["edges"][1],
                self.vulnerable_scenario["edges"][2],
            ],
        }
        self.assertEqual(response.json()["proposed_configuration"], expected)

    def test_returns_structured_change_log(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        removed_edge = self.vulnerable_scenario["edges"][0]
        self.assertEqual(
            response.json()["changes"],
            [
                {
                    "source_node_id": "internet",
                    "target_node_id": "web-server",
                    "protocol": "TCP",
                    "port": 22,
                    "original_connection": removed_edge,
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

    def test_returns_correct_verification_findings_and_counts(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        result = response.json()
        self.assertEqual(
            result["verification_scan"]["summary"],
            {
                "total_resources": 3,
                "total_findings": 1,
                "high": 0,
                "critical": 1,
                "attack_paths": 1,
            },
        )
        self.assertEqual(
            result["before_after"],
            {"initial_findings": 2, "remaining_findings": 1},
        )
        self.assertEqual(
            result["remaining_findings"],
            result["verification_scan"]["findings"],
        )

    def test_returns_remaining_bfs_attack_path(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        result = response.json()
        expected_path = [["internet", "web-server", "database"]]
        self.assertEqual(result["verification_scan"]["attack_paths"], expected_path)
        self.assertEqual(result["remaining_attack_paths"], expected_path)

    def test_reports_residual_risks_when_findings_remain(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        self.assertEqual(response.json()["security_status"], "residual_risks")

    def test_reports_no_detected_risks_when_no_findings_remain(self) -> None:
        response = self.client.post("/api/remediate", json=self.secure_scenario)

        result = response.json()
        self.assertEqual(result["security_status"], "no_detected_risks")
        self.assertEqual(result["remaining_findings"], [])
        self.assertEqual(result["remaining_attack_paths"], [])
        self.assertEqual(result["residual_explanations"], [])
        self.assertEqual(result["remaining_path_explanations"], [])

    def test_explains_residual_path_finding_with_actual_evidence(self) -> None:
        response = self.client.post(
            "/api/remediate", json=self.vulnerable_scenario
        )

        explanation = response.json()["residual_explanations"][0]
        self.assertEqual(
            explanation["risk_classification"],
            "public_to_private_sensitive_attack_path",
        )
        self.assertEqual(
            explanation["affected_resource"],
            {"id": "database", "name": "Private database"},
        )
        self.assertEqual(explanation["severity"], "critical")
        self.assertEqual(
            explanation["finding_explanation"],
            (
                "A network path from the Internet reaches a private sensitive "
                "resource through a compute resource."
            ),
        )
        self.assertEqual(
            [
                (edge["port"], edge["reason"])
                for edge in explanation["connection_evidence"]
            ],
            [(443, "Public HTTPS"), (5432, "Application database access")],
        )
        self.assertIn(
            "potentially network-reachable",
            explanation["why_risk_remains"],
        )
        self.assertIn(
            "does not confirm compromise",
            explanation["why_risk_remains"],
        )
        self.assertIn("one permitted pass", explanation["why_not_remediated"])
        self.assertIn(
            "direct public SSH and database exposures",
            explanation["why_not_remediated"],
        )
        self.assertIn(
            "could break application functionality",
            explanation["why_not_remediated"],
        )
        self.assertIn(
            "least-privilege",
            explanation["recommended_manual_mitigation"],
        )
        self.assertIn(
            "interrupt",
            explanation["potential_operational_impact"],
        )

    def test_explains_every_parallel_connection_on_a_remaining_path(self) -> None:
        scenario = copy.deepcopy(self.vulnerable_scenario)
        scenario["edges"].insert(
            2,
            {
                "source": "internet",
                "target": "web-server",
                "protocol": "TCP",
                "port": 80,
                "reason": "Public HTTP redirect",
            },
        )

        response = self.client.post("/api/remediate", json=scenario)

        explanation = response.json()["remaining_path_explanations"][0]
        self.assertEqual(
            explanation["node_ids"],
            ["internet", "web-server", "database"],
        )
        self.assertEqual(
            explanation["resource_names"],
            ["Internet", "Web server", "Private database"],
        )
        self.assertEqual(
            explanation["display_path"],
            "Internet → Web server → Private database",
        )
        self.assertEqual(
            {
                key: explanation["hops"][0][key]
                for key in (
                    "source_id",
                    "source_name",
                    "target_id",
                    "target_name",
                )
            },
            {
                "source_id": "internet",
                "source_name": "Internet",
                "target_id": "web-server",
                "target_name": "Web server",
            },
        )
        self.assertEqual(
            [
                (
                    connection["protocol"],
                    connection["port"],
                    connection["reason"],
                )
                for connection in explanation["hops"][0]["connections"]
            ],
            [
                ("TCP", 80, "Public HTTP redirect"),
                ("TCP", 443, "Public HTTPS"),
            ],
        )
        self.assertEqual(
            [
                (connection["port"], connection["reason"])
                for connection in explanation["hops"][1]["connections"]
            ],
            [(5432, "Application database access")],
        )
        self.assertEqual(
            [
                connection["port"]
                for connection in explanation["preserved_connections"]
            ],
            [80, 443, 5432],
        )
        self.assertNotIn(
            22,
            [
                connection["port"]
                for connection in explanation["preserved_connections"]
            ],
        )
        self.assertIn(
            "potential network reachability",
            explanation["why_path_remains"],
        )
        self.assertIn(
            "manual architectural or security review",
            explanation["why_remediation_stopped"],
        )
        self.assertIn("least-privilege", explanation["manual_mitigation"])
        self.assertIn("interrupt", explanation["potential_operational_impact"])

    def test_configuration_without_eligible_changes_is_preserved(self) -> None:
        response = self.client.post("/api/remediate", json=self.secure_scenario)

        result = response.json()
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["proposed_configuration"], self.secure_scenario)
        self.assertEqual(
            result["before_after"],
            {"initial_findings": 0, "remaining_findings": 0},
        )

    def test_invalid_configuration_returns_unprocessable_entity(self) -> None:
        invalid_scenario = copy.deepcopy(self.vulnerable_scenario)
        del invalid_scenario["nodes"][0]["name"]

        response = self.client.post("/api/remediate", json=invalid_scenario)

        self.assertEqual(response.status_code, 422)
        self.assertIn("Field required", response.text)

    def test_original_configuration_remains_unchanged(self) -> None:
        original = copy.deepcopy(self.vulnerable_scenario)

        with patch(
            "main.remediate_scenario", wraps=remediate_scenario
        ) as remediate:
            self.client.post("/api/remediate", json=self.vulnerable_scenario)

        self.assertEqual(self.vulnerable_scenario, original)
        self.assertEqual(remediate.call_args.args[0].model_dump(), original)

    def test_calls_remediation_once_and_analyzer_twice_in_order(self) -> None:
        calls = Mock()
        with (
            patch("main.analyze_scenario", wraps=analyze_scenario) as analyze,
            patch("main.remediate_scenario", wraps=remediate_scenario) as remediate,
            patch(
                "main.explain_residual_risks", wraps=explain_residual_risks
            ) as explain,
        ):
            calls.attach_mock(analyze, "analyze")
            calls.attach_mock(remediate, "remediate")
            calls.attach_mock(explain, "explain")

            response = self.client.post(
                "/api/remediate", json=self.vulnerable_scenario
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(remediate.call_count, 1)
        self.assertEqual(explain.call_count, 1)
        self.assertEqual(
            calls.mock_calls,
            [
                call.analyze(ANY),
                call.remediate(ANY),
                call.analyze(ANY),
                call.explain(ANY, ANY, ANY),
            ],
        )

    def test_existing_scan_endpoints_remain_functional(self) -> None:
        predefined_response = self.client.post(
            "/api/scan", json={"scenario_id": "vulnerable"}
        )
        custom_response = self.client.post(
            "/api/scan-custom", json=self.secure_scenario
        )

        self.assertEqual(predefined_response.status_code, 200)
        self.assertEqual(
            set(predefined_response.json()),
            {"summary", "findings", "attack_paths", "events"},
        )
        self.assertEqual(custom_response.status_code, 200)
        self.assertEqual(
            custom_response.json()["security_status"],
            "no_detected_risks",
        )


if __name__ == "__main__":
    unittest.main()
