import copy
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import ANY, Mock, call, patch

from fastapi.testclient import TestClient

import main
from main import app


PDFTOTEXT = shutil.which("pdftotext")


def extract_pdf_text(content: bytes) -> str:
    if PDFTOTEXT is None:
        raise unittest.SkipTest("pdftotext is not available")

    with tempfile.NamedTemporaryFile(suffix=".pdf") as pdf_file:
        pdf_file.write(content)
        pdf_file.flush()
        result = subprocess.run(
            [PDFTOTEXT, pdf_file.name, "-"],
            check=True,
            capture_output=True,
            text=True,
        )
    return result.stdout


class ReportApiTests(unittest.TestCase):
    client = TestClient(app)

    def setUp(self) -> None:
        self.vulnerable_scenario = {
            "id": "report-vulnerable",
            "name": "Report vulnerable infrastructure",
            "description": "Contains a removable exposure and a residual path.",
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
            "id": "report-secure",
            "name": "Report secure infrastructure",
            "description": "Contains no supported security findings.",
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

    def test_valid_scenario_returns_pdf_attachment(self) -> None:
        response = self.client.post(
            "/api/report", json=self.vulnerable_scenario
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/pdf")
        self.assertIn("attachment", response.headers["content-disposition"])
        self.assertIn(".pdf", response.headers["content-disposition"])
        self.assertTrue(response.content.startswith(b"%PDF"))

    def test_invalid_scenario_returns_unprocessable_entity(self) -> None:
        invalid_scenario = copy.deepcopy(self.vulnerable_scenario)
        del invalid_scenario["nodes"][0]["name"]

        response = self.client.post("/api/report", json=invalid_scenario)

        self.assertEqual(response.status_code, 422)
        self.assertIn("Field required", response.text)

    @unittest.skipUnless(PDFTOTEXT, "pdftotext is not available")
    def test_vulnerable_report_contains_findings_changes_and_residuals(self) -> None:
        response = self.client.post(
            "/api/report", json=self.vulnerable_scenario
        )

        text = extract_pdf_text(response.content)
        self.assertIn("Initial Security Findings", text)
        self.assertIn("accepts SSH connections directly from the Internet", text)
        self.assertIn("Proposed Security Changes", text)
        self.assertIn("remove connection", text)
        self.assertIn("Residual risks remain", text)
        self.assertIn("TCP/443", text)
        self.assertIn("TCP/5432", text)
        self.assertIn("potential network reachability", text)

    @unittest.skipUnless(PDFTOTEXT, "pdftotext is not available")
    def test_secure_report_contains_empty_states(self) -> None:
        response = self.client.post("/api/report", json=self.secure_scenario)

        text = extract_pdf_text(response.content)
        self.assertIn("No initial security findings were detected", text)
        self.assertIn("No security changes were proposed", text)
        self.assertIn("No detected risks remain", text)
        self.assertIn("No residual findings remain", text)
        self.assertIn("No remaining potential attack paths were detected", text)

    @unittest.skipUnless(PDFTOTEXT, "pdftotext is not available")
    def test_parallel_connections_are_all_included(self) -> None:
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

        response = self.client.post("/api/report", json=scenario)

        text = extract_pdf_text(response.content)
        self.assertIn("TCP/80", text)
        self.assertIn("Public HTTP redirect", text)
        self.assertIn("TCP/443", text)
        self.assertIn("Public HTTPS", text)

    def test_original_configuration_remains_unchanged(self) -> None:
        original = copy.deepcopy(self.vulnerable_scenario)

        response = self.client.post(
            "/api/report", json=self.vulnerable_scenario
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.vulnerable_scenario, original)

    def test_runs_one_remediation_and_two_analyses(self) -> None:
        calls = Mock()
        with (
            patch(
                "main.analyze_scenario", wraps=main.analyze_scenario
            ) as analyze,
            patch(
                "main.remediate_scenario", wraps=main.remediate_scenario
            ) as remediate,
            patch(
                "main.explain_residual_risks",
                wraps=main.explain_residual_risks,
            ) as explain,
            patch(
                "main.generate_security_report",
                wraps=main.generate_security_report,
            ) as generate,
        ):
            calls.attach_mock(analyze, "analyze")
            calls.attach_mock(remediate, "remediate")
            calls.attach_mock(explain, "explain")
            calls.attach_mock(generate, "generate")

            response = self.client.post(
                "/api/report", json=self.vulnerable_scenario
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(remediate.call_count, 1)
        self.assertEqual(explain.call_count, 1)
        self.assertEqual(generate.call_count, 1)
        self.assertEqual(
            calls.mock_calls,
            [
                call.analyze(ANY),
                call.remediate(ANY),
                call.analyze(ANY),
                call.explain(ANY, ANY, ANY),
                call.generate(ANY, ANY),
            ],
        )

    def test_long_content_and_multiple_findings_generate_successfully(self) -> None:
        scenario = copy.deepcopy(self.vulnerable_scenario)
        scenario["name"] = "Cloud <Production> & Security Review"
        scenario["description"] = "Long <assessment> & description. " * 300
        scenario["nodes"][1]["name"] = "Web server with a long name " * 8
        scenario["edges"][1]["reason"] = "Required HTTPS traffic. " * 30

        response = self.client.post("/api/report", json=scenario)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content.startswith(b"%PDF"))
        self.assertGreater(len(response.content), 1000)


if __name__ == "__main__":
    unittest.main()
