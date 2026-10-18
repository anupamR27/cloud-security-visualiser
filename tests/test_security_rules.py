import unittest

from graph_builder import build_graph
from scenarios import load_scenario
from security_rules import (
    find_public_database_exposures,
    find_public_ssh_exposures,
)


class SecurityRuleTests(unittest.TestCase):
    def test_finds_public_ssh_exposure(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))

        findings = find_public_ssh_exposures(graph)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].resource, "web-server")
        self.assertEqual(findings[0].severity, "high")

    def test_ignores_restricted_ssh(self) -> None:
        graph = build_graph(load_scenario("secure"))

        self.assertEqual(find_public_ssh_exposures(graph), [])

    def test_finds_public_database_exposure(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))
        graph.add_edge(
            "internet",
            "database",
            protocol="TCP",
            port=5432,
            reason="Public database access",
        )

        findings = find_public_database_exposures(graph)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].resource, "database")
        self.assertEqual(findings[0].severity, "critical")

    def test_ignores_private_database_connection(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))

        self.assertEqual(find_public_database_exposures(graph), [])
