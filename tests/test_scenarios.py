import unittest

from pydantic import ValidationError

from models import Edge
from scenarios import load_scenario


class ScenarioLoadingTests(unittest.TestCase):
    def test_loads_secure_scenario(self) -> None:
        scenario = load_scenario("secure")

        self.assertEqual(scenario.id, "secure")
        self.assertEqual(len(scenario.nodes), 4)
        self.assertEqual(len(scenario.edges), 2)

    def test_loads_vulnerable_scenario(self) -> None:
        scenario = load_scenario("vulnerable")

        self.assertEqual(scenario.id, "vulnerable")
        self.assertEqual([edge.port for edge in scenario.edges], [22, 5432])

    def test_rejects_unknown_scenario(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unknown scenario"):
            load_scenario("missing")

    def test_rejects_invalid_port(self) -> None:
        with self.assertRaises(ValidationError):
            Edge(
                source="internet",
                target="web-server",
                protocol="TCP",
                port=70000,
                reason="Invalid connection",
            )

