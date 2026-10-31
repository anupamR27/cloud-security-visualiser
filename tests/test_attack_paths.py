import unittest

from attack_paths import find_sensitive_attack_path
from graph_builder import build_graph
from models import Scenario
from scenarios import load_scenario


class AttackPathTests(unittest.TestCase):
    def test_finds_vulnerable_scenario_path(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))
        events = []

        path = find_sensitive_attack_path(graph, events)

        self.assertEqual(path, ["internet", "web-server", "database"])

    def test_returns_none_for_secure_scenario(self) -> None:
        graph = build_graph(load_scenario("secure"))
        events = []

        self.assertIsNone(find_sensitive_attack_path(graph, events))

    def test_finds_path_from_any_internet_node(self) -> None:
        scenario_data = load_scenario("vulnerable").model_dump()
        scenario_data["nodes"].insert(
            0,
            {
                "id": "disconnected-internet",
                "name": "Disconnected Internet",
                "type": "internet",
                "public": True,
                "sensitive": False,
            },
        )
        graph = build_graph(Scenario.model_validate(scenario_data))
        events = []

        path = find_sensitive_attack_path(graph, events)

        self.assertEqual(path, ["internet", "web-server", "database"])

    def test_respects_edge_direction(self) -> None:
        graph = build_graph(load_scenario("vulnerable")).reverse(copy=True)
        events = []

        self.assertIsNone(find_sensitive_attack_path(graph, events))

    def test_handles_cycles(self) -> None:
        graph = build_graph(load_scenario("secure"))
        graph.add_edge(
            "web-server",
            "internet",
            protocol="TCP",
            port=443,
            reason="Cycle",
        )
        events = []

        self.assertIsNone(find_sensitive_attack_path(graph, events))
        self.assertEqual(
            [event["node_id"] for event in events if event["type"] == "node_visited"],
            ["internet", "web-server"],
        )

    def test_records_actual_exploration_order(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))
        events = []

        find_sensitive_attack_path(graph, events)

        self.assertEqual(
            events,
            [
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
            ],
        )

    def test_rejects_direct_sensitive_database_path(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))
        graph.remove_edge("internet", "web-server")
        graph.add_edge(
            "internet",
            "database",
            protocol="TCP",
            port=5432,
            reason="Direct database access",
        )
        events = []

        self.assertIsNone(find_sensitive_attack_path(graph, events))
