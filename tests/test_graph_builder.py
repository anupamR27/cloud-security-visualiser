import unittest

from graph_builder import build_graph
from scenarios import load_scenario


class GraphBuilderTests(unittest.TestCase):
    def test_builds_directed_graph_with_metadata(self) -> None:
        graph = build_graph(load_scenario("vulnerable"))

        self.assertTrue(graph.has_edge("internet", "web-server"))
        self.assertFalse(graph.has_edge("web-server", "internet"))
        self.assertEqual(graph.nodes["database"]["sensitive"], True)
        self.assertEqual(graph.edges["internet", "web-server", 0]["port"], 22)
