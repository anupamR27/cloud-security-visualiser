from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator


MAX_SCENARIO_NODES = 100
MAX_SCENARIO_EDGES = 500


class Node(BaseModel):
    id: str
    name: str
    type: Literal["internet", "compute", "database"]
    public: bool
    sensitive: bool


class Edge(BaseModel):
    source: str
    target: str
    protocol: str
    port: int = Field(ge=1, le=65535)
    reason: str


class Scenario(BaseModel):
    id: str
    name: str
    description: str
    nodes: list[Node] = Field(max_length=MAX_SCENARIO_NODES)
    edges: list[Edge] = Field(max_length=MAX_SCENARIO_EDGES)

    @model_validator(mode="after")
    def validate_graph_references(self) -> Self:
        node_ids = [node.id for node in self.nodes]
        duplicate_ids = sorted(
            node_id for node_id in set(node_ids) if node_ids.count(node_id) > 1
        )
        if duplicate_ids:
            raise ValueError(
                f"Duplicate node IDs are not allowed: {', '.join(duplicate_ids)}"
            )

        known_node_ids = set(node_ids)
        missing_node_ids = sorted(
            {
                node_id
                for edge in self.edges
                for node_id in (edge.source, edge.target)
                if node_id not in known_node_ids
            }
        )
        if missing_node_ids:
            raise ValueError(
                "Edges reference nonexistent node IDs: "
                f"{', '.join(missing_node_ids)}"
            )

        return self


class Finding(BaseModel):
    resource: str
    severity: Literal["high", "critical"]
    explanation: str
    remediation: str


class ScanRequest(BaseModel):
    scenario_id: str
