from typing import Literal

from pydantic import BaseModel, Field


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
    nodes: list[Node]
    edges: list[Edge]


class Finding(BaseModel):
    resource: str
    severity: Literal["high", "critical"]
    explanation: str
    remediation: str
