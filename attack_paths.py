from collections import deque

import networkx as nx


def find_sensitive_attack_path(
    graph: nx.DiGraph,
    events: list[dict[str, object]],
) -> list[str] | None:
    internet = next(
        (
            node_id
            for node_id, metadata in graph.nodes(data=True)
            if metadata["type"] == "internet"
        ),
        None,
    )
    if internet is None:
        return None

    start = (internet, False)
    queue = deque([start])
    visited = {start}
    parents: dict[tuple[str, bool], tuple[str, bool] | None] = {start: None}

    while queue:
        current, has_compute = queue.popleft()
        current_state = (current, has_compute)
        metadata = graph.nodes[current]
        events.append({"type": "node_visited", "node_id": current})

        if metadata["sensitive"] and not metadata["public"] and has_compute:
            path = []
            state: tuple[str, bool] | None = current_state
            while state is not None:
                path.append(state[0])
                state = parents[state]
            path.reverse()
            events.append({"type": "path_found", "path": path.copy()})
            return path

        next_has_compute = has_compute or metadata["type"] == "compute"
        for neighbor in graph.successors(current):
            ancestor: tuple[str, bool] | None = current_state
            while ancestor is not None and ancestor[0] != neighbor:
                ancestor = parents[ancestor]
            if ancestor is not None:
                continue

            next_state = (neighbor, next_has_compute)
            if next_state in visited:
                continue

            visited.add(next_state)
            parents[next_state] = current_state
            events.append(
                {
                    "type": "edge_traversed",
                    "source": current,
                    "target": neighbor,
                }
            )
            queue.append(next_state)

    return None
