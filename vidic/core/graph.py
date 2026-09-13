# IOC Relationship Graph (Phase 7)
#
# Builds an in-memory graph connecting analyzed emails to the
# indicators (domains/IPs/URLs/emails/hashes) they contained, using the
# ioc_nodes/email_ioc_edges tables in vidic_history.db. Two emails that
# share an indicator end up connected THROUGH that shared node - which
# surfaces reused phishing infrastructure across separate investigations
# without needing any separate similarity/clustering logic.
#
# Uses NetworkX (pure Python, in-memory) rather than a real graph
# database server, since the whole point of this feature is spotting
# infrastructure reuse across a local investigation history that is at
# most a few thousand entries - a full graph DB would be a heavy
# dependency for that scale, and would break the "clone and run, no
# external services" setup the rest of VIDIC follows.

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from vidic.core import db

EMAIL_NODE_PREFIX = "email:"
IOC_NODE_PREFIX = "ioc:"


@dataclass
class GraphStats:
    email_count: int = 0
    ioc_count: int = 0
    edge_count: int = 0
    shared_ioc_count: int = 0  # IOCs that appear in more than one email


def _email_node_id(analysis_id: int) -> str:
    return f"{EMAIL_NODE_PREFIX}{analysis_id}"


def _ioc_node_id(ioc_type: str, ioc_value: str) -> str:
    return f"{IOC_NODE_PREFIX}{ioc_type}:{ioc_value}"


def build_graph() -> nx.Graph:
    """Builds the full IOC relationship graph from history DB data.

    Node attributes:
      - kind: "email" or "ioc"
      - email nodes: analysis_id, subject, verdict, risk_score
      - ioc nodes: ioc_type, ioc_value

    This is rebuilt fresh from the database on every call rather than
    cached, since history entries can be added/renamed/deleted between
    calls and the graph is small enough that rebuilding is cheap.
    """
    analyses, edges = db.get_ioc_graph_data()

    graph = nx.Graph()

    for analysis in analyses:
        node_id = _email_node_id(analysis["id"])
        display_name = analysis.get("label") or analysis["subject"]
        graph.add_node(
            node_id,
            kind="email",
            analysis_id=analysis["id"],
            subject=display_name,
            verdict=analysis["verdict"],
            risk_score=analysis["risk_score"],
        )

    for edge in edges:
        email_node = _email_node_id(edge["analysis_id"])
        if email_node not in graph:
            # Edge points at an analysis that no longer exists (e.g. it
            # was deleted between the two queries in get_ioc_graph_data).
            # Skip rather than create a dangling node.
            continue

        ioc_node = _ioc_node_id(edge["type"], edge["value"])
        if ioc_node not in graph:
            graph.add_node(ioc_node, kind="ioc", ioc_type=edge["type"], ioc_value=edge["value"])

        graph.add_edge(email_node, ioc_node)

    return graph


def get_stats(graph: nx.Graph | None = None) -> GraphStats:
    """Summary counts for display (e.g. in a graph view's title bar)."""
    graph = graph if graph is not None else build_graph()

    email_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "email"]
    ioc_nodes = [n for n, d in graph.nodes(data=True) if d.get("kind") == "ioc"]
    shared = [n for n in ioc_nodes if graph.degree(n) > 1]

    return GraphStats(
        email_count=len(email_nodes),
        ioc_count=len(ioc_nodes),
        edge_count=graph.number_of_edges(),
        shared_ioc_count=len(shared),
    )


def get_neighborhood(graph: nx.Graph, analysis_id: int, hops: int = 1) -> nx.Graph:
    """Returns the subgraph reachable from one specific analyzed email
    within `hops` steps - e.g. hops=1 gives that email plus every IOC it
    contains; hops=2 additionally pulls in every OTHER email that shares
    one of those IOCs. Used to focus the view on "what else is connected
    to this specific investigation" rather than the whole history at once.
    """
    center = _email_node_id(analysis_id)
    if center not in graph:
        return nx.Graph()

    reachable = nx.single_source_shortest_path_length(graph, center, cutoff=hops)
    return graph.subgraph(reachable.keys()).copy()


def find_shared_ioc_clusters(graph: nx.Graph | None = None) -> list[dict]:
    """Returns groups of emails connected through at least one shared
    IOC, sorted by cluster size (largest/most-connected first). Each
    entry describes one connected component of the graph that includes
    more than one email node - i.e. actual infrastructure reuse, not
    isolated single-email nodes with no relationships."""
    graph = graph if graph is not None else build_graph()

    clusters = []
    for component in nx.connected_components(graph):
        email_nodes = [n for n in component if graph.nodes[n].get("kind") == "email"]
        if len(email_nodes) < 2:
            continue

        shared_iocs = [
            graph.nodes[n]
            for n in component
            if graph.nodes[n].get("kind") == "ioc" and graph.degree(n) > 1
        ]

        clusters.append({
            "emails": [graph.nodes[n] for n in email_nodes],
            "shared_iocs": shared_iocs,
            "size": len(email_nodes),
        })

    clusters.sort(key=lambda c: c["size"], reverse=True)
    return clusters