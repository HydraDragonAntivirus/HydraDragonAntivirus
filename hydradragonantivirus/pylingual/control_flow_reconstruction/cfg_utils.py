import networkx as nx

from typing import Callable, Any

from pylingual.editable_bytecode.control_flow_graph import ControlFlowEdgeType


def get_out_edge_dict(cfg: nx.DiGraph, node) -> dict:
    edge_dict = {"natural": (None, None), "conditional": (None, None), "exception": (None, None)}
    if node is None:
        return edge_dict

    out_edges = cfg.out_edges(nbunch=node, data=True)
    for source, target, edge_props in out_edges:
        if edge_props["type"] in [ControlFlowEdgeType.NATURAL.value, ControlFlowEdgeType.JUMP.value]:
            edge_dict["natural"] = (target, edge_props)
        elif edge_props["type"] in [ControlFlowEdgeType.TRUE_JUMP.value, ControlFlowEdgeType.FALSE_JUMP.value]:
            edge_dict["conditional"] = (target, edge_props)
        elif edge_props["type"] == ControlFlowEdgeType.EXCEPTION.value:
            edge_dict["exception"] = (target, edge_props)
        elif edge_props["type"] == ControlFlowEdgeType.META.value:
            pass  # ignore meta edges in graph traversal
        else:
            raise ValueError(f"Unknown edge type {edge_props['type']}")
    return edge_dict


def _to_iter(item):
    """Converts something to an iterable version"""
    if not hasattr(item, "__iter__") or isinstance(item, str):
        return (item,)
    return item


def create_dominator_tree(graph, start_node=None):
    """Creates a dominator tree for the given graph"""

    # default start node is the minimum offset node
    if start_node is None:
        get_start_offset = lambda node: min(_to_iter(graph.nodes.data()[node].get("offset", ())), default=float("inf"))
        start_node = min(graph.nodes, key=get_start_offset)

    dominator_tree = nx.create_empty_copy(graph)
    dominator_tree.add_edges_from(nx.immediate_dominators(graph, start_node).items())
    dominator_tree.remove_edge(start_node, start_node)
    return dominator_tree.reverse()


def get_dominator_function(cfg: nx.DiGraph) -> Callable[[Any, Any], bool]:
    # preprocessing to identify loop headers; dominator tree cached in cfg so we don't recompute unless the graph changed
    if not hasattr(cfg, "dominator_tree"):
        cfg.dominator_tree = create_dominator_tree(cfg, start_node="START")
        cfg.domination_relation = nx.transitive_closure_dag(cfg.dominator_tree)

    def dominates(a, b):
        return cfg.domination_relation.has_edge(a, b) or a == b

    return dominates
