import networkx as nx

from ..cfg_utils import get_out_edge_dict

from typing import Any, Callable
from .abstract.AbstractTemplate import ControlFlowTemplate
# INVARIANT: each node will have at most one of each "natural", "conditional", and "exception" edge


class TemplateEdge:
    def __init__(self, source: Any, dest: Any, edge_verification_func: Callable[[Any, Any, dict], bool] = None, commit_none_to_mapping: bool = True) -> None:
        self.source = source
        self.dest = dest
        self.edge_verification_func = edge_verification_func
        # for optional edges, toggle if the absence of a node will be committed to the mapping
        # set to False for edges that may not exist, even when their template destination may be reachable from other nodes
        self.commit_none_to_mapping = commit_none_to_mapping

    def check_edge(self, graph_source: Any, graph_dest: Any, graph_edge_properties: dict) -> bool:
        # if no verification function is provided, just check that the edge exists
        if self.edge_verification_func is None:
            return graph_dest is not None

        return self.edge_verification_func(graph_source, graph_dest, graph_edge_properties)


class TemplateNode:
    def __init__(
        self, node_verification_func: Callable[[nx.DiGraph, Any], bool] = None, natural_edge: TemplateEdge = None, conditional_edge: TemplateEdge = None, exception_edge: TemplateEdge = None, subtemplate: ControlFlowTemplate = None
    ) -> None:
        self.node_verification_func = node_verification_func
        self.natural_edge = natural_edge
        self.conditional_edge = conditional_edge
        self.exception_edge = exception_edge
        self.subtemplate = subtemplate

    def check_node(self, cfg: nx.DiGraph, node: Any) -> bool:
        # I am not a valid candidate, so this is not a valid mapping
        # it is the job of the node verification func to check in_degree
        if self.node_verification_func is None:
            if node is None:
                return False
        elif not self.node_verification_func(cfg, node):
            return False

        # check the outgoing edges for this node
        node_out_edge_dict = get_out_edge_dict(cfg, node)
        natural_target, natural_properties = node_out_edge_dict["natural"] if node_out_edge_dict["natural"] else (None, None)
        # if the edge is in the template, it must be valid
        if self.natural_edge and not self.natural_edge.check_edge(node, natural_target, natural_properties):
            return False
        # if the edge is not in the template, reject
        if natural_target and not self.natural_edge:
            return False

        conditional_target, conditional_properties = node_out_edge_dict["conditional"] if node_out_edge_dict["conditional"] else (None, None)
        # if the edge is in the template, it must be valid
        if self.conditional_edge and not self.conditional_edge.check_edge(node, conditional_target, conditional_properties):
            return False
        # if the edge is not in the template, reject
        if conditional_target and not self.conditional_edge:
            return False

        exception_target, exception_properties = node_out_edge_dict["exception"] if node_out_edge_dict["exception"] else (None, None)
        # if the edge is in the template, it must be valid
        if self.exception_edge and not self.exception_edge.check_edge(node, exception_target, exception_properties):
            return False
        # if the edge is not in the template, reject
        if exception_target and not self.exception_edge:
            return False

        # node is good and all outgoing edges are good
        return True


class GraphTemplateMatcher:
    def __init__(self, template_node_dict: dict[Any, TemplateNode], root_key: Any, mapping_verification_func: Callable[[nx.DiGraph, dict], bool]) -> None:
        self.template_node_dict = template_node_dict
        self.root_key = root_key
        self.mapping_verification_func = mapping_verification_func

    def match_at_graph_node(self, cfg: nx.DiGraph, root_node: Any) -> dict:
        mapping = dict()
        mapped_nodes = set()

        dfs_stack = [(self.root_key, root_node)]

        original_cfg = cfg  # save this reference for later

        while dfs_stack:
            current_template_key, current_graph_node = dfs_stack.pop()
            current_template_node = self.template_node_dict[current_template_key]
            # if the template node has already been mapped, we don't process it again
            if current_template_key in mapping:
                # if the current template node has been mapped inconsistently, then the mapping failed
                if mapping[current_template_key] != current_graph_node:
                    return None
                else:
                    continue
            if current_graph_node in mapped_nodes:
                return None

            # try to match the node subtemplate if one was provided
            # if there is a match, then update the cfg under consideration, ensuring that nodes don't get double-mapped
            if current_template_node.subtemplate:
                updated_cfg = current_template_node.subtemplate.try_to_match_node(cfg, current_graph_node)
                # if we didn't match the subtemplate, then this node matching failed
                if not updated_cfg:
                    return None

                # check that previously mapped nodes did not get removed
                for mapped_node in mapping.values():
                    if mapped_node is not None and mapped_node not in updated_cfg.nodes:
                        return None

                # update the current graph node
                added_nodes = set(updated_cfg.nodes) - set(cfg.nodes)
                # enforce invariant that templates add no more than one node
                assert len(added_nodes) <= 1
                if added_nodes:
                    current_graph_node = added_nodes.pop()

                # update the cfg
                cfg = updated_cfg

            # if the node is not a valid match, then the mapping failed
            # check_node also checks all the outgoing edges
            if not current_template_node.check_node(cfg, current_graph_node):
                return None

            mapping[current_template_key] = current_graph_node
            mapped_nodes.add(current_graph_node)

            graph_node_out_edge_dict = get_out_edge_dict(cfg, current_graph_node)

            # extend along the natural edge
            if current_template_node.natural_edge:
                next_template_key = current_template_node.natural_edge.dest
                if next_template_key is not None:
                    next_graph_node, _ = graph_node_out_edge_dict["natural"] if graph_node_out_edge_dict["natural"] else (None, None)
                    if next_graph_node is not None or current_template_node.natural_edge.commit_none_to_mapping:
                        dfs_stack.append((next_template_key, next_graph_node))

            # extend along the conditional edge
            if current_template_node.conditional_edge:
                next_template_key = current_template_node.conditional_edge.dest
                if next_template_key is not None:
                    next_graph_node, _ = graph_node_out_edge_dict["conditional"] if graph_node_out_edge_dict["conditional"] else (None, None)
                    if next_graph_node is not None or current_template_node.conditional_edge.commit_none_to_mapping:
                        dfs_stack.append((next_template_key, next_graph_node))

            # extend along the exception edge
            if current_template_node.exception_edge:
                next_template_key = current_template_node.exception_edge.dest
                if next_template_key is not None:
                    next_graph_node, _ = graph_node_out_edge_dict["exception"] if graph_node_out_edge_dict["exception"] else (None, None)
                    if next_graph_node is not None or current_template_node.exception_edge.commit_none_to_mapping:
                        dfs_stack.append((next_template_key, next_graph_node))

        # we have a final mapping, check any top-level verification stuff
        if self.mapping_verification_func and not self.mapping_verification_func(cfg, mapping):
            return None

        # mapping was successful
        if cfg == original_cfg:
            return mapping

        # commit changes to the original cfg by modifying the reference
        original_cfg.clear()
        original_cfg.update(cfg)
        return mapping
