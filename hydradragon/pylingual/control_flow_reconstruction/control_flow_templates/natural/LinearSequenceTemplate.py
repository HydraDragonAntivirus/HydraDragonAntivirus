import networkx as nx

import itertools

from pylingual.editable_bytecode import Inst

from ..abstract.AbstractTemplate import ControlFlowTemplate

# imports for our exception whitelist so we do not have to absorb any tails and affect
# control flow in the future (hopefully fingers crossed)
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable
from ..loop.PreRefinedLoopTemplate import PreRefinedLoopTemplate

from ...cfg_utils import get_out_edge_dict, ControlFlowEdgeType, get_dominator_function


class LinearSequenceTemplate(ControlFlowTemplate):
    """
    A natural progression of control flow templates with the same exception handler.
    No conditional jumps are allowed.
    """

    def __init__(self, *members: ControlFlowTemplate):
        self.members = members

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes or not isinstance(node, ControlFlowTemplate):
            return None

        dominates = get_dominator_function(cfg)

        def is_back_edge(src, dst):
            return dominates(dst, src)

        base_edge_dict = get_out_edge_dict(cfg, node)
        base_exception_handler = base_edge_dict["exception"]

        # validate that the current node is able to start a linear sequence
        # jumps cannot start a linear sequence
        if base_edge_dict["conditional"][0] or (base_edge_dict["natural"][1] and base_edge_dict["natural"][1]["type"] != ControlFlowEdgeType.NATURAL.value):
            return None
        # back edges cannot start a linear sequence
        if any(is_back_edge(*edge) for edge in cfg.out_edges(node)):
            return None

        matched_sequence = [node]
        current_edge_dict = base_edge_dict

        # while there is a natural progression, try to extend the linear sequence
        while (next_node_and_edge_properties := current_edge_dict["natural"])[0]:
            next_node, _ = next_node_and_edge_properties
            next_edge_dict = get_out_edge_dict(cfg, next_node)

            # all elements of a linear sequence must have the same exception handler
            if next_edge_dict["exception"] != base_exception_handler:
                break

            # only the natural incoming edge from the previous node is allowed in linear sequences
            if cfg.in_degree(nbunch=next_node) > 1:
                break

            # do not extend after an END_FINALLY
            if isinstance(matched_sequence[-1], ControlFlowTemplate) and not isinstance(matched_sequence[-1], AbstractNonSequentiable):
                insts = matched_sequence[-1].get_instructions()
                if insts and insts[-1].opname == "END_FINALLY":
                    break

            # do not merge in prerefined loop templates; they still need to be refined
            if isinstance(next_node, PreRefinedLoopTemplate):
                break

            # conditional jumps are only allowed in the last element of a linear sequence
            if current_edge_dict["conditional"][0] and current_edge_dict["natural"][0]:
                break

            # absolute jumps are only allowed in the last element of a linear sequence
            if current_edge_dict["natural"][1] and current_edge_dict["natural"][1]["type"] != ControlFlowEdgeType.NATURAL.value:
                break

            matched_sequence.append(next_node)
            current_edge_dict = next_edge_dict

        # if we didn't reduce the graph size, match failed
        if len(matched_sequence) < 2:
            return None

        # unpack nested LinearSequenceTemplates for improved readability of the parse tree
        unpacked_matched_sequence = []
        for match_item in matched_sequence:
            if isinstance(match_item, LinearSequenceTemplate):
                unpacked_matched_sequence.extend(match_item.members)
            else:
                unpacked_matched_sequence.append(match_item)
        # preserve the incoming edges from the first node and the outgoing edges from the last node
        linear_sequence_template = LinearSequenceTemplate(*unpacked_matched_sequence)
        in_edges = ((linear_sequence_template if src in matched_sequence else src, linear_sequence_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(nbunch=node, data=True))
        out_edges = ((linear_sequence_template, linear_sequence_template if dst in matched_sequence else dst, edge_properties) for src, dst, edge_properties in cfg.out_edges(nbunch=matched_sequence[-1], data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from(matched_sequence)
        reduced_cfg.add_node(linear_sequence_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        return "\n".join(member.to_indented_source(source_lines) for member in self.members)

    def get_instructions(self) -> list[Inst]:
        insts: list[Inst] = []
        for member in self.members:
            insts.extend(member.get_instructions())
        return insts
        return sorted(insts, key=lambda i: i.offset)

    def __repr__(self) -> str:
        name = f"{type(self).__name__}"
        components = ControlFlowTemplate._indent_multiline_string("\n".join(repr(member) for member in self.members))
        return f"{name}[\n{components}]"
