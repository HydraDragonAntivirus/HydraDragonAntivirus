import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...natural.LinearSequenceTemplate import LinearSequenceTemplate

from .ExceptTemplate311 import ExceptTemplate311

from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import (
    assert_edge_type,
    optional_node,
    optional_edge,
    assert_in_degree,
    node_match_all,
    assert_node_has_no_backwards_edges,
    assert_instruction_opname,
    is_exactly_opname,
)



class TryTemplate311(ControlFlowTemplate):
    _subgraph = {
        "try_header": TemplateNode(
            node_verification_func=assert_instruction_opname("NOP"),
            natural_edge=TemplateEdge(source="try_header", dest="try_body", edge_verification_func=assert_edge_type(ControlFlowEdgeType.NATURAL)),
        ),
        "try_body": TemplateNode(
            natural_edge=TemplateEdge(source="try_body", dest="try_footer", edge_verification_func=assert_edge_type(ControlFlowEdgeType.NATURAL)),
            exception_edge=TemplateEdge(
                source="try_body",
                dest="except_body",
            ),
        ),
        "try_footer": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
            ),
            natural_edge=TemplateEdge(source="try_footer", dest="after_try_except", edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="try_footer",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "except_body": TemplateNode(
            subtemplate=ExceptTemplate311,
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="except_body", dest="after_try_except", edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="panic_except",
                edge_verification_func=optional_edge,
            ),
        ),
        "panic_except": TemplateNode(
            node_verification_func=is_exactly_opname("COPY", "POP_EXCEPT", "RERAISE"),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "after_try_except": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="after_try_except",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="after_try_except",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="after_try_except",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
                commit_none_to_mapping=False,
            ),
        ),
        "outer_exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="outer_exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(self, try_header: ControlFlowTemplate, try_body: ControlFlowTemplate, try_footer: ControlFlowTemplate, except_body: ControlFlowTemplate, panic_except: ControlFlowTemplate):
        self.try_header = try_header
        self.try_body = try_body
        self.try_footer = try_footer
        self.except_body = except_body
        self.panic_except = panic_except

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=TryTemplate311._subgraph, root_key="try_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        reduced_cfg = cfg.copy()

        # "bite off" the NOP from a linear sequence template
        if isinstance(mapping["try_header"], LinearSequenceTemplate):
            # grab the nop and update the linear sequence
            nop_inst_template = mapping["try_header"].members[-1]
            mapping["try_header"].members = mapping["try_header"].members[:-1]
            if len(mapping["try_header"].members) == 1:
                nx.relabel_nodes(reduced_cfg, {mapping["try_header"]: mapping["try_header"].members[0]}, copy=False)
                mapping["try_header"] = mapping["try_header"].members[0]

            # transfer outgoing edges to the bitten off chunk
            header_out_edges = list(reduced_cfg.out_edges(mapping["try_header"], data=True))
            reduced_cfg.add_node(nop_inst_template)
            reduced_cfg.remove_edges_from(header_out_edges)
            reduced_cfg.add_edges_from((nop_inst_template, dst, data) for src, dst, data in header_out_edges)
            reduced_cfg.add_edge(mapping["try_header"], nop_inst_template, type=ControlFlowEdgeType.NATURAL.value)
            mapping["try_header"] = nop_inst_template

        try_except_template = TryTemplate311(try_header=mapping["try_header"], try_body=mapping["try_body"], try_footer=mapping["try_footer"], except_body=mapping["except_body"], panic_except=mapping["panic_except"])

        in_edges = ((src, try_except_template, edge_properties) for src, dst, edge_properties in reduced_cfg.in_edges(try_except_template.try_header, data=True))
        out_edges = []
        if mapping["outer_exception_handler"]:
            out_edges.append((try_except_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        if "after_try_except" in mapping.keys():
            after_try_except = mapping["after_try_except"]
            out_edges.append((try_except_template, after_try_except, {"type": ControlFlowEdgeType.NATURAL.value}))

        reduced_cfg.remove_nodes_from([try_except_template.try_header, try_except_template.try_body, try_except_template.try_footer, try_except_template.except_body, try_except_template.panic_except])
        reduced_cfg.add_node(try_except_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        try_header = self.try_header.to_indented_source(source_lines)
        try_body = self._indent_multiline_string(self.try_body.to_indented_source(source_lines))

        except_body = self.except_body.to_indented_source(source_lines)

        lines = [try_header, "try:", try_body, except_body]

        try_footer = self.try_footer.to_indented_source(source_lines)
        if try_footer.strip():
            lines.extend(["else: # inserted", self._indent_multiline_string(try_footer)])

        return "\n".join(lines)

    def __repr__(self) -> str:
        return super().__repr__()
