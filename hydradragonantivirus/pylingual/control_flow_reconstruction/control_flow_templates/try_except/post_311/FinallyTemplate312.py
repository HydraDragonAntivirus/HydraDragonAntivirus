import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...natural.InstructionTemplate import InstructionTemplate
from ...natural.LinearSequenceTemplate import LinearSequenceTemplate
from ...if_then.IfThenTemplate import IfThenTemplate
from ...if_then.IfElseTemplate import IfElseTemplate
from .TryTemplate311 import TryTemplate311
from .TryTemplate312 import TryTemplate312


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
    assert_node_type,
)



class FinallyTemplate312(ControlFlowTemplate):
    _subgraph = {
        "try_header": TemplateNode(
            node_verification_func=assert_instruction_opname("NOP"),
            natural_edge=TemplateEdge(source="try_header", dest="try_body", edge_verification_func=assert_edge_type(ControlFlowEdgeType.NATURAL)),
        ),
        "try_body": TemplateNode(
            natural_edge=TemplateEdge(source="try_body", dest="finally_body", edge_verification_func=assert_edge_type(ControlFlowEdgeType.NATURAL)),
            exception_edge=TemplateEdge(
                source="try_body",
                dest="fail",
            ),
        ),
        "finally_body": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
            ),
            natural_edge=TemplateEdge(source="finally_body", dest=None, edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="finally_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "fail": TemplateNode(
            node_verification_func=assert_in_degree(1),
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
    _subgraph2 = {
        "try_except": TemplateNode(
            node_verification_func=assert_node_type(TryTemplate311, TryTemplate312),
            natural_edge=TemplateEdge(source="try_except", dest="finally_body", edge_verification_func=assert_edge_type(ControlFlowEdgeType.NATURAL)),
            exception_edge=TemplateEdge(
                source="try_except",
                dest="fail",
            ),
        ),
        "finally_body": TemplateNode(
            node_verification_func=node_match_all(
                assert_in_degree(1),
                assert_node_has_no_backwards_edges,
            ),
            natural_edge=TemplateEdge(source="finally_body", dest=None, edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="finally_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "fail": TemplateNode(
            node_verification_func=assert_in_degree(1),
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

    def __init__(self, try_header: ControlFlowTemplate, try_body: ControlFlowTemplate, finally_body: ControlFlowTemplate, fail: ControlFlowTemplate, panic_except: ControlFlowTemplate, cutoff):
        self.try_header = try_header
        self.try_body = try_body
        self.finally_body = finally_body
        self.fail = fail
        self.panic_except = panic_except
        self.cutoff = cutoff

    @staticmethod
    def mapping_verification_func(cfg, mapping):
        finally_body = mapping["finally_body"]
        fail = mapping["fail"]
        if any(x.starts_line is not None for x in fail.get_instructions()):
            return False
        if not isinstance(finally_body, LinearSequenceTemplate):
            finally_body = LinearSequenceTemplate(finally_body)
        if not isinstance(fail, LinearSequenceTemplate):
            fail = LinearSequenceTemplate(fail)
        if isinstance(fail.members[0], InstructionTemplate) and fail.members[0].instruction.opname == "PUSH_EXC_INFO":
            fail.members = fail.members[1:]
        if isinstance(fail.members[-1], InstructionTemplate) and fail.members[-1].instruction.opname == "RERAISE":
            fail.members = fail.members[:-1]
        for x, y in zip(finally_body.members, fail.members):
            if type(x) is not type(y) and not all(type(a) in [IfThenTemplate, IfElseTemplate] for a in (x, y)):
                return False
        mapping["cutoff"] = x
        return True

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=FinallyTemplate312._subgraph, root_key="try_header", mapping_verification_func=FinallyTemplate312.mapping_verification_func)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            matcher = GraphTemplateMatcher(template_node_dict=FinallyTemplate312._subgraph2, root_key="try_except", mapping_verification_func=FinallyTemplate312.mapping_verification_func)

            mapping = matcher.match_at_graph_node(cfg, node)
            if not mapping:
                return None
            mapping["try_header"] = None
            mapping["try_body"] = mapping["try_except"]

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

        template = FinallyTemplate312(try_header=mapping["try_header"], try_body=mapping["try_body"], finally_body=mapping["finally_body"], fail=mapping["fail"], panic_except=mapping["panic_except"], cutoff=mapping["cutoff"])

        in_edges = ((src, template, edge_properties) for src, dst, edge_properties in reduced_cfg.in_edges(template.try_header or template.try_body, data=True))
        out_edges = [(template, dst, edge_properties) for src, dst, edge_properties in reduced_cfg.out_edges(template.finally_body, data=True)]
        if mapping["outer_exception_handler"]:
            out_edges.append((template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))

        reduced_cfg.remove_nodes_from([template.try_header, template.try_body, template.finally_body, template.fail, template.panic_except])
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        try_header = self.try_header.to_indented_source(source_lines) if self.try_header else ""
        try_body = self._indent_multiline_string(self.try_body.to_indented_source(source_lines))

        if isinstance(self.finally_body, LinearSequenceTemplate):
            i = self.finally_body.members.index(self.cutoff) + 1
            in_finally = self._indent_multiline_string(LinearSequenceTemplate(*self.finally_body.members[:i]).to_indented_source(source_lines))
            after = LinearSequenceTemplate(*self.finally_body.members[i:]).to_indented_source(source_lines)
        else:
            in_finally = self._indent_multiline_string(self.finally_body.to_indented_source(source_lines))
            after = ""

        lines = [try_header, "try:", try_body, "finally: # inserted", in_finally, after]

        return "\n".join(lines)

    def __repr__(self) -> str:
        return super().__repr__()
