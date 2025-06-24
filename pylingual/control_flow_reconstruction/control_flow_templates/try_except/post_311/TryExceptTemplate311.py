import networkx as nx

import itertools

from ...abstract.AbstractTemplate import ControlFlowTemplate
from ...abstract.AbstractExceptionBlockTemplate import AbstractExceptionBlockTemplate
from ...natural.LinearSequenceTemplate import LinearSequenceTemplate
from ...loop.LoopExitTemplate import LoopExitTemplate

from .ExceptAsNonMatchSubtemplate311 import ExceptAsNonMatchSubTemplate311

from ....cfg_utils import ControlFlowEdgeType

from ...Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ...match_utils import assert_edge_type, optional_node, optional_edge, assert_in_degree, node_match_all, assert_node_has_no_backwards_edges, assert_instruction_opname
from ...subtemplates.OptionalExitSubtemplate import ExitSubTemplate



class TryExceptTemplate311(ControlFlowTemplate):
    """
    A `try-except` block with just a naked except in Python 3.11+.
       (-1)
        |              (-1)
       (0)              |
       / \\e    -->   (01235)
     (1)  (2)           |
      |    | \\e        (4)
      |   (3)  (5)
      \\j /j
       (4)
    One or more of the try/except may have no further control flow.
    However, if both have successors, they must go to the same place.
    """

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
            subtemplate=ExitSubTemplate,
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
            subtemplate=ExceptAsNonMatchSubTemplate311,
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="except_body", dest="after_try_except", edge_verification_func=optional_edge, commit_none_to_mapping=False),
            exception_edge=TemplateEdge(
                source="except_body",
                dest="panic_except",
                edge_verification_func=optional_edge,
            ),
        ),
        "panic_except": TemplateNode(
            exception_edge=TemplateEdge(
                source="except_body",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            )
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
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=TryExceptTemplate311._subgraph, root_key="try_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        reduced_cfg: nx.DiGraph = cfg.copy()
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

        try_except_template = TryExceptTemplate311(try_header=mapping["try_header"], try_body=mapping["try_body"], try_footer=mapping.get("try_footer", None), except_body=mapping["except_body"], panic_except=mapping["panic_except"])

        in_edges = ((src, try_except_template, edge_properties) for src, dst, edge_properties in reduced_cfg.in_edges(try_except_template.try_header, data=True))
        # only preserve exception handling edges
        # insert a continuation edge to after the try except
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
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        try_header = self.try_header.to_indented_source(source_lines)
        try_body = ControlFlowTemplate._indent_multiline_string(self.try_body.to_indented_source(source_lines))

        # check if there is a try footer as in 3.7 there may not be a try footer at all
        if self.try_footer:
            try_footer = ControlFlowTemplate._indent_multiline_string(self.try_footer.to_indented_source(source_lines))
        else:
            try_footer = ""

        try_except_lines = [try_header, "try:", try_body, try_footer]

        # if we matched against an "Except ... as" chain, then omit the inserted except: block
        omit_except = False
        if isinstance(self.except_body, AbstractExceptionBlockTemplate):
            omit_except = True
        elif isinstance(self.except_body, LoopExitTemplate):
            if isinstance(self.except_body.tail, AbstractExceptionBlockTemplate):
                omit_except = True

        except_body = self.except_body.to_indented_source(source_lines)
        if not omit_except:
            try_except_lines.append("except:")
            except_body = ControlFlowTemplate._indent_multiline_string(except_body)

        try_except_lines.append(except_body)

        # the panic except should never have a line

        return "\n".join(try_except_lines)

    def __repr__(self) -> str:
        return super().__repr__()
