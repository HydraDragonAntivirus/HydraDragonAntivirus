import networkx as nx

from ..abstract.AbstractTemplate import ControlFlowTemplate

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher
from ..natural.InstructionTemplate import InstructionTemplate
from .LoopExitTemplate import LoopExitTemplate

from ..match_utils import optional_node, optional_edge, assert_in_degree, node_match_all
from ...cfg_utils import ControlFlowEdgeType


def is_j(cfg: nx.DiGraph, node) -> bool:
    return isinstance(node, LoopExitTemplate) and isinstance(node.tail, InstructionTemplate) and node.tail.instruction.opname == "JUMP_BACKWARD" and node.exit_statement == "continue" and node.tail.instruction.target.opname == "FOR_ITER"


class ForIf312Template(ControlFlowTemplate):
    _subgraph = {
        "if_header": TemplateNode(
            natural_edge=TemplateEdge(
                source="if_header",
                dest="jump_back",
            ),
            conditional_edge=TemplateEdge(
                source="if_header",
                dest="real_body",
            ),
            exception_edge=TemplateEdge(
                source="if_header",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "jump_back": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1), is_j),
            exception_edge=TemplateEdge(
                source="jump_back",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "real_body": TemplateNode(
            node_verification_func=node_match_all(assert_in_degree(1)),
            exception_edge=TemplateEdge(
                source="real_body",
                dest="exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "exception_handler": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="exception_handler",
                dest=None,
                edge_verification_func=optional_edge,
            ),
        ),
    }

    def __init__(self, if_header: ControlFlowTemplate, body: ControlFlowTemplate, jb: ControlFlowTemplate):
        self.if_header = if_header
        self.body = body
        self.jb = jb

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        matcher = GraphTemplateMatcher(template_node_dict=ForIf312Template._subgraph, root_key="if_header", mapping_verification_func=None)

        mapping = matcher.match_at_graph_node(cfg, node)

        if not mapping:
            return None

        template = ForIf312Template(if_header=mapping["if_header"], body=mapping["real_body"], jb=mapping["jump_back"])

        in_edges = ((src, template, edge) for src, dst, edge in cfg.in_edges(node, data=True))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([mapping["if_header"], mapping["real_body"], mapping["jump_back"]])
        reduced_cfg.add_node(template)
        reduced_cfg.add_edges_from(in_edges)
        if mapping["exception_handler"]:
            reduced_cfg.add_edge(template, mapping["exception_handler"], type=ControlFlowEdgeType.EXCEPTION.value)
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        header = self.if_header.to_indented_source(source_lines)
        body = self._indent_multiline_string(self.body.to_indented_source(source_lines))
        """
        n = header.strip().split('\n')[-1].strip().startswith('if not ')
        fj = self.if_header.get_instructions()[-1].opname == 'POP_JUMP_IF_FALSE'
        breakpoint()
        if fj != n:
            header += '\n\tpass\nelse: # inserted'
        """
        last = max((i.starts_line for i in self.if_header.get_instructions() if i.starts_line is not None), default=None)
        if last is not None and last < len(source_lines) and body.split("\n")[0].strip() != source_lines[last].strip():
            header += "\n\tpass\nelse: # inserted"
        return header + "\n" + body

    def __repr__(self) -> str:
        return super().__repr__()
