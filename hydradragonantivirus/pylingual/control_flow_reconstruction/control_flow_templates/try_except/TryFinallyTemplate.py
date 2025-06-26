import networkx as nx

import itertools

from ..abstract.AbstractTemplate import ControlFlowTemplate
from ..abstract.AbstractNonSequentiableTemplate import AbstractNonSequentiable

from ...cfg_utils import ControlFlowEdgeType

from ..Subgraph import TemplateEdge, TemplateNode, GraphTemplateMatcher

from ..match_utils import assert_edge_type, optional_node, optional_edge, assert_in_degree, assert_instruction_opname, edge_is_none_or_matches



class TryFinallyTemplate(ControlFlowTemplate, AbstractNonSequentiable):
    """
    A `try` block with only a `finally` following it.
       (0)
        |
       (1)
       /e\\     -->   (0123)
     (3) (2)            |
          |j           (4)
         (4)
    does not cover additional finally blocks that will be inserted in the bytecode as a result of returns / breaking out of loops
    """

    _subgraph = {
        "setup_finally": TemplateNode(
            node_verification_func=assert_instruction_opname("SETUP_FINALLY"),
            natural_edge=TemplateEdge(
                source="setup_finally",
                dest="try_body",
            ),
            exception_edge=TemplateEdge(source="setup_finally", dest="outer_exception_handler", edge_verification_func=optional_edge),
        ),
        "try_body": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(
                source="try_body",
                dest="happy_finally",
            ),
            exception_edge=TemplateEdge(
                source="try_body",
                dest="angry_finally",
            ),
        ),
        "happy_finally": TemplateNode(
            node_verification_func=assert_in_degree(1),
            natural_edge=TemplateEdge(source="happy_finally", dest="tail", edge_verification_func=edge_is_none_or_matches(assert_edge_type(ControlFlowEdgeType.JUMP))),
            exception_edge=TemplateEdge(
                source="happy_finally",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "angry_finally": TemplateNode(
            node_verification_func=assert_in_degree(1),
            exception_edge=TemplateEdge(
                source="angry_finally",
                dest="outer_exception_handler",
                edge_verification_func=optional_edge,
            ),
        ),
        "tail": TemplateNode(
            node_verification_func=optional_node,
            natural_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            exception_edge=TemplateEdge(
                source="tail",
                dest=None,
                edge_verification_func=optional_edge,
            ),
            conditional_edge=TemplateEdge(
                source="tail",
                dest=None,
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

    def __init__(self, setup_finally: ControlFlowTemplate, try_body: ControlFlowTemplate, happy_finally: ControlFlowTemplate, angry_finally: ControlFlowTemplate):
        self.setup_finally = setup_finally
        self.try_body = try_body
        self.happy_finally = happy_finally
        self.angry_finally = angry_finally

    @staticmethod
    def try_to_match_node(cfg: nx.DiGraph, node) -> nx.DiGraph:
        """
        Attempts to match this template on the graph at the given node.
        If successful, returns an updated cfg with the appropriate nodes condensed into an instance of this template.
        Otherwise, returns None.
        """
        if node not in cfg.nodes:
            return None

        if cfg.in_degree(node) != 1:
            return None

        # to avoid being treated as a try-except, we actually need to greedily search up one layer
        pred = next(cfg.predecessors(node))

        def verify_finally_match(cfg: nx.DiGraph, mapping: dict[str, ControlFlowTemplate]) -> bool:
            # check to make sure that all non-stack/control instructions match between the two finally blocks
            # this list was made for 3.9, so it may need to be expanded for other versions
            stack_and_control_insts = {"POP_TOP", "POP_EXCEPT", "ROT_TWO", "ROT_THREE", "ROT_FOUR", "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE", "RERAISE"}
            happy_insts = [(inst.opname, inst.arg) for inst in mapping["happy_finally"].get_instructions() if inst.opname not in stack_and_control_insts]
            angry_insts = [(inst.opname, inst.arg) for inst in mapping["angry_finally"].get_instructions() if inst.opname not in stack_and_control_insts]
            return happy_insts == angry_insts

        matcher = GraphTemplateMatcher(template_node_dict=TryFinallyTemplate._subgraph, root_key="setup_finally", mapping_verification_func=verify_finally_match)

        mapping = matcher.match_at_graph_node(cfg, pred)

        if not mapping:
            return None

        finally_template = TryFinallyTemplate(setup_finally=mapping["setup_finally"], try_body=mapping["try_body"], happy_finally=mapping["happy_finally"], angry_finally=mapping["angry_finally"])

        in_edges = [(src, finally_template, edge_properties) for src, dst, edge_properties in cfg.in_edges(finally_template.setup_finally, data=True)]
        # only preserve exception handling edges
        # insert a continuation edge to after the finally
        out_edges = []
        if mapping["outer_exception_handler"]:
            out_edges.append((finally_template, mapping["outer_exception_handler"], {"type": ControlFlowEdgeType.EXCEPTION.value}))
        if mapping["tail"]:
            out_edges.append((finally_template, mapping["tail"], {"type": ControlFlowEdgeType.NATURAL.value}))

        reduced_cfg = cfg.copy()
        reduced_cfg.remove_nodes_from([finally_template.setup_finally, finally_template.try_body, finally_template.happy_finally, finally_template.angry_finally])
        reduced_cfg.add_node(finally_template)
        reduced_cfg.add_edges_from(itertools.chain(in_edges, out_edges))
        return reduced_cfg

    def to_indented_source(self, source_lines: list[str]) -> str:
        """
        Returns the source code for this template, recursively calling into its children to create the full source code.
        """
        # sometimes the setup finally is included in a linear sequence, so we need to include that source
        setup_finally = self.setup_finally.to_indented_source(source_lines)
        try_block = ControlFlowTemplate._indent_multiline_string(self.try_body.to_indented_source(source_lines))
        # pick one of the finally bodies to get the source code from
        finally_body = ControlFlowTemplate._indent_multiline_string(self.happy_finally.to_indented_source(source_lines))
        if not finally_body:
            finally_body = ControlFlowTemplate._indent_multiline_string(self.angry_finally.to_indented_source(source_lines))
        finally_lines = [setup_finally, "try:", try_block, "finally: # inserted", finally_body]
        return "\n".join(finally_lines)

    def __repr__(self) -> str:
        return super().__repr__()
