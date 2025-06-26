import networkx as nx

import os

from pylingual.utils.lazy import lazy_import

from .cfg_utils import ControlFlowEdgeType, get_out_edge_dict, get_dominator_function
from pylingual.editable_bytecode import Inst
from pylingual.editable_bytecode import EditableBytecode

# abstract type
from .control_flow_templates.abstract.AbstractTemplate import ControlFlowTemplate

from .control_flow_templates.placeholders.IrreduciblePlaceholderTemplate import IrreduciblePlaceholderTemplate

# default flow
from .control_flow_templates.natural.InstructionTemplate import InstructionTemplate
from .control_flow_templates.natural.LinearSequenceTemplate import LinearSequenceTemplate
from .control_flow_templates.natural.LineTemplate import LineTemplate

# if/else
from .control_flow_templates.if_then.IfThenTemplate import IfThenTemplate
from .control_flow_templates.if_then.IfElseTemplate import IfElseTemplate
from .control_flow_templates.if_then.IfThenJumpTemplate import IfThenJumpTemplate
from .control_flow_templates.if_then.ConditionalExitTemplate import ConditionalExitTemplate
from .control_flow_templates.booleans.ShortCircuitOrTemplate import ShortCircuitOrTemplate
from .control_flow_templates.booleans.ShortCircuitOrContinueTemplate import ShortCircuitOrContinueTemplate
from .control_flow_templates.booleans.ShortCircuitAndTemplate import ShortCircuitAndTemplate
from .control_flow_templates.booleans.ChainedComparisonTemplate import ChainedComparisonTemplate
from .control_flow_templates.context_managers.WithTemplate import WithTemplate
from .control_flow_templates.context_managers.WithTemplate39 import WithTemplate39
from .control_flow_templates.context_managers.WithCleanup312 import WithCleanup312
from .control_flow_templates.context_managers.AsyncWithCleanup312 import AsyncWithCleanup312
from .control_flow_templates.context_managers.WithTemplate312 import WithTemplate312
from .control_flow_templates.context_managers.Await312Template import Await312Template

# loops
from .control_flow_templates.loop.LoopTemplate import LoopTemplate
from .control_flow_templates.loop.SelfLoopTemplate import SelfLoopTemplate
from .control_flow_templates.loop.LoopExitTemplate import LoopExitTemplate
from .control_flow_templates.loop.PreRefinedLoopTemplate import PreRefinedLoopTemplate
from .control_flow_templates.loop.RefinedLoopTemplate import RefinedLoopTemplate
from .control_flow_templates.loop.WhileTrueIfElseTemplate import WhileTrueIfElseTemplate
from .control_flow_templates.loop.AsyncForTemplate import AsyncForTemplate
from .control_flow_templates.loop.InlinedComprehension import InlinedComprehensionTemplate
from .control_flow_templates.loop.ForIf312Template import ForIf312Template

# exceptions
from .control_flow_templates.try_except.TryExceptTemplate import TryExceptTemplate
from .control_flow_templates.try_except.TryExceptElseTemplate import TryExceptElseTemplate
from .control_flow_templates.try_except.ExceptAsExceptTemplate import ExceptAsExceptTemplate
from .control_flow_templates.try_except.ExceptAsCleanup import ExceptAsCleanupTemplate
from .control_flow_templates.try_except.ExceptAsExitTemplate import ExceptAsExitTemplate
from .control_flow_templates.try_except.FinallyTemplate import FinallyTemplate
from .control_flow_templates.try_except.TryFinallyTemplate import TryFinallyTemplate
from .control_flow_templates.try_except.pre_39.TryFinallyPre39 import Pre39TryFinallyTemplate
from .control_flow_templates.try_except.pre_39.TryFinallyExitPre39 import Pre39TryFinallyExitTemplate
from .control_flow_templates.try_except.pre_39.ExceptAsPre39 import Pre39ExceptAsTemplate
from .control_flow_templates.try_except.ExceptException import ExceptException
from .control_flow_templates.try_except.GeneratorCleanupTemplate import GeneratorCleanupTemplate

# 3.11/3.12-specific exceptions
from .control_flow_templates.try_except.post_311.TryTemplate311 import TryTemplate311
from .control_flow_templates.try_except.post_311.TryTemplate312 import TryTemplate312
from .control_flow_templates.try_except.post_311.FinallyTemplate312 import FinallyTemplate312

import pathlib

lazy_import("pydot")

from typing import Generator, Any


def viz(graph, name, node_label="label"):
    namepath = pathlib.Path(name)
    dot = pydot.Dot(namepath.name)
    nodes = {}

    for node, data in graph.nodes.data():
        n = pydot.Node(hash(node), label=data[node_label])
        dot.add_node(n)
        nodes[hash(node)] = n

    for node1, node2, data in graph.edges.data():
        edge = pydot.Edge(nodes[hash(node1)], nodes[hash(node2)], **data)
        dot.add_edge(edge)

    try:
        dot.write_png(name)
    except FileNotFoundError:
        dot.write_raw(name.replace(".png", ".dot"))


# order matters!
# More specific templates should appear before more general templates for correctness
# More common templates should appear before more rare templates for efficiency
cyclic_templates: list[type[ControlFlowTemplate]] = [
    WhileTrueIfElseTemplate,
    LoopTemplate,
    SelfLoopTemplate,
    ShortCircuitOrTemplate,  # the short circuit templates aren't cyclic, but are needed to match certain while loops
    ShortCircuitAndTemplate,
]

# priority dict structure
# Template type : (pass number, priority number) # lower is earlier
acyclic_templates_priority_dict: dict[ControlFlowTemplate, tuple[int, int]] = {
    RefinedLoopTemplate: (0, 0),
    AsyncForTemplate: (0, 1),  # technically a cyclic template, but it searches up one node to complete the loop
    FinallyTemplate: (0, 10),
    WithTemplate: (0, 11),
    LinearSequenceTemplate: (0, 20),
    ExceptAsExitTemplate: (0, 25),
    ExceptAsExceptTemplate: (0, 27),
    ShortCircuitOrContinueTemplate: (0, 30),
    IfElseTemplate: (1, 43),
    IfThenTemplate: (1, 44),
    IfThenJumpTemplate: (0, 45),
    ConditionalExitTemplate: (0, 46),
    ExceptAsCleanupTemplate: (0, 50),
    TryFinallyTemplate: (0, 60),
    TryExceptElseTemplate: (0, 62),
    ShortCircuitOrTemplate: (0, 70),
    ShortCircuitAndTemplate: (0, 71),
    ChainedComparisonTemplate: (0, 72),
}

# dictionary structure
# version: {template: (pass, priority)}
version_specific_acyclic_templates_dict: dict[tuple[int, int], dict[ControlFlowTemplate, tuple[int, int]]] = {
    (3, 13): {
        TryTemplate312: (-1, 60),
        TryTemplate311: (-1, 61),
        WithCleanup312: (-1, 0),
        AsyncWithCleanup312: (-1, 0),
        WithTemplate312: (0, 10),
        InlinedComprehensionTemplate: (-1, 0),
        GeneratorCleanupTemplate: (0, 1),
        Await312Template: (0, 2),
        ForIf312Template: (0, 0),
        FinallyTemplate312: (-1, 199),
    },
    (3, 12): {
        TryTemplate312: (-1, 60),
        TryTemplate311: (-1, 61),
        WithCleanup312: (-1, 0),
        AsyncWithCleanup312: (-1, 0),
        WithTemplate312: (0, 10),
        InlinedComprehensionTemplate: (-1, 0),
        GeneratorCleanupTemplate: (0, 1),
        Await312Template: (0, 2),
        ForIf312Template: (0, 0),
        FinallyTemplate312: (-1, 199),
    },
    (3, 11): {
        TryTemplate311: (-1, 55),
    },
    (3, 9): {
        WithTemplate39: (0, 12),
        TryExceptTemplate: (1, 61),
    },
    (3, 8): {
        Pre39ExceptAsTemplate: (0, 40),
        Pre39TryFinallyTemplate: (0, 60),
        Pre39TryFinallyExitTemplate: (0, 75),
        ExceptException: (0, 38),
        TryExceptTemplate: (1, 61),
    },
    (3, 7): {
        Pre39ExceptAsTemplate: (0, 40),
        Pre39TryFinallyTemplate: (0, 60),
        Pre39TryFinallyExitTemplate: (0, 75),
        ExceptException: (0, 38),
        TryExceptTemplate: (1, 61),
    },
    (3, 6): {
        Pre39ExceptAsTemplate: (0, 40),
        Pre39TryFinallyTemplate: (0, 60),
        Pre39TryFinallyExitTemplate: (0, 75),
        ExceptException: (0, 38),
        TryExceptTemplate: (1, 61),
    },
}


def get_acyclic_template_passes(version: tuple[int, int]) -> Generator[list[ControlFlowTemplate], None, None]:
    pass_dict = dict()
    # accumulate the passes, merging in version-specific templates
    for template, (pass_number, priority) in (acyclic_templates_priority_dict | version_specific_acyclic_templates_dict.get(version, dict())).items():
        pass_list = pass_dict.get(pass_number, list())
        pass_list.append((template, priority))
        pass_dict[pass_number] = pass_list
    # sort each pass by priority
    for pass_number, pass_list in pass_dict.items():
        pass_dict[pass_number] = [template for template, priority in sorted(pass_list, key=lambda item: item[1])]
    # yield the templates for each pass
    for pass_number in sorted(pass_dict.keys()):
        yield pass_dict[pass_number]


def visualize(graph: nx.DiGraph, name, suffix):
    # visualization is slow
    if os.environ.get("DEBUG_CFLOW", None) != "1":
        return
    for n in graph.nodes:
        graph.nodes[n]["label"] = repr(n)
    v = next(x for x in graph.nodes if not isinstance(x, str)).get_instructions()[0].bytecode.version
    viz(graph, f"/tmp/graph/{name}_{v[1]}_{suffix}.png", edge_label="type")


def structure_loop(cfg: nx.DiGraph, node) -> nx.DiGraph:
    dominates = get_dominator_function(cfg)
    # a node is a loop header if there are back-edges to it
    # a latching node is a node with a back-edge to the loop header
    # a back-edge is an edge from any node that is dominated by this node
    latching_nodes = [pred for pred in cfg.predecessors(node) if dominates(node, pred)]
    if not latching_nodes:
        return None

    # attempt to match a loop template
    for template in cyclic_templates:
        candidate_cfg = template.try_to_match_node(cfg, node)
        if candidate_cfg is not None:
            return candidate_cfg

    if len(node.get_instructions()) == 1 and node.get_instructions()[0].opname == "SEND":
        return None

    # identify the canonical loop exit and outer exception handler by looking at the loop header
    loop_header_edge_dict = get_out_edge_dict(cfg, node)
    canonical_loop_exit, _ = loop_header_edge_dict["conditional"]
    outer_exception_handler, _ = loop_header_edge_dict["exception"]

    # subgraph containing all nodes dominated by the loop header
    dominated_subgraph: nx.DiGraph = cfg.subgraph(n for n in cfg.nodes if dominates(node, n))
    reverse_reachability_map = nx.single_source_shortest_path_length(dominated_subgraph.reverse(), source=node)
    # a node is in the loop if there is a backwards path to the header that doesn't leave the loop
    loop_nodes = [loop_node for loop_node, distance in reverse_reachability_map.items() if distance >= 0]
    # extend loop nodes with their natural edges; you can't leave the loop without a jump of some kind
    # also extend loop nodes with exception edges that do not leave the loop
    natural_edges = [(u, v) for u, v, data in dominated_subgraph.edges(data=True) if data["type"] == ControlFlowEdgeType.NATURAL.value]
    # also extend loop nodes with their conditional edges, excluding the loop header
    conditional_edges = [(u, v) for u, v, data in dominated_subgraph.edges(data=True) if data["type"] in [ControlFlowEdgeType.TRUE_JUMP.value, ControlFlowEdgeType.FALSE_JUMP.value] and u != node]
    internal_exception_edges = [(u, v) for u, v, data in dominated_subgraph.edges(data=True) if data["type"] == ControlFlowEdgeType.EXCEPTION.value and v is not outer_exception_handler]
    natural_dominated_subgraph = dominated_subgraph.edge_subgraph(natural_edges + internal_exception_edges + conditional_edges)
    loop_nodes = set(loop_nodes + [v for _, v in nx.edge_dfs(natural_dominated_subgraph, source=loop_nodes)])

    # canonical loop exit can be misidentified in while trues that start with if statements
    if canonical_loop_exit and any(exit_successor in loop_nodes for exit_successor in cfg.successors(canonical_loop_exit)):
        canonical_loop_exit = None

    # There are 4 kinds of exits:
    # 1. canonical exit (the conditional branch from the loop header)
    # 2. break statement
    # 3. return statement
    # 4. raised exception caught outside loop
    loop_exit_edges = [(src, dst) for src, dst in cfg.edges if src in loop_nodes and dst not in loop_nodes and cfg.get_edge_data(src, dst)["type"] != ControlFlowEdgeType.META.value]

    loop_successor = None
    break_edges = []
    for loop_node, exit_node in loop_exit_edges:
        # skip the canonical exit
        if loop_node is node and exit_node is canonical_loop_exit:
            continue

        # skip exception edges to the outer handler
        if cfg.get_edge_data(loop_node, exit_node)["type"] == ControlFlowEdgeType.EXCEPTION.value and exit_node is outer_exception_handler:
            continue

        # all other cases are exhausted, so we are now only considering break statements
        if loop_successor is None:
            loop_successor = exit_node
        elif loop_successor != exit_node:
            if os.environ.get("DEBUG_CFLOW", None) == "1":
                breakpoint()
            raise RuntimeError("Found multiple break targets in the same loop!")

        break_edges.append((loop_node, exit_node))

    # if there are no break statements, then the successor is the canonical exit
    # the canonical exit may be different in the case of a loop-else, but that only matters if there are breaks
    if loop_successor is None:
        loop_successor = canonical_loop_exit

    # continue edges are all the latching nodes; may be explicit or implicit
    continue_edges = [(src, node) for src in latching_nodes]

    # if we found nothing to refine, then exit
    if not continue_edges and not break_edges:
        return None

    # reduce the break/continue edges
    reduced_cfg = cfg.copy()
    for continue_edge in set(continue_edges):
        LoopExitTemplate.structure_edge_inplace(reduced_cfg, continue_edge, exit_statment="continue")

    for break_edge in set(break_edges):
        LoopExitTemplate.structure_edge_inplace(reduced_cfg, break_edge, exit_statment="break")

    # partially structure the loop while we have the information available
    # if the canonical exit is not the successor, then the canonical exit is a loop else
    if canonical_loop_exit is not None and loop_successor is not None and canonical_loop_exit != loop_successor:
        loop_else_out_edges = get_out_edge_dict(reduced_cfg, canonical_loop_exit)
        if loop_else_out_edges["natural"] is not None and loop_else_out_edges["natural"][0] != loop_successor:
            # todo: fix triple nested loop w else break
            e = (canonical_loop_exit, loop_else_out_edges["natural"][0])
            if dominates(e[1], e[0]):
                # backwards edge
                canonical_loop_exit = LoopExitTemplate.structure_edge_inplace(reduced_cfg, e, exit_statment="continue")
            else:
                canonical_loop_exit = LoopExitTemplate.structure_edge_inplace(reduced_cfg, e, exit_statment="break")
    PreRefinedLoopTemplate.structure_nodes_inplace(reduced_cfg, loop_header=node, canonical_loop_exit=canonical_loop_exit, loop_successor=loop_successor)

    return reduced_cfg


def get_line_out_edge_dict(cfg: nx.DiGraph, insts: list[Inst]) -> dict[str, tuple[Any, ControlFlowEdgeType]]:
    # check that all outgoing edges of a given category have the same target
    line_out_edge_dict = dict()
    for inst in insts:
        for edge_category, (edge_target, edge_data) in get_out_edge_dict(cfg, inst).items():
            # skip considering internal control flow
            if edge_target is None or edge_target in insts:
                continue
            # add edge to line-level mapping if this is the first time we've seen it
            if edge_category not in line_out_edge_dict:
                line_out_edge_dict[edge_category] = (edge_target, edge_data["type"])
            # reject inconsistent mappings; this line cannot be condensed
            elif edge_target != line_out_edge_dict[edge_category]:
                return None
    return line_out_edge_dict


def condense_lines(cfg: nx.DiGraph, bytecode: EditableBytecode) -> nx.DiGraph:
    lno_insts = bytecode.get_lno_insts()
    for line_number, insts in lno_insts.items():
        insts = [inst for inst in insts if inst in cfg.nodes]  # discard unreachable instructions
        if not insts:
            continue
        line_in_edges = cfg.in_edges(nbunch=insts, data=True)
        # check that no edges come from the outside to the middle of the line (sanity check)
        incoming_edges = [(src, dst, data) for src, dst, data in line_in_edges if src not in insts]
        if any(dst != insts[0] for src, dst, data in incoming_edges):
            continue

        line_out_edge_dict = get_line_out_edge_dict(cfg, insts)
        if line_out_edge_dict is None:
            continue

        # group up all the instructions in the line into a LineTemplate
        line_template = LineTemplate(*[InstructionTemplate(inst) for inst in insts])
        cfg.remove_nodes_from(insts)
        cfg.add_node(line_template)
        cfg.add_edges_from((src, line_template, data) for src, dst, data in incoming_edges)
        for edge_category, (target, edge_type) in line_out_edge_dict.items():
            cfg.add_edge(line_template, target, type=edge_type)


def condense_basic_blocks(cfg: nx.DiGraph) -> nx.DiGraph:
    structured_cfg = cfg.copy()
    for node in list(structured_cfg.nodes):
        if node == "START":
            continue
        candidate_cfg = LinearSequenceTemplate.try_to_match_node(structured_cfg, node)
        if candidate_cfg is not None:
            structured_cfg = candidate_cfg
    return structured_cfg


def structure_control_flow(cfg: nx.DiGraph, bytecode: EditableBytecode) -> ControlFlowTemplate:
    # group lines with no weird control flow into LineTemplates
    # currently reduces overall performance on 3.9
    # condense_lines(cfg, bytecode)

    # 1. wrap instructions globally
    structured_cfg = InstructionTemplate.match_graph(cfg)
    root_node = min([inst_template for inst_template in structured_cfg.nodes], key=lambda inst_template: inst_template.get_instructions()[0].offset)
    structured_cfg.add_nodes_from(["START", "END"])
    structured_cfg.add_edge("START", root_node, type="meta")
    structured_cfg.add_edges_from((inst_template, "END", {"type": "meta"}) for inst_template in structured_cfg.nodes if isinstance(inst_template, InstructionTemplate) and inst_template.instruction.opname in ["RETURN_VALUE", "RETURN_CONST"])

    modification_counter = 0
    # 2. match linear sequences globally
    structured_cfg = condense_basic_blocks(structured_cfg)

    # 3. repeat until the graph has no non-meta edges
    #    3a. Check for matches on loop templates
    #    3b. Check for matches on non-loop templates
    #    3c. Check for matches on exception templates
    visualize(structured_cfg, bytecode.name, modification_counter)

    def fully_structured(cfg: nx.DiGraph) -> bool:
        # if there are any non-meta edges, the control flow is not fully structured
        if any(edge_type != ControlFlowEdgeType.META.value for _, _, edge_type in structured_cfg.edges(data="type")):
            return False
        # if there is more than one node other than START and END, the control flow is not fully structured
        if len(cfg) > 3:
            return False
        return True

    infinite_loop_detection_threshold = 50

    while not fully_structured(structured_cfg):
        modified = False
        for acyclic_templates in get_acyclic_template_passes(version=bytecode.version.as_tuple()):
            current_num_nodes = len(structured_cfg.nodes)
            for node in nx.dfs_postorder_nodes(structured_cfg, source="START"):
                # don't process the start node
                if node in ["START", "END"]:
                    continue

                if new_cfg := structure_loop(structured_cfg, node):
                    structured_cfg = new_cfg
                    modified = True
                    modification_counter += 1
                    visualize(structured_cfg, bytecode.name, modification_counter)
                    break

                # check acyclic patterns if no cyclic pattern was matched
                for template in acyclic_templates:
                    candidate_cfg = template.try_to_match_node(structured_cfg, node)
                    if candidate_cfg is not None:
                        structured_cfg = candidate_cfg
                        modified = True
                        modification_counter += 1
                        visualize(structured_cfg, bytecode.name, modification_counter)
                        break

                if modified:
                    break

            if modified:
                break

        if not modified:
            # if in debug mode and template is irreducible breakpoint to inspect cfg
            if os.environ.get("DEBUG_CFLOW", None) == "1":
                breakpoint()
            return IrreduciblePlaceholderTemplate("irreducible")
        else:
            new_num_nodes = len(structured_cfg)
            if new_num_nodes >= current_num_nodes:
                infinite_loop_detection_threshold -= 1
            else:
                infinite_loop_detection_threshold = 50

        if infinite_loop_detection_threshold <= 0:
            return IrreduciblePlaceholderTemplate("infinite grammar loop")

    structured_cfg.remove_nodes_from(["START", "END"])

    return list(structured_cfg.nodes)[0]
