from __future__ import annotations

import itertools
from typing import TYPE_CHECKING
from pathlib import Path

import networkx as nx
import pydot

from pylingual.editable_bytecode import EditableBytecode
from pylingual.utils.lists import flatten
from .cft import ControlFlowTemplate, EdgeKind, InstTemplate, MetaTemplate
from .templates.Block import BlockTemplate

if TYPE_CHECKING:
    DiGraph_CFT = nx.DiGraph[ControlFlowTemplate]
else:
    DiGraph_CFT = nx.DiGraph


class CFG(DiGraph_CFT):
    bytecode: EditableBytecode
    i: int
    start: ControlFlowTemplate
    end: ControlFlowTemplate
    iteration_graphs: list[list[str | list]]
    run: int

    @staticmethod
    def enable_graphing(graph_path: Path | str, fmt: str = "jpg"):
        CFG.visualize = CFG._visualize
        CFG.layout_nodes = CFG._layout_nodes
        CFG.graph_path = Path(graph_path)
        CFG.graph_path.mkdir(exist_ok=True, parents=True)
        CFG.graph_format = fmt

    @staticmethod
    def from_graph(cfg: nx.DiGraph, bytecode: EditableBytecode, iterate=True) -> CFG:
        self = CFG(cfg)

        self.bytecode = bytecode
        self.i = 0
        self.start = MetaTemplate("start", bytecode.codeobj)
        self.end = MetaTemplate("end", bytecode.codeobj)
        self.iteration_graphs = []
        self.run = 0

        InstTemplate.match_all(self)

        for _a, _b, _p in self.edges(data=True):
            self[_a][_b]["kind"] = EdgeKind(_p["type"])

        root_node = min([x for x in self.nodes], key=lambda x: x.get_instructions()[0].offset)
        self.add_nodes_from([self.start, self.end])
        self.add_edge(self.start, root_node, kind=EdgeKind.Meta)
        self.add_edges_from((node, self.end, EdgeKind.Meta.prop()) for node in self.nodes if isinstance(node, InstTemplate) and self.out_degree(node) == 0)

        BlockTemplate.match_all(self)
        if iterate:
            self.iterate()

        return self

    def iterate(self):
        if not self.iteration_graphs:
            self.i += 1
        self.visualize()

    def speculate(self):
        self.iteration_graphs.append([])

    def drop_graphs(self):
        self.iteration_graphs.pop()

    def ordered_iter(self):
        self._create_dominator_tree()
        return nx.dfs_postorder_nodes(self, source=self.start, sort_neighbors=lambda nodes: sorted(nodes, key=lambda x: x.offset, reverse=True))

    def is_loop_header(self, node):
        # Check all predecessors
        for predecessor in self.predecessors(node):
            # A back edge exists if the predecessor is dominated by this node
            if self.dominates(node, predecessor):
                return True
        return False

    def dfs_labeled_edges_no_loop(self, source=None, depth_limit=None, *, sort_neighbors=None):
        if source is None:
            # edges for all components
            nodes = self
        else:
            # edges for components with source
            nodes = [source]
        if depth_limit is None:
            depth_limit = len(self)

        get_children = self.neighbors if sort_neighbors is None else lambda n: iter(sort_neighbors(self.neighbors(n)))

        visited = set()
        for start in nodes:
            if start in visited:
                continue
            yield start, start, "forward"
            visited.add(start)
            stack = [(start, get_children(start))]
            depth_now = 1
            while stack:
                parent, children = stack[-1]
                for child in children:
                    if child in visited or self.is_loop_header(child) or not all(p in visited for p in self.predecessors(child)):
                        yield parent, child, "nontree"
                    else:
                        yield parent, child, "forward"
                        visited.add(child)
                        if depth_now < depth_limit:
                            stack.append((child, iter(get_children(child))))
                            depth_now += 1
                            break
                        else:
                            yield parent, child, "reverse-depth_limit"
                else:
                    stack.pop()
                    depth_now -= 1
                    if stack:
                        yield stack[-1][0], parent, "reverse"
            yield start, start, "reverse"

    def apply_graphs(self):
        graphs = self.iteration_graphs.pop()
        if self.iteration_graphs:
            self.iteration_graphs[-1].append(graphs)
        else:
            for x in flatten(graphs):
                g = pydot.graph_from_dot_data(x)[0]
                g.write(str(CFG.graph_path / g.get_name().replace('"', "")), prog=["neato", "-n"], format=CFG.graph_format)

    def layout_nodes(self):
        pass

    def _layout_nodes(self):
        relabeled = nx.convert_node_labels_to_integers(self, label_attribute="template")  # type: ignore

        root = next(i for i in relabeled.nodes if relabeled.nodes[i]["template"] == self.start)
        for i, pos in nx.nx_pydot.pydot_layout(relabeled, prog="dot", root=root).items():
            relabeled.nodes[i]["template"]._pos = [pos]

    def node_by_offset(self, offset: int):
        return next(x for x in self.nodes if x.offset == offset)

    def _create_dominator_tree(self):
        self._dt = nx.create_empty_copy(self)
        self._dt.add_edges_from(nx.immediate_dominators(self, self.start).items())
        self._dt.remove_edge(self.start, self.start)
        self._dr = nx.transitive_closure_dag(self._dt.reverse())

    def dominates(self, node_a, node_b):
        return self._dr.has_edge(node_a, node_b) or node_a == node_b

    def visualize(self):
        pass

    def _visualize(self):
        for n in self.nodes:
            self.nodes[n]["label"] = repr(n)

        if not self.start._pos:
            self.layout_nodes()

        i = "-".join([str(self.i)] + [str(len(x)) for x in self.iteration_graphs])
        out = Path(f"{CFG.graph_path}/{self.bytecode.name}_{self.bytecode.version[1]}_{i}.{CFG.graph_format}")
        dot = pydot.Dot(out.name, splines=True)
        nodes = {}

        for node, data in self.nodes.data():
            nodes[node] = pydot.Node(str(hash(node)), label=repr(node).replace("\n", "\\l").replace("\t", "|    ") + "\\l", fontname="Noto Sans", labeljust="l", shape="box", pos=node.pos())
            dot.add_node(nodes[node])
        for a, b, data in self.edges.data():
            dot.add_edge(pydot.Edge(nodes[a], nodes[b], **data, label=data["kind"].value, color=data["kind"].color(), fontname="Noto Sans", labeljust="l"))
        if not self.iteration_graphs:
            dot.write(out, prog=["neato", "-n"], format=CFG.graph_format)
        else:
            self.iteration_graphs[-1].append(dot.to_string())

    def cdg(self) -> CFG:
        pdt = nx.create_empty_copy(self)
        pdt.add_edges_from((B, A) for A, B in nx.immediate_dominators(self.reverse(), self.end).items())
        pdt.remove_edge(self.end, self.end)
        pdr = nx.transitive_closure_dag(pdt)
        postdominates = lambda A, B: pdr.has_edge(A, B) or A == B
        control_dependent = lambda A, B: 0 < sum(postdominates(A, succ) for succ in self.successors(B)) < self.out_degree(B)
        cdg = nx.create_empty_copy(self)
        cdg.add_edges_from((B, A, {"kind": EdgeKind.Fall}) for A, B in itertools.product(self.nodes, self.nodes) if A != B and control_dependent(A, B))
        cdg.remove_node(self.end)
        cdg.add_edges_from(((self.start, n) for n in cdg.nodes if cdg.in_degree(n) == 0 and n != self.start), kind=EdgeKind.Fall)
        return cdg
