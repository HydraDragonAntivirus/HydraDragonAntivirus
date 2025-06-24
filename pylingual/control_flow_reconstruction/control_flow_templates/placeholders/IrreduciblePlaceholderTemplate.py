from ..abstract.AbstractTemplate import ControlFlowTemplate


class IrreduciblePlaceholderTemplate(ControlFlowTemplate):
    def __init__(self, msg):
        self.msg = msg

    def to_indented_source(self, source_lines: list[str]) -> str:
        return f"pass  # cflow: {self.msg}"
