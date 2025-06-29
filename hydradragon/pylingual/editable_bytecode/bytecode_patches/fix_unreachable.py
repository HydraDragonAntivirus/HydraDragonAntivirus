from ..EditableBytecode import EditableBytecode


def fix_unreachable(bytecode: EditableBytecode):
    bytecode.remove_unreachable_instructions()
    bytecode.remove_useless_jumps()
    bytecode._bake_jumps()
