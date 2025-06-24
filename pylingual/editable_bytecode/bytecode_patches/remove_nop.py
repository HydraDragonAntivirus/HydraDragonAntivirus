from ..EditableBytecode import EditableBytecode


def remove_nop(bytecode: EditableBytecode):
    to_remove = [x for x in bytecode.instructions if x.opname == "NOP"]
    bytecode.remove_instructions(to_remove)
