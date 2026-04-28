from .EditableBytecode import EditableBytecode
from .Instruction import Inst
from .PYCFile import PYCFile

from . import bytecode_patches as bytecode_patches

__all__ = ["EditableBytecode", "Inst", "PYCFile", "bytecode_patches"]
