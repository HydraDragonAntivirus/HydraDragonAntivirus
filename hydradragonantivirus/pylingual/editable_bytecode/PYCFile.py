from pylingual.utils.version import PythonVersion
from .EditableBytecode import EditableBytecode
from .utils import write_pyc

from xdis.load import load_module_from_file_object, load_module
import xdis.opcodes

from io import BytesIO
import pathlib


class PYCFile(EditableBytecode):
    """Represents a .pyc file. Upon creation, extracts all the bytecode from it."""

    def __init__(self, source, name_prefix=None):
        self.pyc_path = None
        source_tuple = (None, None, None, None, None, None, None)
        if isinstance(source, bytes):
            source = BytesIO(source)
            source_tuple = load_module_from_file_object(source)
        elif isinstance(source, pathlib.Path):
            source_tuple = load_module(str(source))
            self.pyc_path = source
        elif source is not None:
            source_tuple = load_module(source)

        (
            version,
            self.timestamp,
            self.magic,
            self.code,
            self.ispypy,
            self.source_size,
            self.sip_hash,
        ) = source_tuple

        self.version = PythonVersion(version)
        opcode = getattr(xdis.opcodes, f"opcode_{self.version[0]}{self.version[1]}")

        EditableBytecode.__init__(
            self,
            self.code,
            opcode,
            self.version,
            name_prefix=name_prefix,
        )

    def copy(self):
        try:
            copy = PYCFile(None)
            EditableBytecode.__init__(copy, self.to_code(), self.opcode, self.version, self.name_prefix, False)
        except IndexError:
            copy = EditableBytecode.copy(self)

        for attr in (
            "version",
            "timestamp",
            "magic",
            "code",
            "ispypy",
            "source_size",
            "sip_hash",
        ):
            setattr(copy, attr, getattr(self, attr))

        return copy

    def save(self, file, should_close=True, no_lnotab=False):
        """Saves the current recursive bytecode to the specified file."""
        if isinstance(file, str):
            file = open(file, "wb")

        write_pyc(
            file,
            self.to_code(no_lnotab=no_lnotab),
            self.version,
            self.magic,
            self.timestamp,
            self.source_size,
        )

        if should_close:
            file.close()
        return file
