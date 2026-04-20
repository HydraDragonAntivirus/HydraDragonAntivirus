"""
omni_nuitka_framework.py

Heuristic CPython source reconstruction from Nuitka section metadata.
The goal here is not pyc decompilation.  This module stays on the
metadata/CPython-structure side and tries to rebuild readable class and
function source directly from Nuitka blob sections.
"""

from __future__ import annotations

import functools
import keyword
import re
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


# ---------------------------------------------------------------------------
# Nuitka packed-signature tags
# ---------------------------------------------------------------------------

class NuitkaTags:
    ARG          = "a"
    USER_DEF     = "u"
    PRIVATE_DEF  = "p"
    OBJECT_TYPE  = "O"


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

def b2s_safe(val: Any) -> str:
    """Coerce any value to a UTF-8-safe string without raising."""
    if val is None:
        return "None"
    if isinstance(val, str):
        return val
    if isinstance(val, (int, float, bool)):
        return str(val)
    if isinstance(val, (tuple, list, dict, set, frozenset)):
        return str(val)
    if isinstance(val, (bytes, bytearray)):
        try:
            return val.decode("utf-8")
        except UnicodeDecodeError:
            return val.decode("latin-1", errors="replace")
    return repr(val)


def is_b64_image(val: Any) -> bool:
    s = b2s_safe(val) if isinstance(val, (bytes, bytearray)) else str(val)
    return "iVBORw0KGgo" in s or "JFIF" in s


def _trim_sequence(seq: list[Any], marker: Any, limit: int = 12) -> list[Any]:
    """Return *seq* truncated to *limit* items, appending *marker* if trimmed."""
    return seq[:limit] + [marker] if len(seq) > limit else seq


def literal_source(value: Any) -> str:
    """Produce a compact repr suitable for embedding in generated source."""
    if isinstance(value, bytes):
        return repr(b2s_safe(value))
    if isinstance(value, tuple):
        return repr(tuple(_trim_sequence(list(tuple_texts(value)), "...")))
    if isinstance(value, list):
        return repr(_trim_sequence(list(tuple_texts(value)), "..."))
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in list(value.items())[:20]:
            cleaned[b2s_safe(key)] = (
                b2s_safe(item) if isinstance(item, (bytes, bytearray)) else item
            )
        return repr(cleaned)
    return repr(value)


def tuple_texts(value: Any) -> tuple[Any, ...]:
    """Decode bytes items inside a tuple/list; leave everything else as-is."""
    if not isinstance(value, (tuple, list)):
        return ()
    result: list[Any] = []
    for item in value:
        result.append(b2s_safe(item) if isinstance(item, (bytes, bytearray, str)) else item)
    return tuple(result)


# ---------------------------------------------------------------------------
# Annotation helpers
# ---------------------------------------------------------------------------

def is_annotation_dict(d: Any) -> bool:
    if not isinstance(d, dict) or not d or len(d) > 25:
        return False
    for key in d.keys():
        text = b2s_safe(key) if isinstance(key, (bytes, bytearray)) else (key if isinstance(key, str) else None)
        if text is None:
            return False
        if not text.isidentifier() and text != "return":
            return False
    return True


def decode_annotation_blob(d: dict[Any, Any]) -> OrderedDict[str, str]:
    annotations: OrderedDict[str, str] = OrderedDict()
    if not isinstance(d, dict):
        return annotations
    for key, value in d.items():
        name = b2s_safe(key)
        if value is None:
            annotations[name] = "Any"
        elif isinstance(value, bool):
            annotations[name] = "bool"
        elif isinstance(value, int):
            annotations[name] = "int"
        elif isinstance(value, float):
            annotations[name] = "float"
        elif isinstance(value, str):
            annotations[name] = value if value[:1].isupper() else "str"
        elif isinstance(value, (bytes, bytearray)):
            text = b2s_safe(value)
            annotations[name] = text if text[:1].isupper() else "str"
        else:
            annotations[name] = type(value).__name__
    return annotations


# ---------------------------------------------------------------------------
# Packed-signature parser
# ---------------------------------------------------------------------------

def parse_nuitka_packed_signature(
    raw_bytes: bytes | str,
) -> tuple[list[str], list[str], dict[str, str]]:
    """
    Parse a Nuitka packed-signature blob into (method_refs, args, type_hints).

    The blob is NUL-separated segments where the first byte is a tag character
    defined in *NuitkaTags*.
    """
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("utf-8", errors="replace")

    method_refs: list[str] = []
    args: list[str] = []
    types: dict[str, str] = {}

    for segment in raw_bytes.split(b"\x00"):
        if not segment:
            continue
        text = segment.decode("utf-8", errors="replace")
        if not text:
            continue
        tag, name = text[0], text[1:]
        if tag == NuitkaTags.ARG:
            args.append(name)
        elif tag == NuitkaTags.OBJECT_TYPE:
            if args:
                types[args[-1]] = name
        elif tag in (NuitkaTags.USER_DEF, NuitkaTags.PRIVATE_DEF):
            parts = name.split(".", 1)
            if len(parts) == 2 and parts[0].isidentifier():
                method_refs.append(name)

    return method_refs, args, types


# ---------------------------------------------------------------------------
# Classification regexes & constant sets
# ---------------------------------------------------------------------------

IDENTIFIER_RE      = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLASS_NAME_RE      = re.compile(r"^_?[A-Z][A-Za-z0-9_]*$")
IMPORT_PATH_RE     = re.compile(r"^[a-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
METHOD_REF_RE      = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$")
HTTP_ENDPOINT_RE   = re.compile(r"https?://[A-Za-z0-9]|/functions/[A-Za-z0-9_]")

DECORATOR_NAMES: frozenset[str] = frozenset(
    {"property", "abstractmethod", "staticmethod", "classmethod"}
)
META_FIELD_NAMES: frozenset[str] = frozenset({
    "__prepare__", "__qualname__", "__firstlineno__", "__static_attributes__",
    "__orig_bases__", "__getitem__", "metaclass", "annotations", "origin",
    "has_location", "__module__",
})
KNOWN_METHOD_NAMES: frozenset[str] = frozenset({
    "__init__", "__new__", "__repr__", "__str__", "__bytes__",
    "__eq__", "__hash__", "__reduce__", "__iter__", "__len__",
    "__bool__", "__contains__", "__copy__",
    "prepare", "copy", "clone", "close", "json",
    "value", "type_id", "_packed", "_init_without_validation",
    "register_hook", "deregister_hook",
})
KNOWN_METHOD_PREFIXES: tuple[str, ...] = (
    "prepare_", "register_", "deregister_", "iter_", "get_", "set_",
    "raise_", "encode_", "decode_", "_encode_", "_get_", "_init_",
    "add_", "remove_", "clear_", "reset_", "is_", "has_", "can_",
)
KNOWN_BASE_NAMES: frozenset[str] = frozenset({
    "Exception", "Warning", "ValueError", "TypeError", "RuntimeError",
    "ConnectionError", "LookupError", "MessageDefect", "IncompleteRead",
})
NOISE_CLASS_NAMES: frozenset[str] = frozenset({
    "ABCMeta", "Callable", "Iterable", "Mapping", "OrderedDict", "Path",
    "Sequence", "defaultdict",
})
WEAK_TOPLEVEL_FUNCTION_NAMES: frozenset[str] = frozenset({
    "self", "cls", "url", "warn", "reason", "conn", "header", "headers",
    "body", "json", "data", "params", "value", "type", "origin", "message",
    "status", "host", "path", "replace", "warnings", "lstrip",
})
MODULE_DOCSTRING_HINTS: tuple[str, ...] = (
    "module", "package", "utilities", "helpers", "exceptions",
    "tools", "support", "constants",
)
MODULE_DOCSTRING_BAD_PREFIXES: tuple[str, ...] = (
    "build ", "parse ", "return ", "create ", "construct ", "convert ",
    "serialize ", "deserialize ", "encode ", "decode ", "represent ",
    "initialize ", "prepare ", "register ", "deregister ",
    "max retries exceeded",
)
_C_API_PREFIXES: tuple[str, ...] = (
    "SSL_", "X509_", "EVP_", "BIO_", "OBJ_", "ASN1_", "PEM_",
    "PKCS", "RSA_", "EC_", "DH_",
)

TYPING_NAMES: frozenset[str] = frozenset({"Any", "Callable", "Mapping", "Iterable", "Sequence"})


# ---------------------------------------------------------------------------
# Text classification helpers
# ---------------------------------------------------------------------------

def clean_docstring(text: Any) -> str | None:
    s = str(text).strip()
    return s.replace("\r\n", "\n").replace("\r", "\n") if s else None


@functools.lru_cache(maxsize=4096)
def safe_identifier(name: str | None) -> str | None:
    """
    Sanitise *name* into a valid Python identifier, or return *None*.

    Results are cached because the same strings recur many thousands of
    times during a typical blob scan.
    """
    if name is None:
        return None
    text = str(name).strip().replace("-", "_").replace(" ", "_")
    text = re.sub(r"[^0-9A-Za-z_]", "_", text)
    if not text:
        return None
    if text[0].isdigit():
        text = "_" + text
    if keyword.iskeyword(text):
        text += "_"
    return text if IDENTIFIER_RE.fullmatch(text) else None


def normalize_annotation_text(value: Any) -> str | None:
    text = b2s_safe(value).strip()
    if not text:
        return None
    _replacements = {
        "typing.Any":      "Any",
        "typing.Callable": "Callable",
        "typing.Mapping":  "Mapping",
        "typing.Iterable": "Iterable",
        "typing.Sequence": "Sequence",
    }
    return _replacements.get(text, text)


def is_probable_docstring(text: Any) -> bool:
    if not isinstance(text, str):
        return False
    text = text.strip()
    if len(text) < 12 or " " not in text:
        return False
    if IMPORT_PATH_RE.fullmatch(text) or METHOD_REF_RE.fullmatch(text):
        return False
    return True


def is_probable_import_path(text: Any) -> bool:
    return isinstance(text, str) and bool(IMPORT_PATH_RE.fullmatch(text)) and text.lower() == text


def is_probable_class_name(text: Any) -> bool:
    return (
        isinstance(text, str)
        and bool(CLASS_NAME_RE.fullmatch(text))
        and text not in DECORATOR_NAMES
        and text not in NOISE_CLASS_NAMES
    )


def is_probable_method_name(text: Any) -> bool:
    if not isinstance(text, str):
        return False
    if text in DECORATOR_NAMES or text in META_FIELD_NAMES:
        return False
    if text in KNOWN_METHOD_NAMES:
        return True
    if text.startswith(KNOWN_METHOD_PREFIXES):
        return True
    if text.startswith("__") and text.endswith("__") and len(text) > 4:
        return True
    return bool(IDENTIFIER_RE.fullmatch(text) and text[:1].islower())


def is_probable_endpoint(text: Any) -> bool:
    return isinstance(text, str) and bool(HTTP_ENDPOINT_RE.search(text))


def is_probable_module_docstring(text: str) -> bool:
    if not is_probable_docstring(text):
        return False
    lowered = text.strip().lower()
    if lowered.startswith(MODULE_DOCSTRING_BAD_PREFIXES):
        return False
    if any(token in lowered for token in (" must ", " invalid ", "unsupported ", "deprecated")):
        return False
    return "\n" in text or any(token in lowered for token in MODULE_DOCSTRING_HINTS)


def is_fragmentary_docstring(text: str | None) -> bool:
    cleaned = clean_docstring(text)
    if not cleaned:
        return True
    stripped = cleaned.strip()
    if stripped[:1] in {",", ":", "%", ")"}:
        return True
    if "\n" not in stripped and len(stripped.split()) < 3:
        return True
    return False


def should_render_constant(name: Any) -> bool:
    return isinstance(name, str) and name.isupper() and 3 <= len(name) <= 64


# ---------------------------------------------------------------------------
# AST nodes
# ---------------------------------------------------------------------------

@dataclass
class FunctionDefNode:
    name:        str
    is_method:   bool                    = False
    args:        list[str]               = field(default_factory=list)
    annotations: OrderedDict[str, str]   = field(default_factory=OrderedDict)
    return_type: str | None              = None
    decorators:  list[str]               = field(default_factory=list)
    docstring:   str | None              = None
    messages:    list[str]               = field(default_factory=list)
    string_hints: list[str]              = field(default_factory=list)
    tuples:      list[tuple[Any, ...]]   = field(default_factory=list)
    dict_hints:  list[dict[str, Any]]    = field(default_factory=list)
    literals:    list[Any]               = field(default_factory=list)
    body_lines:  list[str]               = field(default_factory=list)
    line_hint:   int | None              = None

    def reset_hints(self) -> None:
        """Clear all accumulated hints — used when a new method block opens."""
        self.messages.clear()
        self.string_hints.clear()
        self.tuples.clear()
        self.dict_hints.clear()
        self.literals.clear()

    def render(self, indent: int = 0) -> str:
        pad = "    " * indent
        out: list[str] = []

        for decorator in self.decorators:
            out.append(f"{pad}@{decorator}")

        args = self.args[:] or (["self"] if self.is_method else [])
        if "classmethod" in self.decorators and args and args[0] == "self":
            args[0] = "cls"
        if "property" in self.decorators:
            args = ["self"]

        signature: list[str] = []
        for arg in args:
            ann = self.annotations.get(arg)
            signature.append(f"{arg}: {ann}" if ann else arg)

        ret = f" -> {self.return_type}" if self.return_type else ""
        out.append(f"{pad}def {self.name}({', '.join(signature)}){ret}:")

        body: list[str] = []
        if self.docstring:
            doc = clean_docstring(self.docstring) or ""
            doc_lines = doc.splitlines()
            if len(doc_lines) <= 1:
                body.append(f'"""{doc}"""')
            else:
                body.append('"""')
                body.extend(doc_lines)
                body.append('"""')
        body.extend(self.body_lines)
        if not body:
            body = ["pass"]

        body_pad = "    " * (indent + 1)
        for line in body:
            out.append(f"{body_pad}{line}" if line else "")
        return "\n".join(out) + "\n"


@dataclass
class ClassDefNode:
    name:       str
    bases:      list[str]                        = field(default_factory=list)
    docstring:  str | None                       = None
    slots:      tuple[str, ...] | None           = None
    attributes: set[str]                         = field(default_factory=set)
    constants:  OrderedDict[str, str]            = field(default_factory=OrderedDict)
    methods:    OrderedDict[str, FunctionDefNode] = field(default_factory=OrderedDict)

    def render(self, indent: int = 0) -> str:
        pad = "    " * indent
        header = f"{pad}class {self.name}"
        if self.bases:
            header += f"({', '.join(self.bases)})"
        header += ":"
        out = [header]

        body_lines: list[str] = []
        if self.docstring:
            doc = clean_docstring(self.docstring) or ""
            doc_lines = doc.splitlines()
            if len(doc_lines) <= 1:
                body_lines.append(f'"""{doc}"""')
            else:
                body_lines.append('"""')
                body_lines.extend(doc_lines)
                body_lines.append('"""')
        if self.slots:
            body_lines.append(f"__slots__ = {repr(self.slots)}")
        for cname, cval in self.constants.items():
            body_lines.append(f"{cname} = {cval}")
        if self.attributes:
            body_lines.append("# Recovered instance attributes")
            for attr in sorted(self.attributes):
                body_lines.append(f"# self.{attr}")
        for method in self.methods.values():
            if body_lines:
                body_lines.append("")
            body_lines.extend(method.render(indent + 1).rstrip().splitlines())
        if not body_lines:
            body_lines = ["pass"]

        body_pad = "    " * (indent + 1)
        for line in body_lines:
            if not line:
                out.append("")
            elif line.startswith(body_pad) or line.startswith("    " * (indent + 2)):
                # Already carries the correct indentation from method.render()
                out.append(line)
            else:
                out.append(f"{body_pad}{line}")
        return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Pending-state container  (replaces 8 naked local variables + 4 reset blocks)
# ---------------------------------------------------------------------------

@dataclass
class _PendingState:
    docstring:   str | None              = None
    annotations: dict[str, str] | None   = None
    decorators:  list[str]               = field(default_factory=list)
    args:        list[str] | None        = None
    line:        int | None              = None
    dicts:       list[dict[str, Any]]    = field(default_factory=list)
    tuples:      list[tuple[Any, ...]]   = field(default_factory=list)
    literals:    list[Any]               = field(default_factory=list)

    def reset(self) -> None:
        self.docstring   = None
        self.annotations = None
        self.decorators  = []
        self.args        = None
        self.line        = None
        self.dicts       = []
        self.tuples      = []
        self.literals    = []


# ---------------------------------------------------------------------------
# Window-scoring helper (shared by structural heuristics)
# ---------------------------------------------------------------------------

def _score_window(
    items: list[Any],
    start: int,
    length: int,
    *,
    want_annotation_dict: bool = True,
    want_tuple: bool = True,
    want_docstring: bool = True,
    want_lineno: bool = True,
) -> int:
    score = 0
    window = items[start : start + length]
    if want_annotation_dict and any(isinstance(x, dict) and is_annotation_dict(x) for x in window):
        score += 2
    if want_tuple and any(isinstance(x, tuple) and 0 < len(x) <= 12 for x in window):
        score += 1
    if want_docstring and any(isinstance(x, str) and is_probable_docstring(x) for x in window):
        score += 1
    if want_lineno and any(isinstance(x, int) and 0 < x < 10_000 for x in window):
        score += 1
    return score


# ---------------------------------------------------------------------------
# Main decompiler engine
# ---------------------------------------------------------------------------

class OmniDecompiler:
    """
    Two-pass heuristic decompiler for Nuitka metadata blobs.

    Pass 1 — ``run_pass_1_structural_mapping``:
        Scans the raw item stream and builds an in-memory AST of
        :class:`ClassDefNode` and :class:`FunctionDefNode` objects.

    Pass 2 — ``run_pass_2_ast_synthesis``:
        Iterates over the AST nodes and infers a plausible Python body for
        every function using method-name patterns, attribute sets, error
        messages, and other string hints.
    """

    def __init__(self) -> None:
        self.classes:          OrderedDict[str, ClassDefNode]    = OrderedDict()
        self.functions:        OrderedDict[str, FunctionDefNode] = OrderedDict()
        self.module_constants: OrderedDict[str, str]             = OrderedDict()
        self.imports:          OrderedDict[str, None]            = OrderedDict()
        self.from_imports:     OrderedDict[str, OrderedDict[str, None]] = OrderedDict()
        self.api_endpoints:    set[str]                          = set()
        self.images:           OrderedDict[str, int]             = OrderedDict()
        self.vk_table:         OrderedDict[str, Any]             = OrderedDict()
        self.module_docstring: str | None                        = None
        self.class_candidates: set[str]                          = set()
        self.current_class:    str | None                        = None
        self.current_function: FunctionDefNode | None            = None
        self.last_item_name:   str | None                        = None

    # ------------------------------------------------------------------
    # Node factories
    # ------------------------------------------------------------------

    def ensure_class(self, cls_name: str | None) -> ClassDefNode | None:
        cls_name = safe_identifier(cls_name)
        if not cls_name:
            return None
        if cls_name not in self.classes:
            self.classes[cls_name] = ClassDefNode(cls_name)
        return self.classes[cls_name]

    def ensure_function(self, func_name: str | None) -> FunctionDefNode | None:
        func_name = safe_identifier(func_name)
        if not func_name:
            return None
        if func_name not in self.functions:
            self.functions[func_name] = FunctionDefNode(func_name, is_method=False)
        return self.functions[func_name]

    def ensure_method(self, cls_name: str | None, method_name: str | None) -> FunctionDefNode | None:
        cls_node   = self.ensure_class(cls_name)
        method_name = safe_identifier(method_name)
        if cls_node is None or not method_name:
            return None
        if method_name not in cls_node.methods:
            cls_node.methods[method_name] = FunctionDefNode(method_name, is_method=True, args=["self"])
        return cls_node.methods[method_name]

    def record_import(self, module_path: str, names: list[str] | None = None) -> None:
        if not is_probable_import_path(module_path):
            return
        if names:
            bucket = self.from_imports.setdefault(module_path, OrderedDict())
            for name in names:
                ident = safe_identifier(name)
                if ident:
                    bucket[ident] = None
        else:
            self.imports[module_path] = None

    # ------------------------------------------------------------------
    # Pass 1 — structural mapping helpers
    # ------------------------------------------------------------------

    def _collect_class_candidates(self, items: list[Any]) -> set[str]:
        scores: defaultdict[str, int] = defaultdict(int)
        for index, item in enumerate(items):
            text = b2s_safe(item) if isinstance(item, (bytes, bytearray)) else (item if isinstance(item, str) else None)
            if not isinstance(text, str):
                continue
            # Explicit ClassName.method refs score the owner class directly
            match = METHOD_REF_RE.fullmatch(text)
            if match:
                owner = match.group(1)
                if is_probable_class_name(owner):
                    scores[owner] += 5
                continue
            if not is_probable_class_name(text):
                continue
            score = _score_window(items, index + 1, 10)
            window = items[index + 1 : index + 10]
            if any(
                isinstance(x, (bytes, bytearray, str))
                and b2s_safe(x) in META_FIELD_NAMES | DECORATOR_NAMES
                for x in window
            ):
                score += 2
            if any(
                isinstance(x, (bytes, bytearray, str)) and is_probable_method_name(b2s_safe(x))
                for x in window
            ):
                score += 2
            if score >= 3:
                scores[text] += score
        return {name for name, s in scores.items() if s >= 3}

    def _should_capture_module_docstring(self, items: list[Any], index: int, text: str) -> bool:
        if self.current_class or self.current_function:
            return False
        if index > 4 or not is_probable_module_docstring(text):
            return False
        window = items[index + 1 : index + 6]
        if any(
            isinstance(x, (bytes, bytearray, str)) and is_probable_import_path(b2s_safe(x))
            for x in window
        ):
            return True
        return "\n" in text

    def _looks_like_toplevel_function(
        self,
        items: list[Any],
        index: int,
        text: str,
        pending: _PendingState,
    ) -> bool:
        if text in WEAK_TOPLEVEL_FUNCTION_NAMES or text.startswith("__") or is_probable_import_path(text):
            return False
        score = 0
        if pending.annotations:
            score += 2
        if pending.args:
            score += 1
        score += _score_window(items, index + 1, 6)
        if any(
            isinstance(x, tuple)
            and 0 < len(x) <= 8
            and all(safe_identifier(b2s_safe(v)) for v in x)
            for x in items[index + 1 : index + 7]
        ):
            score += 1
        return score >= 3

    def _looks_like_method_block(self, items: list[Any], index: int, text: str) -> bool:
        if not is_probable_method_name(text):
            if not (self.current_class and text.startswith("_") and IDENTIFIER_RE.fullmatch(text)):
                return False
        score = _score_window(items, index + 1, 10)
        if text in KNOWN_METHOD_NAMES or text.startswith(KNOWN_METHOD_PREFIXES):
            score += 2
        if text.startswith("_") and self.current_class:
            score += 1
        return score >= 2

    def _hydrate_class_metadata(self, items: list[Any], index: int, cls_node: ClassDefNode) -> None:
        if not cls_node.docstring:
            for offset, candidate in enumerate(items[index + 1 : index + 8], start=1):
                if isinstance(candidate, (bytes, bytearray, str)):
                    txt = b2s_safe(candidate)
                    if txt in self.class_candidates and txt != cls_node.name:
                        break
                    if METHOD_REF_RE.fullmatch(txt) or self._looks_like_method_block(items, index + offset, txt):
                        break
                if isinstance(candidate, str) and is_probable_docstring(candidate):
                    cls_node.docstring = clean_docstring(candidate)
                    break
        if not cls_node.bases:
            for candidate in reversed(items[max(0, index - 3) : index]):
                txt = b2s_safe(candidate) if isinstance(candidate, (bytes, bytearray)) else (candidate if isinstance(candidate, str) else None)
                if not isinstance(txt, str):
                    continue
                if txt in {"ABCMeta", "Callable", "Mapping"}:
                    continue
                if txt in KNOWN_BASE_NAMES or (
                    is_probable_class_name(txt)
                    and txt not in self.class_candidates
                    and txt != cls_node.name
                ):
                    cls_node.bases.append(txt)
                    break

    # ------------------------------------------------------------------
    # Pending-state → function helper
    # ------------------------------------------------------------------

    def _apply_pending(
        self,
        func: FunctionDefNode | None,
        pending: _PendingState,
    ) -> None:
        if func is None:
            return
        ann = self._normalize_annotations(pending.annotations)
        explicit_args = self._normalize_args(pending.args, method=func.is_method)
        if not explicit_args and ann:
            explicit_args = self._normalize_args(
                [n for n in ann if n != "return"], method=func.is_method
            )
        if explicit_args:
            func.args = explicit_args
        if ann:
            func.annotations.update({k: v for k, v in ann.items() if k != "return"})
            if ann.get("return"):
                func.return_type = ann["return"]
        for decorator in pending.decorators:
            if decorator not in func.decorators:
                func.decorators.append(decorator)
        if pending.docstring and not func.docstring:
            func.docstring = clean_docstring(pending.docstring)
        if pending.line and not func.line_hint:
            func.line_hint = pending.line
        for d in pending.dicts:
            self._record_target_hint(func, "dict", d)
        for t in pending.tuples:
            self._record_target_hint(func, "tuple", t)
        for lit in pending.literals:
            self._record_target_hint(func, "literal", lit)

    # ------------------------------------------------------------------
    # Hint recording
    # ------------------------------------------------------------------

    def _record_target_hint(self, target: FunctionDefNode | None, kind: str, value: Any) -> None:
        if target is None:
            return
        if kind == "dict":
            target.dict_hints.append(self._trim_dict(value))
        elif kind == "tuple":
            target.tuples.append(tuple_texts(value))
        elif kind == "literal":
            target.literals.append(value)
        elif kind == "message":
            text = clean_docstring(value)
            if text and text not in target.messages:
                target.messages.append(text)
        elif kind == "string":
            text = b2s_safe(value)
            if text and text not in target.string_hints:
                target.string_hints.append(text)

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _normalize_args(self, values: list[Any] | None, *, method: bool = False) -> list[str]:
        args: list[str] = []
        for v in values or ():
            ident = safe_identifier(b2s_safe(v))
            if ident and ident not in {"return", "None"}:
                args.append(ident)
        if method:
            if not args or args[0] != "self":
                args = ["self"] + [a for a in args if a != "self"]
        return args

    def _normalize_annotations(self, ann_dict: dict[str, Any] | None) -> OrderedDict[str, str]:
        result: OrderedDict[str, str] = OrderedDict()
        for key, value in (ann_dict or {}).items():
            ident = safe_identifier(key)
            if ident:
                text = normalize_annotation_text(value)
                if text:
                    result[ident] = text
        return result

    @staticmethod
    def _trim_dict(value: dict[Any, Any]) -> dict[str, Any]:
        return {
            b2s_safe(k): (b2s_safe(v) if isinstance(v, (bytes, bytearray)) else v)
            for k, v in list(value.items())[:20]
        }

    # ------------------------------------------------------------------
    # Pass 1 — item dispatch
    # ------------------------------------------------------------------

    def _dispatch_packed(
        self,
        item: bytes,
        pending: _PendingState,
    ) -> bool:
        """Handle a packed-signature blob; return True if current_function was updated."""
        refs, args, hints = parse_nuitka_packed_signature(item)
        if refs:
            for ref in refs:
                match = METHOD_REF_RE.fullmatch(ref)
                if not match:
                    continue
                owner = match.group(1)
                if not is_probable_class_name(owner):
                    continue
                func = self.ensure_method(owner, match.group(2))
                self.current_function = None
                self.current_class    = owner
                self.current_function = func
                self._apply_pending(func, pending)
                pending.reset()
            return True
        if args:
            pending.args = args
            if hints:
                pending.annotations = hints
        return False

    def _dispatch_string(
        self,
        items: list[Any],
        index: int,
        text: str,
        pending: _PendingState,
    ) -> None:
        """Handle a string item in the main scan loop."""
        self.last_item_name = text

        if is_probable_endpoint(text):
            self.api_endpoints.add(text)

        if text in DECORATOR_NAMES:
            pending.decorators.append(text)
            return

        # Explicit ClassName.method reference
        method_ref = METHOD_REF_RE.fullmatch(text)
        if method_ref:
            owner = method_ref.group(1)
            if is_probable_class_name(owner):
                func = self.ensure_method(owner, method_ref.group(2))
                self.current_function = None
                self.current_class    = owner
                self.current_function = func
                self._apply_pending(func, pending)
                pending.reset()
            return

        # Known class name
        if text in self.class_candidates:
            cls_node = self.ensure_class(text)
            self.current_class    = text
            self.current_function = None
            if cls_node:
                self._hydrate_class_metadata(items, index, cls_node)
                if pending.docstring and not cls_node.docstring:
                    cls_node.docstring  = clean_docstring(pending.docstring)
                    pending.docstring   = None
            return

        # Import path
        if is_probable_import_path(text):
            names: list[str] | None = None
            if index + 1 < len(items) and isinstance(items[index + 1], tuple):
                names = [
                    n for n in tuple_texts(items[index + 1])
                    if isinstance(n, str) and safe_identifier(n)
                ]
            self.record_import(text, names)
            self.current_class    = None
            self.current_function = None
            return

        # Module-level constant (UPPER_CASE followed by a value)
        if should_render_constant(text) and index + 1 < len(items):
            nxt = items[index + 1]
            if isinstance(nxt, (str, bytes, bytearray, int, float, bool, tuple, list, dict)):
                self.module_constants[text] = literal_source(nxt)
            return

        # Private attribute in a class context
        if (
            self.current_class
            and text.startswith("_")
            and not text.startswith("__")
            and len(text) > 1
            and not self._looks_like_method_block(items, index, text)
        ):
            cls_node = self.classes.get(self.current_class)
            if cls_node:
                cls_node.attributes.add(text)

        # Method block inside the current class
        if self.current_class and self._looks_like_method_block(items, index, text):
            func = self.ensure_method(self.current_class, text)
            self.current_function = None
            self.current_function = func
            self._apply_pending(func, pending)
            pending.reset()
            return

        # Top-level function
        if not self.current_class and is_probable_method_name(text):
            if self._looks_like_toplevel_function(items, index, text, pending):
                func = self.ensure_function(text)
                self.current_function = None
                self.current_function = func
                self._apply_pending(func, pending)
                pending.reset()
                return

        # Docstring / error message
        if is_probable_docstring(text):
            if not self.module_docstring and self._should_capture_module_docstring(items, index, text):
                self.module_docstring = clean_docstring(text)
            elif self.current_function:
                self._record_target_hint(self.current_function, "message", text)
            else:
                pending.docstring = text
            return

        # Generic string hint for the current function
        if self.current_function and text not in DECORATOR_NAMES:
            self._record_target_hint(self.current_function, "string", text)

    # ------------------------------------------------------------------
    # Pass 1 — main entry point
    # ------------------------------------------------------------------

    def run_pass_1_structural_mapping(self, blob_items: list[Any]) -> None:
        items = list(blob_items)
        self.class_candidates = self._collect_class_candidates(items)
        pending = _PendingState()

        for index, item in enumerate(items):
            if item is None:
                continue

            # ---------- bytes / packed signature ----------
            if isinstance(item, (bytes, bytearray)):
                text = b2s_safe(item)
                if b"\x00" in item and len(item) > 4:
                    # VK virtual-key table entry
                    if text.startswith("VK_") and index + 1 < len(items) and isinstance(items[index + 1], int):
                        self.vk_table[text] = items[index + 1]
                        continue
                    self._dispatch_packed(item, pending)
                else:
                    # Base-64 image tag
                    if text.endswith("_B64") and index + 1 < len(items):
                        nxt = items[index + 1]
                        if isinstance(nxt, (bytes, bytearray, str)) and is_b64_image(nxt):
                            self.images[text] = len(b2s_safe(nxt))
                            continue
                    self._dispatch_string(items, index, text, pending)
                continue

            # ---------- dict ----------
            if isinstance(item, dict):
                if is_annotation_dict(item):
                    pending.annotations = decode_annotation_blob(item)
                elif self.current_function:
                    self._record_target_hint(self.current_function, "dict", item)
                else:
                    pending.dicts.append(item)
                continue

            # ---------- tuple ----------
            if isinstance(item, tuple):
                decoded = tuple_texts(item)
                if self.last_item_name == "__slots__" and self.current_class:
                    cls_node = self.classes.get(self.current_class)
                    if cls_node:
                        cls_node.slots = tuple(
                            x for x in decoded if isinstance(x, str) and safe_identifier(x)
                        )
                elif all(isinstance(x, str) and safe_identifier(x) for x in decoded) and 0 < len(decoded) <= 12:
                    pending.args = list(decoded)
                if self.current_function:
                    self._record_target_hint(self.current_function, "tuple", item)
                else:
                    pending.tuples.append(item)
                continue

            # ---------- numeric / bool literal ----------
            if isinstance(item, (int, float, bool)):
                if isinstance(item, int) and 0 < item < 10_000:
                    pending.line = item
                if self.current_function:
                    self._record_target_hint(self.current_function, "literal", item)
                else:
                    pending.literals.append(item)
                continue

            # ---------- plain string ----------
            if isinstance(item, str) and item:
                self._dispatch_string(items, index, item, pending)

    # ------------------------------------------------------------------
    # Pass 1 — signature finalization
    # ------------------------------------------------------------------

    def _finalize_function_signature(self, func: FunctionDefNode) -> None:
        if func.is_method:
            if not func.args:
                func.args = ["self"]
            elif func.args[0] not in {"self", "cls"}:
                func.args = ["self"] + [a for a in func.args if a not in {"self", "cls"}]

        if func.name == "__eq__" and func.is_method:
            if not func.args:
                func.args = ["self", "other"]
            elif "other" not in func.args:
                func.args = [func.args[0], "other"]
        elif func.name in {"register_hook", "deregister_hook"} and func.is_method and len(func.args) <= 1:
            func.args = [func.args[0] if func.args else "self", "event", "hook"]

        if "property" in func.decorators:
            func.args = ["self"]

    # ------------------------------------------------------------------
    # Pass 2 — attribute scraping
    # ------------------------------------------------------------------

    def _scrape_all_attributes(self) -> None:
        """Aggregate instance attributes referenced anywhere inside each class."""
        for cls_node in self.classes.values():
            found: set[str] = set()
            for func in cls_node.methods.values():
                for hint in func.string_hints:
                    if IDENTIFIER_RE.fullmatch(hint) and hint.startswith("_"):
                        found.add(hint)
                for tup in func.tuples:
                    for item in tup:
                        if isinstance(item, str) and IDENTIFIER_RE.fullmatch(item) and item.startswith("_"):
                            found.add(item)
                for msg in func.messages:
                    for word in re.findall(r"_([a-zA-Z0-9_]+)", msg):
                        ident = "_" + word
                        if IDENTIFIER_RE.fullmatch(ident):
                            found.add(ident)
            # C-API binding sentinel attributes
            all_hints = {h for f in cls_node.methods.values() for h in f.string_hints}
            if any(h == "_lib" or any(h.startswith(p) for p in _C_API_PREFIXES) for h in all_hints):
                found.add("_lib")
            if any(h == "_ffi" for h in all_hints):
                found.add("_ffi")
            if any(h in {"_ptr", "_handle"} for h in all_hints):
                found.add("_ptr")
            cls_node.attributes.update(found)

    def _candidate_attributes(self, cls_node: ClassDefNode | None, func: FunctionDefNode) -> list[str]:
        if cls_node is None:
            return []
        attrs = sorted(cls_node.attributes)
        for tup in func.tuples:
            for item in tup:
                if isinstance(item, str) and item.startswith("_") and item not in attrs:
                    attrs.append(item)
        return attrs

    # ------------------------------------------------------------------
    # Pass 2 — body-building helpers
    # ------------------------------------------------------------------

    def _has_meaningful_body(self, func: FunctionDefNode) -> bool:
        for line in func.body_lines:
            stripped = line.strip()
            if not stripped or stripped == "pass":
                continue
            if stripped.startswith("#") or stripped.startswith("config = ") or stripped.startswith("state = "):
                continue
            return True
        return False

    def _should_keep_function(self, func: FunctionDefNode) -> bool:
        if func.name in WEAK_TOPLEVEL_FUNCTION_NAMES:
            return False
        if func.annotations or func.decorators:
            return True
        return self._has_meaningful_body(func)

    def _imported_symbol_names(self) -> set[str]:
        names: set[str] = set()
        for bucket in self.from_imports.values():
            names.update(bucket.keys())
        return names

    def _should_keep_class(self, cls_node: ClassDefNode) -> bool:
        if cls_node.name in NOISE_CLASS_NAMES:
            return False
        if not cls_node.methods and not cls_node.attributes and not cls_node.docstring:
            return False
        imported = self._imported_symbol_names()
        meaningful = sum(
            1 for f in cls_node.methods.values()
            if f.annotations or f.decorators or self._has_meaningful_body(f)
        )
        if cls_node.name in imported and not cls_node.attributes and not cls_node.constants:
            if meaningful <= 1:
                return False
        if cls_node.name in {"Unknown", "None_"} and meaningful <= 1 and not cls_node.attributes:
            return False
        if is_fragmentary_docstring(cls_node.docstring) and meaningful == 0 and not cls_node.attributes:
            return False
        return True

    # ------------------------------------------------------------------
    # Pass 2 — message / hint analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _is_api_call_hint(text: str) -> bool:
        if not IDENTIFIER_RE.fullmatch(text) or "_" not in text or len(text) < 4:
            return False
        parts = text.split("_")
        return any(p[:1].isupper() for p in parts[:2])

    @staticmethod
    def _is_method_call_hint(text: str) -> bool:
        return bool(IDENTIFIER_RE.fullmatch(text)) and text[:1].islower() and "_" in text and len(text) > 3

    @staticmethod
    def _is_docstring_message(text: str) -> bool:
        return (
            len(text) > 30
            and ("\n" in text or ":param" in text or ":return" in text or ":type" in text)
        )

    @staticmethod
    def _is_error_message(text: str) -> bool:
        lower = text.strip().lower()
        return (
            len(text) < 100
            and "\n" not in text
            and any(kw in lower for kw in (
                "must be", "invalid", "unsupported", "error", "failed",
                "cannot", "expected", "should be", "not a valid", "is not", "deprecated",
            ))
        )

    def _promote_messages_to_docstrings(self, func: FunctionDefNode) -> None:
        if func.docstring:
            return
        remaining: list[str] = []
        for msg in func.messages:
            if not func.docstring and self._is_docstring_message(msg):
                func.docstring = clean_docstring(msg)
            else:
                remaining.append(msg)
        func.messages = remaining

    def _validation_lines(self, func: FunctionDefNode) -> list[str]:
        lines: list[str] = []
        non_self = [a for a in func.args if a not in {"self", "cls"}]
        primary = non_self[0] if non_self else "value"
        for message in func.messages[:6]:
            lower = message.lower()
            if "must be string" in lower or "must be a byte string" in lower:
                lines += [
                    f"if not isinstance({primary}, (str, bytes)):",
                    f"    raise TypeError({message!r})",
                ]
            elif "must be a name" in lower:
                lines += [
                    f"if not isinstance({primary}, Name):",
                    f"    raise TypeError({message!r})",
                ]
            elif "must be an objectidentifier" in lower:
                lines += [
                    f"if not isinstance({primary}, ObjectIdentifier):",
                    f"    raise TypeError({message!r})",
                ]
            elif "must be an integer" in lower or "must be int" in lower:
                lines += [
                    f"if not isinstance({primary}, int):",
                    f"    raise TypeError({message!r})",
                ]
            elif "must be a float" in lower:
                lines += [
                    f"if not isinstance({primary}, (int, float)):",
                    f"    raise TypeError({message!r})",
                ]
            elif "must be a list" in lower or "must be a sequence" in lower:
                lines += [
                    f"if not isinstance({primary}, (list, tuple)):",
                    f"    raise TypeError({message!r})",
                ]
            elif "must be an instance of" in lower:
                lines.append(f"# Validation: {message}")
            elif "unsupported" in lower or lower.startswith("invalid "):
                lines.append(f"raise ValueError({message!r})")
                break
            elif "deprecated" in lower:
                lines.append(f"warnings.warn({message!r}, DeprecationWarning, stacklevel=2)")
        return lines

    # ------------------------------------------------------------------
    # Pass 2 — specialised body builders
    # ------------------------------------------------------------------

    def _build_prepare_body(self, cls_node: ClassDefNode | None, func: FunctionDefNode) -> list[str]:
        if cls_node is None:
            return []
        lines: list[str] = []
        helpers = [n for n in cls_node.methods if n.startswith("prepare_")]
        if func.name == "prepare" and helpers:
            arg_set = set(func.args)
            for helper in helpers:
                suffix = helper[len("prepare_"):]
                call_args: list[str] = []
                if suffix in arg_set:
                    call_args.append(suffix)
                elif suffix == "body":
                    call_args = [c for c in ("data", "files", "json", "params") if c in arg_set]
                elif suffix == "auth" and "auth" in arg_set:
                    call_args.append("auth")
                elif suffix == "hooks" and "hooks" in arg_set:
                    call_args.append("hooks")
                lines.append(f"self.{helper}({', '.join(call_args)})")
            return lines

        if func.name.startswith("prepare_"):
            suffix = func.name[len("prepare_"):]
            non_self = [a for a in func.args if a not in {"self", "cls"}]
            if suffix in non_self:
                lines.append(f"self.{suffix} = {suffix}")
            elif suffix == "headers" and "headers" in non_self:
                lines.append("self.headers = headers or {}")
            elif suffix == "url" and "url" in non_self:
                lines.append("self.url = url")
            elif suffix == "method" and "method" in non_self:
                lines.append("self.method = method.upper()")
            elif suffix == "cookies" and "cookies" in non_self:
                lines.append("self._cookies = cookies")
            elif suffix == "body":
                if "data" in non_self:
                    lines.append("self.body = data")
                if "json" in non_self:
                    lines.append("self.json = json")
            elif suffix == "hooks" and "hooks" in non_self:
                lines.append("self.hooks = hooks")
        return lines

    def _build_api_call_body(
        self,
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
    ) -> list[str]:
        """Generate a body from string_hints that look like C-API or method calls."""
        non_self    = [a for a in func.args if a not in {"self", "cls"}]
        lines: list[str] = []

        api_calls:    list[str] = []
        method_calls: list[str] = []
        field_refs:   list[str] = []
        for hint in func.string_hints:
            if self._is_api_call_hint(hint):
                api_calls.append(hint)
            elif self._is_method_call_hint(hint):
                method_calls.append(hint)
            elif IDENTIFIER_RE.fullmatch(hint) and hint.startswith("_"):
                field_refs.append(hint)

        # --- error / deprecation lines from messages ---
        error_msgs = [m for m in func.messages if self._is_error_message(m)]
        for msg in error_msgs[:2]:
            lower = msg.lower()
            if "must be" in lower:
                if non_self:
                    lines += [f"if not {non_self[0]}:", f"    raise TypeError({msg!r})"]
                else:
                    lines.append(f"# Validation: {msg}")
            elif "deprecated" in lower:
                lines.append(f"warnings.warn({msg!r}, DeprecationWarning, stacklevel=2)")

        # --- sequential C-API calls ---
        if api_calls:
            has_lib = any(h.startswith(_C_API_PREFIXES) for h in api_calls)
            for i, call in enumerate(api_calls[:8]):
                call_args_str = ", ".join(non_self[:3])
                is_last = i == len(api_calls[:8]) - 1
                prefix  = "return " if (is_last and (func.name.startswith("get_") or "property" in func.decorators)) else ""
                if has_lib:
                    lines.append(f"{prefix}self._lib.{call}({call_args_str})" if func.is_method else f"{prefix}lib.{call}({call_args_str})")
                else:
                    lines.append(f"{prefix}{call}({call_args_str})")

        # --- sibling method calls ---
        if method_calls:
            methods_in_class = cls_node.methods if cls_node else {}
            for call in method_calls[:6]:
                if func.is_method:
                    if call in methods_in_class:
                        lines.append(f"self.{call}()")
                    else:
                        lines.append(f"self.{call}({', '.join(non_self[:2])})")
                else:
                    lines.append(f"{call}({', '.join(non_self[:2])})")

        # --- field references as last resort ---
        if field_refs and not lines:
            if not non_self:
                lines.append(f"return self.{field_refs[0]}" if func.is_method else f"return {field_refs[0]}")
            else:
                for ref in field_refs[:3]:
                    lines.append(f"self.{ref} = {non_self[0]}" if func.is_method else f"{ref} = {non_self[0]}")

        return lines

    # ------------------------------------------------------------------
    # Pass 2 — special-method dispatch table
    # ------------------------------------------------------------------

    def _body_special(
        self,
        cls_node: ClassDefNode,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str] | None:
        """
        Return body lines for well-known dunder/special methods, or *None*
        if the method name is not recognised as special.
        """
        name = func.name

        if name == "__repr__":
            if attrs:
                pieces = ", ".join(f"{a.lstrip('_')}={{self.{a}!r}}" for a in attrs[:4])
                return [f'return f"<{cls_node.name}({pieces})>"']
            return [f'return f"<{cls_node.name}>"']

        if name == "__str__":
            return [f"return str(self.{attrs[0]})"] if attrs else [f'return f"<{cls_node.name}>"']

        if name == "__bytes__":
            return [f"return bytes(self.{attrs[0]})"] if attrs else None

        if name == "__len__":
            for attr in attrs:
                if any(kw in attr for kw in ("list", "items", "data", "buffer", "entries")):
                    return [f"return len(self.{attr})"]
            return [f"return len(self.{attrs[0]})"] if attrs else None

        if name == "__bool__":
            return [f"return bool(self.{attrs[0]})"] if attrs else ["return True"]

        if name == "__iter__":
            return [f"return iter(self.{attrs[0]})"] if attrs else ["return iter(())"]

        if name == "__contains__":
            if attrs and non_self:
                return [f"return {non_self[0]} in self.{attrs[0]}"]

        if name in {"__eq__"}:
            if not attrs:
                return None
            left  = ", ".join(f"self.{a}"  for a in attrs[:4])
            right = ", ".join(f"other.{a}" for a in attrs[:4])
            guard = [f"if not isinstance(other, {cls_node.name}):", "    return NotImplemented"]
            if len(attrs[:4]) == 1:
                return guard + [f"return ({left},) == ({right},)"]
            return guard + [f"return ({left}) == ({right})"]

        if name == "__hash__":
            if not attrs:
                return None
            members = ", ".join(f"self.{a}" for a in attrs[:4])
            suffix  = "," if len(attrs[:4]) == 1 else ""
            return [f"return hash(({members}{suffix}))"]

        if name == "__reduce__":
            if not attrs:
                return None
            members = ", ".join(f"self.{a}" for a in attrs[:4])
            suffix  = "," if len(attrs[:4]) == 1 else ""
            return [f"return (self.__class__, ({members}{suffix}))"]

        if name in {"copy", "clone", "__copy__"}:
            return [f"return {cls_node.name}(**self.__dict__)"]

        if name == "register_hook":
            return ["self.hooks.setdefault(event, []).append(hook)", "return hook"]

        if name == "deregister_hook":
            return [
                "hooks = self.hooks.get(event, [])",
                "if hook in hooks:",
                "    hooks.remove(hook)",
                "    return True",
                "return False",
            ]

        if name in {"close", "shutdown", "cleanup", "dispose", "destroy", "__del__"}:
            lines = [f"self.{a} = None" for a in attrs[:4]]
            return lines if lines else ["pass"]

        return None  # not a recognised special method

    # ------------------------------------------------------------------
    # Pass 2 — main body builder
    # ------------------------------------------------------------------

    def _build_body(self, cls_node: ClassDefNode | None, func: FunctionDefNode) -> list[str]:
        attrs    = self._candidate_attributes(cls_node, func)
        non_self = [a for a in func.args if a not in {"self", "cls"}]

        # Abstract methods need no body
        if "abstractmethod" in func.decorators:
            return ["raise NotImplementedError"]

        # Promote rich messages to docstrings before we use them
        self._promote_messages_to_docstrings(func)

        # ---- __init__ / _init_without_validation ----
        if func.name in {"__init__", "_init_without_validation"}:
            lines: list[str] = []
            lines.extend(self._validation_lines(func))   # validate FIRST
            used: set[str] = set()
            for arg in non_self:
                preferred: str | None = None
                if f"_{arg}" in attrs:
                    preferred = f"_{arg}"
                elif arg in attrs:
                    preferred = arg
                elif len(non_self) == 1 and "_value" in attrs:
                    preferred = "_value"
                else:
                    for candidate in attrs:
                        if candidate not in used and candidate.lstrip("_") == arg:
                            preferred = candidate
                            break
                if preferred:
                    used.add(preferred)
                    lines.append(f"self.{preferred} = {arg}")
            return lines

        # ---- property accessors ----
        if func.name == "value" and "property" in func.decorators:
            return ["return self._value"] if "_value" in attrs else (
                [f"return self.{attrs[0]}"] if attrs else ["return None"]
            )
        if func.name == "type_id" and "property" in func.decorators and "_type_id" in attrs:
            return ["return self._type_id"]

        # ---- named property pattern: getXxx → return self._xxx ----
        if func.name.startswith("get") and len(func.name) > 3 and not non_self:
            candidate = func.name[3:4].lower() + func.name[4:]
            for attr in attrs:
                if attr.lstrip("_") == candidate:
                    return [f"return self.{attr}"]

        if func.name == "_packed" and "_value" in attrs:
            return ["return self._value.packed"]

        # ---- special dunder / well-known methods ----
        if cls_node is not None:
            special = self._body_special(cls_node, func, attrs, non_self)
            if special is not None:
                return special

        # ---- prepare / prepare_xxx ----
        prepare_lines = self._build_prepare_body(cls_node, func)
        if prepare_lines:
            return prepare_lines

        validation = self._validation_lines(func)

        # ---- rich hint-driven body (API/method calls from string_hints) ----
        if func.string_hints or func.messages:
            api_body = self._build_api_call_body(cls_node, func)
            if api_body:
                return validation + api_body

        if validation:
            return validation

        # ---- dict hints → config pattern ----
        lines = []
        if func.dict_hints:
            lines.append(f"config = {literal_source(func.dict_hints[0])}")

        # ---- tuple hints → state / assignment pattern ----
        if func.tuples:
            for tup in func.tuples[:3]:
                texts = [t for t in tup if isinstance(t, str)]
                if not texts:
                    continue
                if all(IDENTIFIER_RE.fullmatch(t) for t in texts):
                    if func.is_method and func.name.startswith(("_set", "set_", "_update", "update_")):
                        for t in texts[:4]:
                            if non_self:
                                lines.append(f"self.{t} = {non_self[0]}.get({t!r}, None)")
                            else:
                                lines.append(f"# field: {t}")
                    elif not lines:
                        lines.append(f"state = {literal_source(tup)}")

        # ---- string hints → comments / call stubs ----
        for text in func.string_hints[:8]:
            if is_probable_docstring(text) or self._is_api_call_hint(text):
                continue
            if is_probable_endpoint(text):
                lines.append(f"# External reference: {text}")
            elif self._is_method_call_hint(text) and func.is_method and cls_node:
                if text in cls_node.methods:
                    lines.append(f"self.{text}()")
                elif not lines:
                    lines.append(f"self.{text}({', '.join(non_self[:2])})")
            elif len(text) > 20 and " " in text:
                lines.append(f"# {text}")

        # ---- literal hints → set_ constants ----
        if func.literals and not lines:
            int_lits = [v for v in func.literals if isinstance(v, int) and v > 0]
            if int_lits and func.name.startswith(("set_", "_set_")):
                suffix = func.name.split("set_", 1)[-1]
                lines.append(f"self._{suffix} = {int_lits[0]}")

        if lines:
            return lines

        # ---- structural inference as last resort ----
        return self._structural_fallback(cls_node, func, attrs, non_self)

    def _structural_fallback(
        self,
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        """Pure name/arg/attr pattern matching — last resort body generation."""
        lines: list[str] = []

        if "property" in func.decorators:
            if attrs:
                name_match = func.name.lstrip("_")
                for attr in attrs:
                    if attr.lstrip("_") == name_match:
                        return [f"return self.{attr}"]
                return [f"return self.{attrs[0]}"]
            return ["return None"]

        if len(non_self) == 1 and func.name.startswith(("set_", "_set_")):
            suffix = func.name.split("set_", 1)[-1]
            return ([f"self._{suffix} = {non_self[0]}"] if func.is_method else [f"{suffix} = {non_self[0]}"])

        if non_self and func.name.startswith(("add_", "_add_", "append_")):
            suffix = func.name.split("_", 1)[-1]
            if func.is_method:
                lines.append(f"self._{suffix}s.append({non_self[0]})")

        elif non_self and func.name.startswith(("remove_", "_remove_", "delete_")):
            suffix = func.name.split("_", 1)[-1]
            if func.is_method:
                lines.append(f"self._{suffix}s.remove({non_self[0]})")

        elif func.name.startswith(("clear_", "_clear_", "reset_")):
            suffix = func.name.split("_", 1)[-1]
            if func.is_method:
                lines.append(f"self._{suffix} = None")

        elif func.name.startswith(("is_", "has_", "can_")):
            suffix = func.name.split("_", 1)[-1]
            for attr in attrs:
                if suffix in attr:
                    return [f"return bool(self.{attr})"]
            lines.append("return False")

        elif func.name.startswith("get") and not non_self:
            return [f"return self.{attrs[0]}"] if attrs else ["return None"]

        elif func.is_method and non_self:
            matched = False
            for arg in non_self[:4]:
                for attr in attrs:
                    if attr.lstrip("_") == arg:
                        lines.append(f"self.{attr} = {arg}")
                        matched = True
                        break
            if not matched:
                for arg in non_self[:3]:
                    lines.append(f"self._{arg} = {arg}")

        else:
            return [f"return self.{attrs[0]}"] if attrs else ["pass"]

        return lines or ["pass"]

    # ------------------------------------------------------------------
    # Pass 2 — main entry point
    # ------------------------------------------------------------------

    def run_pass_2_ast_synthesis(self) -> None:
        self._scrape_all_attributes()

        # --- classes ---
        kept_classes: OrderedDict[str, ClassDefNode] = OrderedDict()
        for cls_name, cls_node in self.classes.items():
            if cls_name.endswith("Warning") and not cls_node.bases:
                cls_node.bases = ["Warning"]
            elif cls_name.endswith("Error") and not cls_node.bases:
                cls_node.bases = ["Exception"]
            for func in cls_node.methods.values():
                self._finalize_function_signature(func)
                func.body_lines = self._build_body(cls_node, func)
            if self._should_keep_class(cls_node):
                kept_classes[cls_name] = cls_node
        self.classes = kept_classes

        # --- top-level functions ---
        kept_functions: OrderedDict[str, FunctionDefNode] = OrderedDict()
        for name, func in self.functions.items():
            self._finalize_function_signature(func)
            func.body_lines = self._build_body(None, func)
            if self._should_keep_function(func):
                kept_functions[name] = func
        self.functions = kept_functions


# ---------------------------------------------------------------------------
# Source generator
# ---------------------------------------------------------------------------

def _iter_import_lines(decompiler: OmniDecompiler) -> Iterator[str]:
    """Yield sorted import statements, stdlib before third-party (best-effort)."""
    import sys as _sys
    stdlib_modules = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()

    from_lines:   list[str] = []
    plain_lines:  list[str] = []

    for module_path, names in decompiler.from_imports.items():
        if names:
            from_lines.append(f"from {module_path} import {', '.join(names)}")
    for module_path in decompiler.imports:
        if module_path not in decompiler.from_imports:
            plain_lines.append(f"import {module_path}")

    all_lines = sorted(set(from_lines + plain_lines))
    top_mod   = lambda s: s.split()[1].split(".")[0]
    stdlib    = [l for l in all_lines if top_mod(l) in stdlib_modules]
    third     = [l for l in all_lines if top_mod(l) not in stdlib_modules]

    yield from stdlib
    if stdlib and third:
        yield ""
    yield from third


def generate_omni_source(decompiler: OmniDecompiler, section_name: str) -> str:
    lines: list[str] = []

    # Module docstring
    if decompiler.module_docstring:
        doc = clean_docstring(decompiler.module_docstring) or ""
        doc_lines = doc.splitlines()
        if len(doc_lines) <= 1:
            lines.append(f'"""{doc}"""')
        else:
            lines += ['"""', *doc_lines, '"""']

    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append(f"# Heuristic CPython reconstruction for: {section_name}")

    # Collect typing names used in annotations
    all_funcs: list[FunctionDefNode] = list(decompiler.functions.values())
    for cls_node in decompiler.classes.values():
        all_funcs.extend(cls_node.methods.values())
    used_typing: OrderedDict[str, None] = OrderedDict()
    for func in all_funcs:
        all_annotations = list(func.annotations.values()) + ([func.return_type] if func.return_type else [])
        for ann in all_annotations:
            if not ann:
                continue
            for token in re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", ann):
                if token in TYPING_NAMES:
                    used_typing[token] = None
    if used_typing:
        lines.append(f"from typing import {', '.join(used_typing)}")

    # Imports
    import_lines = list(_iter_import_lines(decompiler))
    if import_lines:
        lines.append("")
        lines.extend(import_lines)

    # API endpoint comments
    if decompiler.api_endpoints:
        lines.append("")
        for url in sorted(decompiler.api_endpoints):
            lines.append(f"# endpoint: {url}")

    # Virtual-key table
    if decompiler.vk_table:
        lines.append("")
        for name, value in decompiler.vk_table.items():
            lines.append(f"{name} = {value!r}")

    # Module-level constants
    if decompiler.module_constants:
        lines.append("")
        for name, value in decompiler.module_constants.items():
            if should_render_constant(name):
                lines.append(f"{name} = {value}")

    # Top-level functions
    if decompiler.functions:
        lines.append("")
        for func in decompiler.functions.values():
            lines.extend(func.render(0).rstrip().splitlines())
            lines.append("")

    # Classes
    for cls_node in decompiler.classes.values():
        if not cls_node.methods and not cls_node.attributes and not cls_node.docstring:
            continue
        lines.append("")
        lines.extend(cls_node.render(0).rstrip().splitlines())
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        import nuitka_deobfuscate  # type: ignore[import-untyped]
    except ImportError:
        print("[-] Nuitka deobfuscate extension missing.")
        return 1

    blob_path = Path("rcdata_10_3.bin")
    if not blob_path.exists():
        print(f"[-] Blob not found: {blob_path}")
        return 1

    raw      = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(raw)
    out_dir  = Path("restore_deep_ultra") / "reconstructed_source_v12_omni"
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for section_name, items in sections.items():
        if not items:
            continue
        decompiler = OmniDecompiler()
        decompiler.run_pass_1_structural_mapping(items)
        decompiler.run_pass_2_ast_synthesis()
        source = generate_omni_source(decompiler, section_name)
        if "class " not in source and "def " not in source:
            continue
        safe_name = re.sub(r'[<>:"/\\|?*\x00]', "_", section_name).strip("._") or "section"
        out_file  = out_dir / f"{safe_name}.py"
        out_file.write_text(source, encoding="utf-8")
        count += 1

    print(f"[*] Reconstructed {count} file(s) → {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
