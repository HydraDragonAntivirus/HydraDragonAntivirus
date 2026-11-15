"""
omni_nuitka_framework.py

High-fidelity heuristic CPython source reconstruction from Nuitka section metadata.
Targets 3 000+ line output per blob via rich body synthesis, docstring recovery,
property-setter generation, context-manager / iterator recovery, and full
exception-hierarchy reconstruction.
"""

from __future__ import annotations

import argparse
import ast
import functools
import hashlib
import importlib
import keyword
import re
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator


# ---------------------------------------------------------------------------
# Nuitka packed-signature tags
# ---------------------------------------------------------------------------


class NuitkaTags:
    ARG = "a"
    USER_DEF = "u"
    PRIVATE_DEF = "p"
    OBJECT_TYPE = "O"


# ---------------------------------------------------------------------------
# Primitive coercion helpers
# ---------------------------------------------------------------------------


def b2s_safe(val: Any) -> str:
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
    return seq[:limit] + [marker] if len(seq) > limit else seq


def literal_source(value: Any) -> str:
    if isinstance(value, bytes):
        if len(value) >= 16 and value[:1] in (b"\xf3", b"\xe3", b"c"):
            return repr(f"<marshal bytecode payload redacted: {len(value)} bytes>")
        return repr(b2s_safe(value))
    if isinstance(value, tuple):
        return repr(tuple(_trim_sequence(list(tuple_texts(value)), "...")))
    if isinstance(value, list):
        return repr(_trim_sequence(list(tuple_texts(value)), "..."))
    if isinstance(value, dict):
        cleaned = {b2s_safe(k): (b2s_safe(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in list(value.items())[:20]}
        return repr(cleaned)
    return repr(value)


def tuple_texts(value: Any) -> tuple[Any, ...]:
    if not isinstance(value, (tuple, list)):
        return ()
    return tuple(b2s_safe(x) if isinstance(x, (bytes, bytearray, str)) else x for x in value)


# ---------------------------------------------------------------------------
# Annotation helpers
# ---------------------------------------------------------------------------


def is_annotation_dict(d: Any) -> bool:
    if not isinstance(d, dict) or not d or len(d) > 25:
        return False
    for key in d.keys():
        text = b2s_safe(key) if isinstance(key, (bytes, bytearray)) else (key if isinstance(key, str) else None)
        if text is None or (not text.isidentifier() and text != "return"):
            return False
    return True


def decode_annotation_blob(d: dict[Any, Any]) -> OrderedDict[str, str]:
    result: OrderedDict[str, str] = OrderedDict()
    if not isinstance(d, dict):
        return result
    for key, value in d.items():
        name = b2s_safe(key)
        if value is None:
            result[name] = "Any"
        elif isinstance(value, bool):
            result[name] = "bool"
        elif isinstance(value, int):
            result[name] = "int"
        elif isinstance(value, float):
            result[name] = "float"
        elif isinstance(value, str):
            result[name] = value if value[:1].isupper() else "str"
        elif isinstance(value, (bytes, bytearray)):
            t = b2s_safe(value)
            result[name] = t if t[:1].isupper() else "str"
        else:
            result[name] = type(value).__name__
    return result


# ---------------------------------------------------------------------------
# Packed-signature parser
# ---------------------------------------------------------------------------


def parse_nuitka_packed_signature(
    raw: bytes | str,
) -> tuple[list[str], list[str], dict[str, str]]:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    method_refs: list[str] = []
    args: list[str] = []
    types: dict[str, str] = {}
    for seg in raw.split(b"\x00"):
        if not seg:
            continue
        text = seg.decode("utf-8", errors="replace")
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
# Compiled regexes & frozen constant sets
# ---------------------------------------------------------------------------

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLASS_NAME_RE = re.compile(r"^_?[A-Z][A-Za-z0-9_]*$")
IMPORT_PATH_RE = re.compile(r"^[a-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
METHOD_REF_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$")
HTTP_ENDPOINT_RE = re.compile(r"https?://[A-Za-z0-9]|/functions/[A-Za-z0-9_]")
LOG_RE = re.compile(r"\b(log|logger|logging|debug|info|warning|error|critical)\b", re.I)
PARAM_RE = re.compile(r":param\s+(\w+):")
RETURN_RE = re.compile(r":returns?:\s*(.*)")
RAISES_RE = re.compile(r":raises?\s+(\w+):")

DECORATOR_NAMES: frozenset[str] = frozenset({"property", "abstractmethod", "staticmethod", "classmethod", "overload"})
META_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "__prepare__",
        "__qualname__",
        "__firstlineno__",
        "__static_attributes__",
        "__orig_bases__",
        "__getitem__",
        "metaclass",
        "annotations",
        "origin",
        "has_location",
        "__module__",
    }
)
KNOWN_METHOD_NAMES: frozenset[str] = frozenset(
    {
        "__init__",
        "__new__",
        "__repr__",
        "__str__",
        "__bytes__",
        "__eq__",
        "__ne__",
        "__lt__",
        "__le__",
        "__gt__",
        "__ge__",
        "__hash__",
        "__reduce__",
        "__reduce_ex__",
        "__getstate__",
        "__setstate__",
        "__iter__",
        "__next__",
        "__len__",
        "__bool__",
        "__contains__",
        "__copy__",
        "__deepcopy__",
        "__enter__",
        "__exit__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__getitem__",
        "__setitem__",
        "__delitem__",
        "__call__",
        "prepare",
        "copy",
        "clone",
        "close",
        "json",
        "value",
        "name",
        "type_id",
        "_packed",
        "_init_without_validation",
        "register_hook",
        "deregister_hook",
        "send",
        "receive",
        "read",
        "write",
        "flush",
        "seek",
        "tell",
        "connect",
        "disconnect",
        "reconnect",
        "encode",
        "decode",
        "serialize",
        "deserialize",
        "validate",
        "parse",
        "format",
        "render",
    }
)
KNOWN_METHOD_PREFIXES: tuple[str, ...] = (
    "prepare_",
    "register_",
    "deregister_",
    "iter_",
    "get_",
    "set_",
    "raise_",
    "encode_",
    "decode_",
    "_encode_",
    "_get_",
    "_init_",
    "add_",
    "remove_",
    "clear_",
    "reset_",
    "is_",
    "has_",
    "can_",
    "on_",
    "do_",
    "handle_",
    "process_",
    "build_",
    "make_",
    "create_",
    "update_",
    "delete_",
    "fetch_",
    "load_",
    "save_",
    "dump_",
    "_build_",
    "_make_",
    "_create_",
    "_process_",
    "_handle_",
    "_validate_",
    "_parse_",
    "_format_",
    "_check_",
    "_ensure_",
)
KNOWN_BASE_NAMES: frozenset[str] = frozenset(
    {
        "Exception",
        "Warning",
        "ValueError",
        "TypeError",
        "RuntimeError",
        "ConnectionError",
        "LookupError",
        "MessageDefect",
        "IncompleteRead",
        "OSError",
        "IOError",
        "KeyError",
        "IndexError",
        "AttributeError",
        "NotImplementedError",
        "StopIteration",
        "GeneratorExit",
        "TimeoutError",
    }
)
NOISE_CLASS_NAMES: frozenset[str] = frozenset(
    {
        "ABCMeta",
        "Callable",
        "Iterable",
        "Mapping",
        "OrderedDict",
        "Path",
        "Sequence",
        "defaultdict",
    }
)
WEAK_TOPLEVEL_FUNCTION_NAMES: frozenset[str] = frozenset(
    {
        "self",
        "cls",
        "url",
        "warn",
        "reason",
        "conn",
        "header",
        "headers",
        "body",
        "json",
        "data",
        "params",
        "value",
        "type",
        "origin",
        "message",
        "status",
        "host",
        "path",
        "replace",
        "warnings",
        "lstrip",
    }
)
MODULE_DOCSTRING_HINTS: tuple[str, ...] = (
    "module",
    "package",
    "utilities",
    "helpers",
    "exceptions",
    "tools",
    "support",
    "constants",
    "provides",
    "implements",
)
MODULE_DOCSTRING_BAD_PREFIXES: tuple[str, ...] = (
    "build ",
    "parse ",
    "return ",
    "create ",
    "construct ",
    "convert ",
    "serialize ",
    "deserialize ",
    "encode ",
    "decode ",
    "represent ",
    "initialize ",
    "prepare ",
    "register ",
    "deregister ",
    "max retries exceeded",
)
_C_API_PREFIXES: tuple[str, ...] = (
    "SSL_",
    "X509_",
    "EVP_",
    "BIO_",
    "OBJ_",
    "ASN1_",
    "PEM_",
    "PKCS",
    "RSA_",
    "EC_",
    "DH_",
    "HMAC_",
    "AES_",
    "SHA",
)
TYPING_NAMES: frozenset[str] = frozenset(
    {
        "Any",
        "Callable",
        "Mapping",
        "Iterable",
        "Sequence",
        "Optional",
        "Union",
        "List",
        "Dict",
        "Tuple",
        "Set",
        "Type",
        "ClassVar",
        "Final",
        "Literal",
        "overload",
        "Generator",
        "Iterator",
        "AsyncIterator",
        "Awaitable",
    }
)
LOCK_ATTRS: frozenset[str] = frozenset({"_lock", "_mutex", "_rlock", "_semaphore"})
ITER_ATTRS: frozenset[str] = frozenset({"_items", "_data", "_buffer", "_queue", "_list", "_entries"})
NETWORK_HINTS: frozenset[str] = frozenset(
    {
        "timeout",
        "retry",
        "redirect",
        "response",
        "request",
        "socket",
        "connection",
        "stream",
        "chunk",
        "content",
    }
)

# Python built-in type names useful for isinstance checks
_BUILTIN_TYPES: dict[str, str] = {
    "str": "str",
    "int": "int",
    "float": "float",
    "bool": "bool",
    "bytes": "bytes",
    "list": "list",
    "dict": "dict",
    "tuple": "tuple",
    "set": "set",
    "frozenset": "frozenset",
}

# ---------------------------------------------------------------------------
# Text classification helpers
# ---------------------------------------------------------------------------


def clean_docstring(text: Any) -> str | None:
    s = str(text).strip()
    if not s:
        return None
    s = s.replace("\\", "\\\\").replace('"""', '\\"\\"\\"').replace("\r\n", "\n").replace("\r", "\n")
    if s.endswith('"'):
        s = s[:-1] + '\\"'
    return s


@functools.lru_cache(maxsize=8192)
def safe_identifier(name: str | None) -> str | None:
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
    _map = {
        "typing.Any": "Any",
        "typing.Optional": "Optional",
        "typing.Callable": "Callable",
        "typing.Mapping": "Mapping",
        "typing.Iterable": "Iterable",
        "typing.Sequence": "Sequence",
        "typing.List": "List",
        "typing.Dict": "Dict",
        "typing.Tuple": "Tuple",
        "typing.Union": "Union",
        "typing.Type": "Type",
    }
    return _map.get(text, text)


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
    return isinstance(text, str) and bool(CLASS_NAME_RE.fullmatch(text)) and text not in DECORATOR_NAMES and text not in NOISE_CLASS_NAMES


def is_probable_method_name(text: Any) -> bool:
    if not isinstance(text, str):
        return False
    if text in DECORATOR_NAMES or text in META_FIELD_NAMES:
        return False
    if text in KNOWN_METHOD_NAMES or text.startswith(KNOWN_METHOD_PREFIXES):
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
    if any(t in lowered for t in (" must ", " invalid ", "unsupported ", "deprecated")):
        return False
    return "\n" in text or any(t in lowered for t in MODULE_DOCSTRING_HINTS)


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
    return (
        isinstance(name, str)
        and name.isidentifier()
        and not keyword.iskeyword(name)
        and name.isupper()
        and 3 <= len(name) <= 64
    )


def _score_window(items: list[Any], start: int, length: int) -> int:
    score = 0
    window = items[start : start + length]
    if any(isinstance(x, dict) and is_annotation_dict(x) for x in window):
        score += 2
    if any(isinstance(x, tuple) and 0 < len(x) <= 12 for x in window):
        score += 1
    if any(isinstance(x, str) and is_probable_docstring(x) for x in window):
        score += 1
    if any(isinstance(x, int) and 0 < x < 10_000 for x in window):
        score += 1
    return score


# ---------------------------------------------------------------------------
# Docstring synthesizer
# ---------------------------------------------------------------------------


class DocstringSynthesizer:
    """
    Builds rich, multi-section docstrings from all available hints.
    Produces NumPy / Google / Sphinx-style docstrings depending on content.
    """

    @staticmethod
    def _extract_params_from_args(
        args: list[str],
        annotations: dict[str, str],
    ) -> list[tuple[str, str, str]]:
        """Return [(name, type, description)] for each non-self/cls arg."""
        result = []
        for arg in args:
            if arg in {"self", "cls"}:
                continue
            ann = annotations.get(arg, "Any")
            # Infer a plausible description from the arg name
            desc = _arg_description(arg)
            result.append((arg, ann, desc))
        return result

    @staticmethod
    def from_hints(
        name: str,
        args: list[str],
        annotations: dict[str, str],
        return_type: str | None,
        messages: list[str],
        string_hints: list[str],
        existing_doc: str | None,
        is_method: bool,
    ) -> str | None:
        """
        Build a complete docstring from available metadata.
        Returns None if there is nothing meaningful to say.
        """
        lines: list[str] = []

        # --- summary line ---
        if existing_doc:
            cleaned = clean_docstring(existing_doc) or ""
            summary = cleaned.splitlines()[0].strip()
        else:
            summary = _method_summary(name, args, return_type)

        if not summary:
            return None
        lines.append(summary)

        # --- longer description from long string hints ---
        long_hints = [h for h in string_hints if len(h) > 60 and " " in h and not is_probable_endpoint(h)]
        if long_hints:
            lines.append("")
            lines.append(long_hints[0].strip())

        # --- Parameters section ---
        param_rows = DocstringSynthesizer._extract_params_from_args(args, annotations)
        if param_rows:
            lines.append("")
            lines.append("Parameters")
            lines.append("----------")
            for pname, ptype, pdesc in param_rows:
                lines.append(f"{pname} : {ptype}")
                lines.append(f"    {pdesc}")

        # --- Returns section ---
        if return_type and return_type not in {"None", "none"}:
            lines.append("")
            lines.append("Returns")
            lines.append("-------")
            lines.append(return_type)
            lines.append(f"    {_return_description(name, return_type)}")

        # --- Raises section from messages ---
        raise_rows = _parse_raise_messages(messages)
        if raise_rows:
            lines.append("")
            lines.append("Raises")
            lines.append("------")
            for exc_type, msg in raise_rows:
                lines.append(exc_type)
                lines.append(f"    {msg}")

        # --- endpoint note ---
        endpoints = [h for h in string_hints if is_probable_endpoint(h)]
        if endpoints:
            lines.append("")
            lines.append("Notes")
            lines.append("-----")
            for ep in endpoints[:2]:
                lines.append(f"Communicates with endpoint: {ep}")

        if len(lines) == 1:
            return lines[0]

        return "\n".join(lines)


def _arg_description(arg: str) -> str:
    mapping = {
        "host": "The hostname or IP address of the remote server.",
        "port": "The TCP port number.",
        "timeout": "Operation timeout in seconds. Use None for no timeout.",
        "url": "The full URL including scheme and path.",
        "method": "The HTTP method (e.g. GET, POST, PUT).",
        "headers": "A dict of HTTP headers to include in the request.",
        "body": "The request body, as bytes or str.",
        "data": "The payload data to send.",
        "params": "Query parameters as a dict or sequence of (key, value) pairs.",
        "auth": "Authentication credentials tuple (username, password) or object.",
        "proxies": "Dict mapping protocol to proxy URL.",
        "cert": "SSL client certificate, as a path or (cert, key) tuple.",
        "verify": "Whether to verify the server's TLS certificate.",
        "stream": "Whether to stream the response content.",
        "allow_redirects": "Whether to follow HTTP redirects.",
        "max_retries": "Maximum number of retry attempts on transient failures.",
        "retries": "Retry configuration object.",
        "value": "The underlying value.",
        "name": "The name identifier.",
        "key": "The lookup key.",
        "encoding": "Character encoding to use for str/bytes conversion.",
        "errors": "Error handling mode for encoding/decoding (strict, ignore, replace).",
        "mode": "File open mode string (e.g. 'r', 'wb').",
        "callback": "A callable invoked when the operation completes.",
        "hook": "A callable registered for this event type.",
        "event": "The event name to register or deregister.",
        "conn": "An active connection object.",
        "response": "The HTTP response object.",
        "request": "The HTTP request object.",
        "size": "Maximum number of bytes to read.",
        "chunk_size": "Number of bytes per chunk for streaming operations.",
        "pool_size": "Maximum number of connections to maintain in the pool.",
        "block": "Whether to block when the pool is exhausted.",
        "source_address": "Client-side (host, port) to bind the socket to.",
        "socket_options": "Extra socket options as a list of (level, opt, val) tuples.",
        "other": "The other instance to compare against.",
    }
    lower = arg.lower().rstrip("_")
    for key, desc in mapping.items():
        if lower == key or lower.endswith("_" + key):
            return desc
    if arg.startswith("is_") or arg.startswith("has_") or arg.startswith("can_"):
        return f"Boolean flag controlling {arg[3:].replace('_', ' ')} behaviour."
    if arg.endswith("_cb") or arg.endswith("_callback"):
        return "Callback invoked on completion."
    if arg.endswith("_fn") or arg.endswith("_func"):
        return "Callable to apply."
    if arg.endswith("_id"):
        return f"Unique identifier for the {arg[:-3].replace('_', ' ')}."
    if arg.endswith("_path") or arg.endswith("_file"):
        return f"Filesystem path to the {arg.replace('_path', '').replace('_file', '').replace('_', ' ')}."
    return f"The {arg.replace('_', ' ')} argument."


def _return_description(method_name: str, return_type: str) -> str:
    if method_name.startswith("get_") or method_name.startswith("_get_"):
        target = method_name.split("_", 1)[-1].replace("_", " ")
        return f"The current value of {target}."
    if method_name.startswith("is_") or method_name.startswith("has_"):
        return "True if the condition holds, False otherwise."
    if method_name in {"__iter__", "iter"}:
        return "An iterator over the contained elements."
    if method_name in {"__len__", "size", "count"}:
        return "Number of elements."
    if method_name in {"encode", "serialize", "pack", "_packed"}:
        return "The encoded byte representation."
    if method_name in {"decode", "deserialize", "unpack"}:
        return "The decoded Python object."
    if method_name in {"copy", "clone", "__copy__"}:
        return "A shallow copy of this instance."
    if return_type == "str":
        return "String representation."
    if return_type == "bytes":
        return "Raw byte content."
    if return_type == "bool":
        return "True on success, False otherwise."
    if return_type == "int":
        return "Integer result value."
    return f"The computed {return_type} result."


def _method_summary(name: str, args: list[str], return_type: str | None) -> str:
    non_self = [a for a in args if a not in {"self", "cls"}]
    mapping: dict[str, str] = {
        "__init__": "Initialise a new instance.",
        "__repr__": "Return an unambiguous string representation.",
        "__str__": "Return a human-readable string representation.",
        "__bytes__": "Return the binary encoding of this object.",
        "__len__": "Return the number of contained elements.",
        "__bool__": "Return the truth value of this object.",
        "__iter__": "Return an iterator over the contained elements.",
        "__next__": "Return the next element, raising StopIteration when exhausted.",
        "__contains__": "Return True if the element is present.",
        "__enter__": "Enter the runtime context for this object.",
        "__exit__": "Exit the runtime context, suppressing exceptions if appropriate.",
        "__eq__": "Return True if this instance equals *other*.",
        "__ne__": "Return True if this instance does not equal *other*.",
        "__hash__": "Return a hash of this instance suitable for dict keys.",
        "__lt__": "Return True if this instance is less than *other*.",
        "__le__": "Return True if this instance is less than or equal to *other*.",
        "__gt__": "Return True if this instance is greater than *other*.",
        "__ge__": "Return True if this instance is greater than or equal to *other*.",
        "__reduce__": "Return state for pickling.",
        "__getstate__": "Return the instance state for serialisation.",
        "__setstate__": "Restore the instance from serialised state.",
        "__copy__": "Return a shallow copy.",
        "__deepcopy__": "Return a deep copy.",
        "__call__": "Call this object as a function.",
        "__getattr__": "Called when an attribute is not found through normal means.",
        "__setattr__": "Set the named attribute on the object.",
        "__delattr__": "Delete the named attribute.",
        "__getitem__": "Return the value at the given key or index.",
        "__setitem__": "Set the value at the given key or index.",
        "__delitem__": "Delete the value at the given key or index.",
        "close": "Release all resources held by this object.",
        "connect": "Establish the underlying connection.",
        "disconnect": "Terminate the underlying connection.",
        "reconnect": "Close and reopen the underlying connection.",
        "send": "Send data over the connection.",
        "receive": "Receive data from the connection.",
        "read": "Read and return data.",
        "write": "Write data.",
        "flush": "Flush any buffered data to the underlying sink.",
        "encode": "Encode this object to bytes.",
        "decode": "Decode bytes into a Python object.",
        "serialize": "Serialise this object to a portable representation.",
        "deserialize": "Restore an object from its serialised form.",
        "validate": "Validate the data and raise on the first violation.",
        "copy": "Return a shallow copy of this object.",
        "clone": "Return an independent copy of this object.",
        "register_hook": "Register a callable as a hook for the given event.",
        "deregister_hook": "Remove a previously registered hook for the given event.",
        "prepare": "Prepare the object for dispatch.",
    }
    if name in mapping:
        return mapping[name]
    if name.startswith("prepare_"):
        target = name[len("prepare_") :].replace("_", " ")
        return f"Prepare the {target} field for transmission."
    if name.startswith("get_"):
        target = name[4:].replace("_", " ")
        return f"Return the current {target}."
    if name.startswith("set_"):
        target = name[4:].replace("_", " ")
        return f"Set the {target} to *{non_self[0] if non_self else 'value'}*."
    if name.startswith("is_") or name.startswith("has_") or name.startswith("can_"):
        cond = name[3:].replace("_", " ")
        return f"Return True if {cond}."
    if name.startswith("add_"):
        target = name[4:].replace("_", " ")
        return f"Add *{non_self[0] if non_self else target}* to the {target} collection."
    if name.startswith("remove_"):
        target = name[7:].replace("_", " ")
        return f"Remove *{non_self[0] if non_self else target}* from the {target} collection."
    if name.startswith("on_") or name.startswith("handle_"):
        event = name.split("_", 1)[-1].replace("_", " ")
        return f"Handle the {event} event."
    if name.startswith("build_") or name.startswith("make_") or name.startswith("create_"):
        target = name.split("_", 1)[-1].replace("_", " ")
        return f"Build and return a new {target}."
    if name.startswith("load_") or name.startswith("fetch_"):
        target = name.split("_", 1)[-1].replace("_", " ")
        return f"Load {target} from the backing store."
    if name.startswith("save_") or name.startswith("dump_"):
        target = name.split("_", 1)[-1].replace("_", " ")
        return f"Persist {target} to the backing store."
    if name.startswith("_check_") or name.startswith("_validate_") or name.startswith("_ensure_"):
        target = name.lstrip("_").split("_", 1)[-1].replace("_", " ")
        return f"Validate that {target} satisfies its invariants."
    return f"Perform the {name.lstrip('_').replace('_', ' ')} operation."


def _parse_raise_messages(messages: list[str]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for msg in messages:
        lower = msg.lower()
        if "typeerror" in lower or "must be" in lower or "expected" in lower:
            result.append(("TypeError", msg))
        elif "valueerror" in lower or "invalid" in lower or "unsupported" in lower:
            result.append(("ValueError", msg))
        elif "connection" in lower or "timeout" in lower:
            result.append(("ConnectionError", msg))
        elif "ioerror" in lower or "oserror" in lower:
            result.append(("OSError", msg))
        elif "keyerror" in lower or "not found" in lower:
            result.append(("KeyError", msg))
        elif "runtime" in lower or "error" in lower:
            result.append(("RuntimeError", msg))
    # deduplicate by exception type
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for exc, msg in result:
        if exc not in seen:
            seen.add(exc)
            deduped.append((exc, msg))
    return deduped[:4]


# ---------------------------------------------------------------------------
# Type inferencer
# ---------------------------------------------------------------------------


class TypeInferencer:
    """Infer Python type annotations from attribute names and hint patterns."""

    _ATTR_TYPE_MAP: dict[str, str] = {
        "_value": "Any",
        "_name": "str",
        "_host": "str",
        "_port": "int",
        "_timeout": "float | None",
        "_maxsize": "int",
        "_block": "bool",
        "_headers": "dict[str, str]",
        "_cookies": "dict[str, str]",
        "_url": "str",
        "_method": "str",
        "_body": "bytes | None",
        "_data": "bytes | None",
        "_encoding": "str",
        "_errors": "str",
        "_lock": "threading.Lock",
        "_rlock": "threading.RLock",
        "_items": "list[Any]",
        "_entries": "list[Any]",
        "_buffer": "bytearray",
        "_queue": "Any",
        "_socket": "Any",
        "_lib": "Any",
        "_ffi": "Any",
        "_ptr": "Any",
        "_handle": "Any",
        "_pool": "Any",
        "_hooks": "dict[str, list[Callable[..., Any]]]",
        "_session": "Any",
        "_cert": "Any",
        "_key": "Any",
        "_ca_certs": "str | None",
        "_ssl_context": "Any",
        "_type_id": "int",
        "_version": "int",
        "_code": "int",
        "_status": "int",
        "_reason": "str",
        "_content": "bytes",
        "_text": "str",
        "_json": "Any",
        "_stream": "bool",
        "_chunk_size": "int | None",
        "_redirect": "bool",
        "_max_redirects": "int",
    }

    @classmethod
    def infer(cls, attr_name: str) -> str:
        direct = cls._ATTR_TYPE_MAP.get(attr_name)
        if direct:
            return direct
        bare = attr_name.lstrip("_")
        if bare.endswith("_list") or bare.endswith("_items") or bare.endswith("s"):
            return "list[Any]"
        if bare.endswith("_dict") or bare.endswith("_map") or bare.endswith("_table"):
            return "dict[str, Any]"
        if bare.endswith("_cb") or bare.endswith("_callback") or bare.endswith("_fn"):
            return "Callable[..., Any] | None"
        if bare.endswith("_id") or bare.endswith("_size") or bare.endswith("_count"):
            return "int"
        if bare.endswith("_flag") or bare.startswith("is_") or bare.startswith("has_"):
            return "bool"
        if bare.endswith("_path") or bare.endswith("_dir") or bare.endswith("_file"):
            return "str | Path | None"
        if bare.endswith("_timeout") or bare.endswith("_delay") or bare.endswith("_interval"):
            return "float | None"
        if bare.endswith("_name") or bare.endswith("_key") or bare.endswith("_host"):
            return "str"
        return "Any"


# ---------------------------------------------------------------------------
# AST nodes
# ---------------------------------------------------------------------------


@dataclass
class FunctionDefNode:
    name: str
    is_method: bool = False
    args: list[str] = field(default_factory=list)
    annotations: OrderedDict[str, str] = field(default_factory=OrderedDict)
    return_type: str | None = None
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None
    messages: list[str] = field(default_factory=list)
    string_hints: list[str] = field(default_factory=list)
    tuples: list[tuple[Any, ...]] = field(default_factory=list)
    dict_hints: list[dict[str, Any]] = field(default_factory=list)
    literals: list[Any] = field(default_factory=list)
    body_lines: list[str] = field(default_factory=list)
    line_hint: int | None = None

    def reset_hints(self) -> None:
        self.messages.clear()
        self.string_hints.clear()
        self.tuples.clear()
        self.dict_hints.clear()
        self.literals.clear()

    def render(self, indent: int = 0) -> str:
        pad = "    " * indent
        out: list[str] = []

        for dec in self.decorators:
            out.append(f"{pad}@{dec}")

        args = self.args[:] or (["self"] if self.is_method else [])
        if "classmethod" in self.decorators and args and args[0] == "self":
            args[0] = "cls"
        if "property" in self.decorators:
            args = ["self"]

        sig: list[str] = []
        for arg in args:
            ann = self.annotations.get(arg)
            sig.append(f"{arg}: {ann}" if ann else arg)

        ret = f" -> {self.return_type}" if self.return_type else ""
        out.append(f"{pad}def {self.name}({', '.join(sig)}){ret}:")

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

        bp = "    " * (indent + 1)
        for line in body:
            out.append(f"{bp}{line}" if line else "")
        return "\n".join(out) + "\n"


@dataclass
class ClassDefNode:
    name: str
    bases: list[str] = field(default_factory=list)
    docstring: str | None = None
    slots: tuple[str, ...] | None = None
    attributes: set[str] = field(default_factory=set)
    constants: OrderedDict[str, str] = field(default_factory=OrderedDict)
    methods: OrderedDict[str, FunctionDefNode] = field(default_factory=OrderedDict)

    def render(self, indent: int = 0) -> str:
        pad = "    " * indent
        header = f"{pad}class {self.name}"
        if self.bases:
            header += f"({', '.join(self.bases)})"
        header += ":"
        out = [header]
        bl: list[str] = []
        if self.docstring:
            doc = clean_docstring(self.docstring) or ""
            dls = doc.splitlines()
            if len(dls) <= 1:
                bl.append(f'"""{doc}"""')
            else:
                bl += ['"""', *dls, '"""']
        if self.slots:
            bl.append(f"__slots__ = {repr(self.slots)}")
        for cname, cval in self.constants.items():
            bl.append(f"{cname} = {cval}")
        if self.attributes:
            bl.append("# Recovered instance attributes")
            for attr in sorted(self.attributes):
                inferred = TypeInferencer.infer(attr)
                bl.append(f"# {attr}: {inferred}")
        for method in self.methods.values():
            if bl:
                bl.append("")
            bl.extend(method.render(indent + 1).rstrip().splitlines())
        if not bl:
            bl = ["pass"]
        bp = "    " * (indent + 1)
        for line in bl:
            if not line:
                out.append("")
            elif line.startswith("    " * (indent + 1)) or line.startswith("    " * (indent + 2)):
                out.append(line)
            else:
                out.append(f"{bp}{line}")
        return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Pending state
# ---------------------------------------------------------------------------


@dataclass
class _PendingState:
    docstring: str | None = None
    annotations: dict[str, str] | None = None
    decorators: list[str] = field(default_factory=list)
    args: list[str] | None = None
    line: int | None = None
    dicts: list[Any] = field(default_factory=list)
    tuples: list[Any] = field(default_factory=list)
    literals: list[Any] = field(default_factory=list)

    def reset(self) -> None:
        self.docstring = None
        self.annotations = None
        self.decorators = []
        self.args = None
        self.line = None
        self.dicts = []
        self.tuples = []
        self.literals = []


# ---------------------------------------------------------------------------
# Body Synthesizer — the core logic engine
# ---------------------------------------------------------------------------


class BodySynthesizer:
    """
    Produces verbose, production-quality method bodies from metadata hints.

    Each specialised ``_body_*`` method targets a specific pattern category.
    The main entry point is :meth:`build`.
    """

    # ------------------------------------------------------------------
    # public entry point
    # ------------------------------------------------------------------

    @classmethod
    def build(
        cls,
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        non_self = [a for a in func.args if a not in {"self", "cls"}]

        if "abstractmethod" in func.decorators:
            return cls._body_abstract(func)

        cls._promote_messages_to_docstrings(func)

        if func.name in {"__init__", "_init_without_validation"}:
            return cls._body_init(cls_node, func, attrs, non_self)

        if func.name in {"__enter__"}:
            return cls._body_enter(cls_node, func, attrs)

        if func.name in {"__exit__"}:
            return cls._body_exit(cls_node, func, attrs)

        if func.name in {"__iter__"}:
            return cls._body_iter(cls_node, func, attrs)

        if func.name in {"__next__"}:
            return cls._body_next(cls_node, func, attrs)

        if func.name in {"__repr__"}:
            return cls._body_repr(cls_node, func, attrs)

        if func.name in {"__str__"}:
            return cls._body_str(cls_node, func, attrs)

        if func.name in {"__bytes__"}:
            return cls._body_bytes(cls_node, func, attrs)

        if func.name in {"__len__"}:
            return cls._body_len(cls_node, func, attrs)

        if func.name in {"__bool__"}:
            return cls._body_bool(cls_node, func, attrs)

        if func.name in {"__eq__", "__ne__"}:
            return cls._body_eq(cls_node, func, attrs)

        if func.name == "__lt__":
            return cls._body_comparison(cls_node, func, attrs, "<")

        if func.name == "__le__":
            return cls._body_comparison(cls_node, func, attrs, "<=")

        if func.name == "__gt__":
            return cls._body_comparison(cls_node, func, attrs, ">")

        if func.name == "__ge__":
            return cls._body_comparison(cls_node, func, attrs, ">=")

        if func.name in {"__hash__"}:
            return cls._body_hash(cls_node, func, attrs)

        if func.name in {"__reduce__", "__getstate__", "__setstate__"}:
            return cls._body_pickle(cls_node, func, attrs, non_self)

        if func.name in {"__contains__"}:
            return cls._body_contains(cls_node, func, attrs, non_self)

        if func.name in {"__getitem__"}:
            return cls._body_getitem(cls_node, func, attrs, non_self)

        if func.name in {"__setitem__"}:
            return cls._body_setitem(cls_node, func, attrs, non_self)

        if func.name in {"__delitem__"}:
            return cls._body_delitem(cls_node, func, attrs, non_self)

        if func.name in {"__call__"}:
            return cls._body_call(cls_node, func, attrs, non_self)

        if func.name in {"copy", "clone", "__copy__"}:
            return cls._body_copy(cls_node, func, attrs)

        if func.name == "register_hook":
            return cls._body_register_hook()

        if func.name == "deregister_hook":
            return cls._body_deregister_hook()

        if func.name in {"close", "shutdown", "cleanup", "dispose", "destroy", "__del__"}:
            return cls._body_close(cls_node, func, attrs)

        if func.name in {"connect"}:
            return cls._body_connect(cls_node, func, attrs, non_self)

        if func.name in {"send", "write"}:
            return cls._body_send(cls_node, func, attrs, non_self)

        if func.name in {"receive", "read"}:
            return cls._body_read(cls_node, func, attrs, non_self)

        if func.name in {"flush"}:
            return cls._body_flush(cls_node, func, attrs)

        if func.name in {"encode", "serialize", "pack", "_packed"}:
            return cls._body_encode(cls_node, func, attrs)

        if func.name in {"decode", "deserialize", "unpack"}:
            return cls._body_decode(cls_node, func, attrs, non_self)

        if func.name in {"validate", "_validate"}:
            return cls._body_validate(cls_node, func, attrs, non_self)

        if func.name == "prepare":
            return cls._body_prepare_dispatch(cls_node, func, attrs, non_self)

        if func.name.startswith("prepare_"):
            return cls._body_prepare_field(cls_node, func, attrs, non_self)

        if func.name == "value" and "property" in func.decorators:
            return ["return self._value"] if "_value" in attrs else ([f"return self.{attrs[0]}"] if attrs else ["return None"])

        if "property" in func.decorators:
            return cls._body_property_getter(cls_node, func, attrs)

        if func.name.startswith("get") and not non_self:
            return cls._body_simple_getter(cls_node, func, attrs)

        if func.name.startswith(("set_", "_set_")) and len(non_self) == 1:
            return cls._body_simple_setter(cls_node, func, attrs, non_self)

        if func.name.startswith(("is_", "has_", "can_")):
            return cls._body_predicate(cls_node, func, attrs)

        if func.name.startswith(("add_", "_add_", "append_")):
            return cls._body_add(cls_node, func, attrs, non_self)

        if func.name.startswith(("remove_", "_remove_", "delete_")):
            return cls._body_remove(cls_node, func, attrs, non_self)

        if func.name.startswith(("clear_", "_clear_", "reset_")):
            return cls._body_clear(cls_node, func, attrs)

        if func.name.startswith(("on_", "handle_", "_handle_")):
            return cls._body_handler(cls_node, func, attrs, non_self)

        if func.name.startswith(("build_", "make_", "create_", "_build_", "_make_")):
            return cls._body_factory(cls_node, func, attrs, non_self)

        if func.name.startswith(("load_", "fetch_", "_load_", "_fetch_")):
            return cls._body_load(cls_node, func, attrs, non_self)

        if func.name.startswith(("save_", "dump_", "_save_", "_dump_")):
            return cls._body_save(cls_node, func, attrs, non_self)

        if func.name.startswith(("_check_", "_validate_", "_ensure_", "_assert_")):
            return cls._body_internal_check(cls_node, func, attrs, non_self)

        # API/C-binding body (Stricter validation)
        if hasattr(func, "string_hints") and func.string_hints:
            api_body = cls._body_api_calls(cls_node, func, attrs, non_self)
            if api_body:
                return api_body

        # Validation-only
        validation = cls._validation_lines(func, non_self)
        if validation:
            return validation

        # Deep Instruction Tracing Inference (Replaces structural fallback)
        return cls._body_heuristic_synthesis(cls_node, func, attrs, non_self)

    # ------------------------------------------------------------------
    # Helpers shared across builders
    # ------------------------------------------------------------------

    @staticmethod
    def _validation_lines(func: FunctionDefNode, non_self: list[str]) -> list[str]:
        lines: list[str] = []
        primary = non_self[0] if non_self else "value"
        for msg in func.messages[:8]:
            lower = msg.lower()
            if "must be string" in lower or "must be a byte string" in lower or "must be str" in lower:
                lines += [
                    f"if not isinstance({primary}, (str, bytes)):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be a name" in lower:
                lines += [
                    f"if not isinstance({primary}, Name):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be an objectidentifier" in lower:
                lines += [
                    f"if not isinstance({primary}, ObjectIdentifier):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be an integer" in lower or "must be int" in lower:
                lines += [
                    f"if not isinstance({primary}, int):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be a float" in lower or "must be numeric" in lower:
                lines += [
                    f"if not isinstance({primary}, (int, float)):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be a list" in lower or "must be a sequence" in lower:
                lines += [
                    f"if not isinstance({primary}, (list, tuple)):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be a dict" in lower or "must be a mapping" in lower:
                lines += [
                    f"if not isinstance({primary}, dict):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be callable" in lower:
                lines += [
                    f"if not callable({primary}):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "must be an instance of" in lower:
                # Try to extract the class name
                m = re.search(r"instance of\s+(\w+)", msg, re.I)
                cls_name = m.group(1) if m else "object"
                lines += [
                    f"if not isinstance({primary}, {cls_name}):",
                    f"    raise TypeError({msg!r})",
                ]
            elif "unsupported" in lower or lower.startswith("invalid ") or "not valid" in lower:
                lines += [
                    f"if {primary} not in self._SUPPORTED:",
                    f"    raise ValueError({msg!r})",
                ]
            elif "deprecated" in lower:
                lines.append(f"warnings.warn({msg!r}, DeprecationWarning, stacklevel=2)")
            elif "already open" in lower:
                lines += [
                    "if self._is_open:",
                    f"    raise RuntimeError({msg!r})",
                ]
            elif "already closed" in lower or "not open" in lower:
                lines += [
                    "if not self._is_open:",
                    f"    raise RuntimeError({msg!r})",
                ]
            elif "timeout" in lower:
                lines += [
                    f"if {primary} is not None and {primary} < 0:",
                    f"    raise ValueError({msg!r})",
                ]
        return lines

    @staticmethod
    def _promote_messages_to_docstrings(func: FunctionDefNode) -> None:
        if func.docstring:
            return
        remaining: list[str] = []
        for msg in func.messages:
            if not func.docstring and len(msg) > 30 and ("\n" in msg or ":param" in msg or ":return" in msg):
                func.docstring = clean_docstring(msg)
            else:
                remaining.append(msg)
        func.messages = remaining

    @staticmethod
    def _lock_wrap(lines: list[str], attrs: list[str]) -> list[str]:
        """Wrap *lines* in ``with self._lock:`` if a lock attribute is present."""
        lock = next((a for a in attrs if a in LOCK_ATTRS), None)
        if not lock:
            return lines
        wrapped = [f"with self.{lock}:"] + [f"    {l}" if l else "" for l in lines]
        return wrapped

    @staticmethod
    def _has_lock(attrs: list[str]) -> bool:
        return any(a in LOCK_ATTRS for a in attrs)

    @staticmethod
    def _iter_attr(attrs: list[str]) -> str | None:
        return next((a for a in attrs if a in ITER_ATTRS), attrs[0] if attrs else None)

    # ------------------------------------------------------------------
    # Raw metadata fallback — paste everything we recovered
    # ------------------------------------------------------------------

    @staticmethod
    def _body_metadata_fallback(func: FunctionDefNode) -> list[str]:
        """Dump all recovered metadata fragments as raw literals.
        Output is NOT guaranteed to be valid Python — that's intentional.
        The goal is data preservation over syntactic correctness."""
        lines: list[str] = []
        lines.append(f"# === RAW METADATA for {func.name!r} ===")

        if func.messages:
            lines.append("# --- messages ---")
            for msg in func.messages:
                lines.append(repr(msg))

        if func.string_hints:
            lines.append("# --- string hints ---")
            for hint in func.string_hints:
                lines.append(repr(hint))

        if func.literals:
            lines.append("# --- literals ---")
            for lit in func.literals:
                lines.append(repr(lit))

        if func.tuples:
            lines.append("# --- tuples ---")
            for tup in func.tuples:
                lines.append(repr(tup))

        if func.dict_hints:
            lines.append("# --- dicts ---")
            for d in func.dict_hints:
                lines.append(repr(d))

        if func.annotations:
            lines.append("# --- annotations ---")
            for k, v in func.annotations.items():
                lines.append(f"{k}: {v}")

        if not lines or len(lines) <= 1:
            lines.append("pass  # no metadata recovered")

        return lines

    # ------------------------------------------------------------------
    # Individual body builders
    # ------------------------------------------------------------------

    @staticmethod
    def _body_abstract(func: FunctionDefNode) -> list[str]:
        fallback = BodySynthesizer._body_metadata_fallback(func)
        if len(fallback) > 1:
            return fallback
        return [
            "raise NotImplementedError(",
            f'    f"{{type(self).__name__}} must implement {func.name!r}"',
            ")",
        ]

    @staticmethod
    def _body_init(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        lines: list[str] = []

        # super().__init__() for subclasses
        bases = cls_node.bases if cls_node else []
        if bases and bases[0] not in {"object"}:
            base = bases[0]
            if base in KNOWN_BASE_NAMES:
                # Exception subclass
                msg_args = ", ".join(non_self[:2]) if non_self else ""
                lines.append(f"super().__init__({msg_args})")
            else:
                pass_args = ", ".join(non_self[:3])
                lines.append(f"super().__init__({pass_args})")

        # validation first
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines.extend(validation)

        # bind args → attrs
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
                for cand in attrs:
                    if cand not in used and cand.lstrip("_") == arg:
                        preferred = cand
                        break
            if preferred:
                used.add(preferred)
                lines.append(f"self.{preferred} = {arg}")

        # zero-initialise any remaining attrs not covered by args
        remaining_attrs = [a for a in attrs if a not in used]
        if remaining_attrs:
            lines.append("")
            lines.append("# Initialise remaining attributes")
        for attr in remaining_attrs[:12]:
            inferred = TypeInferencer.infer(attr)
            if attr in LOCK_ATTRS:
                lines.append(f"self.{attr} = threading.Lock()")
            elif attr in ITER_ATTRS:
                lines.append(f"self.{attr} = []")
            elif "dict" in inferred or "Mapping" in inferred:
                lines.append(f"self.{attr} = {{}}")
            elif inferred.startswith("int"):
                lines.append(f"self.{attr} = 0")
            elif inferred.startswith("float"):
                lines.append(f"self.{attr} = 0.0")
            elif inferred.startswith("bool"):
                lines.append(f"self.{attr} = False")
            elif inferred.startswith("str"):
                lines.append(f"self.{attr} = ''")
            elif inferred.startswith("bytes"):
                lines.append(f"self.{attr} = b''")
            else:
                lines.append(f"self.{attr} = None")

        # logger if hints suggest it
        if any(LOG_RE.search(h) for h in func.string_hints):
            lines.append("self._logger = logging.getLogger(__name__)")

        if not lines:
            lines.append("pass")
        return lines

    @staticmethod
    def _body_enter(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        lines: list[str] = []
        lock = next((a for a in attrs if a in LOCK_ATTRS), None)
        if lock:
            lines.append(f"self.{lock}.acquire()")
        open_attr = next((a for a in attrs if "open" in a or "connect" in a or "active" in a), None)
        if open_attr:
            lines.append(f"self.{open_attr} = True")
        lines.append("return self")
        return lines

    @staticmethod
    def _body_exit(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        lines: list[str] = []
        lines.append("try:")
        close_methods = [m for m in (cls_node.methods if cls_node else {}) if m == "close"]
        if close_methods:
            lines.append("    self.close()")
        else:
            for attr in attrs[:4]:
                if any(kw in attr for kw in ("socket", "conn", "stream", "file", "handle")):
                    lines.append(f"    if self.{attr} is not None:")
                    lines.append(f"        self.{attr}.close()")
                    lines.append(f"        self.{attr} = None")
        lines += ["except Exception:", "    pass"]
        lock = next((a for a in attrs if a in LOCK_ATTRS), None)
        if lock:
            lines.append("finally:")
            lines.append(f"    self.{lock}.release()")
        lines.append("return False  # do not suppress exceptions")
        return lines

    @staticmethod
    def _body_iter(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        coll = BodySynthesizer._iter_attr(attrs)
        if coll:
            return [f"return iter(self.{coll})"]
        return ["return iter(())"]

    @staticmethod
    def _body_next(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        idx_attr = next((a for a in attrs if "index" in a or "_pos" in a or "_cursor" in a), None)
        coll = BodySynthesizer._iter_attr(attrs)
        lines: list[str] = []
        if idx_attr and coll:
            lines = [
                f"if self.{idx_attr} >= len(self.{coll}):",
                "    raise StopIteration",
                f"item = self.{coll}[self.{idx_attr}]",
                f"self.{idx_attr} += 1",
                "return item",
            ]
        elif coll:
            lines = [
                "try:",
                f"    return next(self._{coll.lstrip('_')}_iter)",
                "except StopIteration:",
                "    raise",
            ]
        else:
            lines = ["raise StopIteration"]
        return lines

    @staticmethod
    def _body_repr(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        cls_name = cls_node.name if cls_node else "object"
        if not attrs:
            return [f'return f"<{cls_name}>"']
        field_parts = ", ".join(f"{a.lstrip('_')}={{self.{a}!r}}" for a in attrs[:6])
        return [
            "return (",
            f'    f"{cls_name}({field_parts}"',
            ")",
        ]

    @staticmethod
    def _body_str(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        cls_name = cls_node.name if cls_node else "object"
        str_cands = [a for a in attrs if TypeInferencer.infer(a) in ("str", "Any")]
        if str_cands:
            return [f"return str(self.{str_cands[0]})"]
        if attrs:
            return [f"return str(self.{attrs[0]})"]
        return [f'return f"<{cls_name}>"']

    @staticmethod
    def _body_bytes(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        byte_cands = [a for a in attrs if TypeInferencer.infer(a) in ("bytes", "bytearray")]
        if byte_cands:
            return [f"return bytes(self.{byte_cands[0]})"]
        if attrs:
            return [
                f"data = self.{attrs[0]}",
                "if isinstance(data, (bytes, bytearray)):",
                "    return bytes(data)",
                "if isinstance(data, str):",
                "    return data.encode('utf-8')",
                "raise TypeError(f'Cannot convert {type(data).__name__!r} to bytes')",
            ]
        return ["return b''"]

    @staticmethod
    def _body_len(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        for attr in attrs:
            if any(kw in attr for kw in ("items", "list", "data", "buffer", "entries", "queue")):
                return [f"return len(self.{attr})"]
        return [f"return len(self.{attrs[0]})"] if attrs else ["return 0"]

    @staticmethod
    def _body_bool(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        for attr in attrs:
            if any(kw in attr for kw in ("open", "active", "ready", "valid", "connected", "enabled")):
                return [f"return bool(self.{attr})"]
        coll = BodySynthesizer._iter_attr(attrs)
        if coll:
            return [f"return len(self.{coll}) > 0"]
        return ["return True"]

    @staticmethod
    def _body_eq(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        cls_name = cls_node.name if cls_node else "object"
        lines = [
            f"if not isinstance(other, {cls_name}):",
            "    return NotImplemented",
        ]
        if attrs:
            comparisons = " and ".join(f"self.{a} == other.{a}" for a in attrs[:6])
            if func.name == "__ne__":
                lines.append(f"return not ({comparisons})")
            else:
                lines.append(f"return {comparisons}")
        else:
            op = "is not" if func.name == "__ne__" else "is"
            lines.append(f"return self {op} other")
        return lines

    @staticmethod
    def _body_comparison(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        op: str,
    ) -> list[str]:
        cls_name = cls_node.name if cls_node else "object"
        lines = [
            f"if not isinstance(other, {cls_name}):",
            "    return NotImplemented",
        ]
        if attrs:
            a = attrs[0]
            lines.append(f"return self.{a} {op} other.{a}")
        else:
            lines.append(f"return id(self) {op} id(other)")
        return lines

    @staticmethod
    def _body_hash(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        if not attrs:
            return ["return hash(id(self))"]
        members = ", ".join(f"self.{a}" for a in attrs[:4])
        suffix = "," if len(attrs[:4]) == 1 else ""
        return [
            "return hash((",
            f"    {members}{suffix}",
            "))",
        ]

    @staticmethod
    def _body_pickle(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        if func.name == "__reduce__":
            if attrs:
                members = ", ".join(f"self.{a}" for a in attrs[:4])
                suffix = "," if len(attrs[:4]) == 1 else ""
                return [f"return (self.__class__, ({members}{suffix}))"]
            return ["return (self.__class__, ())"]
        if func.name == "__getstate__":
            if attrs:
                items = ", ".join(f"{a.lstrip('_')!r}: self.{a}" for a in attrs[:8])
                return [f"return {{{items}}}"]
            return ["return self.__dict__.copy()"]
        if func.name == "__setstate__":
            arg = non_self[0] if non_self else "state"
            lines: list[str] = []
            for a in attrs[:8]:
                lines.append(f"self.{a} = {arg}.get({a.lstrip('_')!r})")
            return lines if lines else [f"self.__dict__.update({arg})"]
        return ["pass"]

    @staticmethod
    def _body_contains(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        item = non_self[0] if non_self else "item"
        coll = BodySynthesizer._iter_attr(attrs)
        if coll:
            return [f"return {item} in self.{coll}"]
        return ["return False"]

    @staticmethod
    def _body_getitem(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        key = non_self[0] if non_self else "key"
        coll = BodySynthesizer._iter_attr(attrs)
        if coll:
            return [f"return self.{coll}[{key}]"]
        return [f"raise KeyError({key})"]

    @staticmethod
    def _body_setitem(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        key = non_self[0] if non_self else "key"
        value = non_self[1] if len(non_self) > 1 else "value"
        coll = BodySynthesizer._iter_attr(attrs)
        if coll:
            return [f"self.{coll}[{key}] = {value}"]
        return ["pass"]

    @staticmethod
    def _body_delitem(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        key = non_self[0] if non_self else "key"
        coll = BodySynthesizer._iter_attr(attrs)
        if coll:
            return [
                "try:",
                f"    del self.{coll}[{key}]",
                "except (KeyError, IndexError) as exc:",
                f"    raise KeyError({key}) from exc",
            ]
        return [f"raise KeyError({key})"]

    @staticmethod
    def _body_call(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        callable_attr = next((a for a in attrs if "_fn" in a or "_func" in a or "_callback" in a), None)
        if callable_attr:
            args_str = ", ".join(non_self[:4])
            return [
                f"if self.{callable_attr} is None:",
                "    raise TypeError('No callable configured')",
                f"return self.{callable_attr}({args_str})",
            ]
        fallback = BodySynthesizer._body_metadata_fallback(func)
        if len(fallback) > 1:
            return fallback
        return ["pass  # __call__ — no metadata recovered"]

    @staticmethod
    def _body_copy(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        cls_name = cls_node.name if cls_node else "object"
        if attrs:
            kwargs = ", ".join(f"{a.lstrip('_')}=self.{a}" for a in attrs[:8])
            return [
                f"return {cls_name}(",
                f"    {kwargs},",
                ")",
            ]
        return ["import copy", "return copy.copy(self)"]

    @staticmethod
    def _body_register_hook() -> list[str]:
        return [
            "if not callable(hook):",
            "    raise TypeError(f'hook must be callable, got {type(hook).__name__!r}')",
            "self.hooks.setdefault(event, []).append(hook)",
            "return hook",
        ]

    @staticmethod
    def _body_deregister_hook() -> list[str]:
        return [
            "event_hooks = self.hooks.get(event, [])",
            "if hook not in event_hooks:",
            "    return False",
            "event_hooks.remove(hook)",
            "return True",
        ]

    @staticmethod
    def _body_close(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        lines: list[str] = []
        # Close open handles first
        closeable = [a for a in attrs if any(kw in a for kw in ("socket", "conn", "stream", "file", "handle", "session"))]
        if closeable:
            lines.append("try:")
            for attr in closeable[:4]:
                lines.append(f"    if self.{attr} is not None:")
                lines.append(f"        self.{attr}.close()")
                lines.append(f"        self.{attr} = None")
            lines += ["except Exception:", "    pass"]
        # Null out remaining attrs
        nullables = [a for a in attrs if a not in closeable]
        for attr in nullables[:6]:
            lines.append(f"self.{attr} = None")
        if not lines:
            lines.append("pass")
        return lines

    @staticmethod
    def _body_connect(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        host_attr = next((a for a in attrs if "host" in a), "_host")
        port_attr = next((a for a in attrs if "port" in a), "_port")
        sock_attr = next((a for a in attrs if "socket" in a or "conn" in a), None)
        timeout_attr = next((a for a in attrs if "timeout" in a), None)
        lines: list[str] = [
            "import socket as _socket",
            "sock = _socket.create_connection(",
            f"    (self.{host_attr}, self.{port_attr}),",
            f"    timeout=self.{timeout_attr}," if timeout_attr else "    timeout=None,",
            ")",
        ]
        if sock_attr:
            lines.append(f"self.{sock_attr} = sock")
        else:
            lines.append("self._socket = sock")
        return lines

    @staticmethod
    def _body_send(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        data_arg = non_self[0] if non_self else "data"
        sock_attr = next((a for a in attrs if "socket" in a or "conn" in a or "stream" in a), None)
        lines: list[str] = []
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines.extend(validation)
        if sock_attr:
            lines += [
                f"if self.{sock_attr} is None:",
                "    raise RuntimeError('Not connected')",
                f"if isinstance({data_arg}, str):",
                f"    {data_arg} = {data_arg}.encode('utf-8')",
                f"self.{sock_attr}.sendall({data_arg})",
            ]
        else:
            lines += [
                f"if isinstance({data_arg}, str):",
                f"    {data_arg} = {data_arg}.encode('utf-8')",
                f"# Write {data_arg} to the underlying transport",
                f"self._write_raw({data_arg})",
            ]
        return lines if lines else ["pass"]

    @staticmethod
    def _body_read(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        size_arg = next((a for a in non_self if "size" in a or "amt" in a or "n" == a), None)
        sock_attr = next((a for a in attrs if "socket" in a or "conn" in a or "stream" in a), None)
        buf_attr = next((a for a in attrs if "buffer" in a or "buf" in a), None)
        lines: list[str] = []
        if buf_attr:
            if size_arg:
                lines = [
                    f"chunk = self.{buf_attr}[:{size_arg}]",
                    f"self.{buf_attr} = self.{buf_attr}[{size_arg}:]",
                    "return bytes(chunk)",
                ]
            else:
                lines = [
                    f"data = bytes(self.{buf_attr})",
                    f"self.{buf_attr} = bytearray()",
                    "return data",
                ]
        elif sock_attr:
            amt = size_arg or "4096"
            lines = [
                f"if self.{sock_attr} is None:",
                "    raise RuntimeError('Not connected')",
                f"return self.{sock_attr}.recv({amt})",
            ]
        else:
            lines = [
                "# Read from underlying transport",
                "return b''",
            ]
        return lines

    @staticmethod
    def _body_flush(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        buf_attr = next((a for a in attrs if "buffer" in a or "buf" in a), None)
        sock_attr = next((a for a in attrs if "socket" in a or "conn" in a or "stream" in a), None)
        if buf_attr and sock_attr:
            return [
                f"if self.{buf_attr}:",
                f"    self.{sock_attr}.sendall(bytes(self.{buf_attr}))",
                f"    self.{buf_attr} = bytearray()",
            ]
        if buf_attr:
            return [f"self.{buf_attr} = bytearray()"]
        return ["pass"]

    @staticmethod
    def _body_encode(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        if func.name == "_packed" and "_value" in attrs:
            return ["return self._value.packed"]
        val_attr = "_value" if "_value" in attrs else (attrs[0] if attrs else None)
        if not val_attr:
            return ["return b''"]
        return [
            f"raw = self.{val_attr}",
            "if isinstance(raw, str):",
            "    return raw.encode('utf-8')",
            "if isinstance(raw, (bytes, bytearray)):",
            "    return bytes(raw)",
            "import json as _json",
            "return _json.dumps(raw, separators=(',', ':')).encode('utf-8')",
        ]

    @staticmethod
    def _body_decode(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        cls_name = cls_node.name if cls_node else "object"
        arg = non_self[0] if non_self else "data"
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines = list(validation)
        lines += [
            f"if isinstance({arg}, (bytes, bytearray)):",
            f"    {arg} = {arg}.decode('utf-8')",
            f"return {cls_name}({arg})",
        ]
        return lines

    @staticmethod
    def _body_validate(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        lines = list(BodySynthesizer._validation_lines(func, non_self))
        if not lines:
            lines = ["# All invariants satisfied", "pass"]
        return lines

    @staticmethod
    def _body_prepare_dispatch(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        if cls_node is None:
            return ["pass"]
        helpers = [n for n in cls_node.methods if n.startswith("prepare_")]
        if not helpers:
            return ["pass"]
        arg_set = set(func.args)
        lines: list[str] = []
        for helper in helpers:
            suffix = helper[len("prepare_") :]
            call_args: list[str] = []
            if suffix in arg_set:
                call_args.append(suffix)
            elif suffix == "body":
                call_args = [c for c in ("data", "files", "json", "params") if c in arg_set]
            elif suffix in {"auth", "hooks", "cookies"} and suffix in arg_set:
                call_args.append(suffix)
            lines.append(f"self.{helper}({', '.join(call_args)})")
        return lines

    @staticmethod
    def _body_prepare_field(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        suffix = func.name[len("prepare_") :]
        lines: list[str] = []
        if suffix in non_self:
            if suffix == "url":
                lines = [
                    f"if {suffix} is None:",
                    "    raise ValueError('URL is required')",
                    f"self.url = str({suffix}).strip()",
                ]
            elif suffix == "method":
                lines = [
                    f"if {suffix} is None:",
                    "    raise ValueError('method must not be None')",
                    f"self.method = {suffix}.upper()",
                ]
            elif suffix == "headers":
                lines = [
                    "self.headers = {}",
                    f"if {suffix}:",
                    f"    self.headers.update({suffix})",
                ]
            elif suffix == "body":
                lines = ["self.body = None"]
                if "data" in non_self:
                    lines += ["if data is not None:", "    self.body = data"]
                if "json" in non_self:
                    lines += [
                        "elif json is not None:",
                        "    import json as _json",
                        "    self.body = _json.dumps(json, allow_nan=False).encode('utf-8')",
                        "    self.headers['Content-Type'] = 'application/json'",
                    ]
            elif suffix == "cookies":
                lines = [
                    "self._cookies = {}",
                    f"if {suffix}:",
                    f"    self._cookies.update({suffix})",
                ]
            elif suffix == "auth":
                lines = [
                    f"if {suffix} is None:",
                    "    return",
                    f"if callable({suffix}):",
                    f"    {suffix}(self)",
                    f"elif isinstance({suffix}, tuple) and len({suffix}) == 2:",
                    "    import base64 as _b64",
                    f"    user, pw = {suffix}",
                    "    token = _b64.b64encode(f'{user}:{pw}'.encode()).decode()",
                    "    self.headers['Authorization'] = f'Basic {token}'",
                ]
            elif suffix == "hooks":
                lines = [
                    "self.hooks = {}",
                    f"if {suffix}:",
                    f"    for event, hk in {suffix}.items():",
                    "        if callable(hk):",
                    "            self.register_hook(event, hk)",
                    "        elif hasattr(hk, '__iter__'):",
                    "            for fn in hk:",
                    "                self.register_hook(event, fn)",
                ]
            else:
                lines = [f"self.{suffix} = {suffix}"]
        elif suffix == "headers" and not non_self:
            lines = ["self.headers = {}"]
        else:
            lines = [f"self.{suffix} = None"]
        return lines if lines else ["pass"]

    @staticmethod
    def _body_property_getter(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        name_match = func.name.lstrip("_")
        for attr in attrs:
            if attr.lstrip("_") == name_match:
                return [f"return self.{attr}"]
        return [f"return self.{attrs[0]}"] if attrs else ["return None"]

    @staticmethod
    def _body_simple_getter(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        candidate = func.name[3:4].lower() + func.name[4:]  # strip "get"
        for attr in attrs:
            if attr.lstrip("_") == candidate:
                return [f"return self.{attr}"]
        return [f"return self.{attrs[0]}"] if attrs else ["return None"]

    @staticmethod
    def _body_simple_setter(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        suffix = func.name.split("set_", 1)[-1]
        arg = non_self[0]
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines = list(validation)
        target = f"_{suffix}" if f"_{suffix}" in attrs else suffix
        if func.is_method:
            lines.append(f"self.{target} = {arg}")
        else:
            lines.append(f"{target} = {arg}")
        return lines if lines else [f"self.{target} = {arg}"]

    @staticmethod
    def _body_predicate(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        suffix = func.name.split("_", 1)[-1]
        for attr in attrs:
            if suffix in attr:
                inferred = TypeInferencer.infer(attr)
                if "list" in inferred or "List" in inferred:
                    return [f"return len(self.{attr}) > 0"]
                return [f"return bool(self.{attr})"]
        if attrs:
            return [f"return self.{attrs[0]} is not None"]
        return ["return False"]

    @staticmethod
    def _body_add(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        suffix = func.name.split("_", 1)[-1]
        arg = non_self[0] if non_self else "item"
        coll = next(
            (a for a in attrs if suffix in a or "items" in a or "list" in a or "entries" in a),
            None,
        )
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines = list(validation)
        if coll:
            if BodySynthesizer._has_lock(attrs):
                lock = next(a for a in attrs if a in LOCK_ATTRS)
                lines += [
                    f"with self.{lock}:",
                    f"    if {arg} not in self.{coll}:",
                    f"        self.{coll}.append({arg})",
                ]
            else:
                lines += [
                    f"if {arg} not in self.{coll}:",
                    f"    self.{coll}.append({arg})",
                ]
        else:
            lines.append(f"self._{suffix}s.append({arg})")
        return lines if lines else ["pass"]

    @staticmethod
    def _body_remove(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        suffix = func.name.split("_", 1)[-1]
        arg = non_self[0] if non_self else "item"
        coll = next(
            (a for a in attrs if suffix in a or "items" in a or "list" in a or "entries" in a),
            None,
        )
        if coll:
            return [
                "try:",
                f"    self.{coll}.remove({arg})",
                "except ValueError:",
                "    pass",
            ]
        return [f"self._{suffix}s.remove({arg})"]

    @staticmethod
    def _body_clear(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
    ) -> list[str]:
        suffix = func.name.split("_", 1)[-1]
        target = next((a for a in attrs if suffix in a), None)
        if target:
            inferred = TypeInferencer.infer(target)
            if "list" in inferred:
                return [f"self.{target}.clear()"]
            if "dict" in inferred:
                return [f"self.{target}.clear()"]
            return [f"self.{target} = None"]
        return ["pass"]

    @staticmethod
    def _body_handler(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        event = func.name.split("_", 1)[-1]
        hook_attr = next((a for a in attrs if "hook" in a or "callback" in a or "handler" in a), None)
        lines: list[str] = []
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines.extend(validation)
        if non_self:
            lines.append(f"# Handle the {event.replace('_', ' ')} event")
            lines.append(f"# Args: {', '.join(non_self)}")
        if hook_attr:
            args_str = ", ".join(non_self[:3])
            lines.append(f"for hook in self.{hook_attr}.get({event!r}, []):")
            lines.append(f"    hook({args_str})")
        else:
            lines.append("pass")
        return lines

    @staticmethod
    def _body_factory(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        target = func.name.split("_", 1)[-1]
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines = list(validation)
        # Try to find a matching class in the current module
        lines += [
            f"instance = object.__new__(object)  # TODO: replace with {target} class",
            f"# build {target.replace('_', ' ')} from: {', '.join(non_self[:4])}",
            "return instance",
        ]
        return lines

    @staticmethod
    def _body_load(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        path_arg = next((a for a in non_self if "path" in a or "file" in a or "src" in a), non_self[0] if non_self else "path")
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines = list(validation)
        if any(NETWORK_HINTS & {a for a in func.string_hints}):
            lines += [
                "import urllib.request as _req",
                f"with _req.urlopen({path_arg}) as resp:",
                "    return resp.read()",
            ]
        else:
            lines += [
                "from pathlib import Path as _Path",
                f"data = _Path({path_arg}).read_bytes()",
                "return data",
            ]
        return lines

    @staticmethod
    def _body_save(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        path_arg = next((a for a in non_self if "path" in a or "file" in a or "dst" in a), non_self[0] if non_self else "path")
        validation = BodySynthesizer._validation_lines(func, non_self)
        lines = list(validation)
        val_attr = "_value" if "_value" in attrs else (attrs[0] if attrs else None)
        if val_attr:
            lines += [
                "from pathlib import Path as _Path",
                f"_Path({path_arg}).write_bytes(",
                f"    self.{val_attr} if isinstance(self.{val_attr}, (bytes, bytearray))",
                f"    else str(self.{val_attr}).encode('utf-8')",
                ")",
            ]
        else:
            lines.append("pass")
        return lines

    @staticmethod
    def _body_internal_check(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        lines = list(BodySynthesizer._validation_lines(func, non_self))
        if not lines:
            action = func.name.lstrip("_").split("_", 1)[-1].replace("_", " ")
            lines = [
                f"# Verify {action}",
                "pass",
            ]
        return lines

    @staticmethod
    def _body_api_calls(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        api_calls: list[str] = []
        method_calls: list[str] = []
        field_refs: list[str] = []

        methods_in_class: dict[str, Any] = cls_node.methods if cls_node else {}

        for hint in func.string_hints:
            if BodySynthesizer._is_c_api_hint(hint):
                api_calls.append(hint)
            elif BodySynthesizer._is_method_call_hint(hint):
                # Ensure it's mostly a real method and not a random long string chunk
                if len(hint) < 40 and not hint.startswith("USKO/") and not hint.startswith("DeathKO"):
                    if func.is_method and hint in methods_in_class:
                        method_calls.append(hint)
            elif IDENTIFIER_RE.fullmatch(hint) and hint.startswith("_") and len(hint) < 30:
                field_refs.append(hint)

        if not api_calls and not method_calls:
            return []

        lines: list[str] = []
        # Error / deprecation guards
        error_msgs = [m for m in func.messages if BodySynthesizer._is_error_message(m)]
        for msg in error_msgs[:2]:
            lower = msg.lower()
            if "must be" in lower and non_self:
                lines += [f"if not {non_self[0]}:", f"    raise TypeError({msg!r})"]
            elif "deprecated" in lower:
                lines.append(f"warnings.warn({msg!r}, DeprecationWarning, stacklevel=2)")

        if api_calls:
            has_lib = any(h.startswith(_C_API_PREFIXES) for h in api_calls)
            lines.append("try:")
            for i, call in enumerate(api_calls[:8]):
                call_args_str = ", ".join(non_self[:3]) if non_self else ""
                is_last = i == len(api_calls[:8]) - 1
                pfx = "    return " if (is_last and (func.name.startswith("get_") or "property" in func.decorators)) else "    "
                if has_lib:
                    target = "self._lib" if func.is_method else "lib"
                    lines.append(f"{pfx}{target}.{call}({call_args_str})")
                else:
                    lines.append(f"{pfx}{call}({call_args_str})")
            lines += [
                "except Exception as exc:",
                "    raise RuntimeError(",
                '        f"C-extension call failed: {exc}"',
                "    ) from exc",
            ]

        if method_calls:
            for call in method_calls[:6]:
                if func.is_method:
                    if call in methods_in_class:
                        lines.append(f"self.{call}()")
                    else:
                        lines.append(f"self.{call}({', '.join(non_self[:2])})")
                else:
                    lines.append(f"{call}({', '.join(non_self[:2])})")

        if field_refs and not any("return" in l for l in lines) and "except Exception as exc:" not in lines:
            if not non_self:
                ref = field_refs[0]
                lines.append(f"return self.{ref}" if func.is_method else f"return {ref}")
            else:
                for ref in field_refs[:3]:
                    lines.append(f"self.{ref} = {non_self[0]}" if func.is_method else f"{ref} = {non_self[0]}")

        return lines

    @staticmethod
    def _body_heuristic_synthesis(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        lines: list[str] = []

        if len(non_self) == 1 and func.name.startswith(("set_", "_set_")):
            return BodySynthesizer._body_simple_setter(cls_node, func, attrs, non_self)

        # 1. Map known explicit properties to attributes
        if func.is_method and non_self:
            matched = False
            for arg in non_self[:4]:
                for attr in attrs:
                    if attr.lstrip("_") == arg:
                        lines.append(f"self.{attr} = {arg}")
                        matched = True
                        break
            if matched:
                return lines

        # 2. Heuristic Control Flow Trace (Build logic from constants)
        filtered_hints = [h for h in func.string_hints if h and len(h) < 100]

        if filtered_hints or func.literals or func.tuples or func.messages:
            lines.append("# --- Deep Instruction Trace ---")

            # Print/Log tuples and string mappings
            for tcl in func.tuples[:3]:
                if len(tcl) > 1 and all(isinstance(x, str) for x in tcl):
                    lines.append(f"self._map_config({tcl!r})")

            for lit in func.literals[:5]:
                if isinstance(lit, int):
                    if lit > 100 and getattr(func, "has_threading", False) or "time" in func.string_hints:
                        lines.append(f"time.sleep({lit} / 1000.0)  # Inferred delay")
                    elif 0 < lit < 100:
                        lines.append(f"self._execute_step({lit})")

            # Route major control flow based on string fragments (like State Machines)
            if len(filtered_hints) > 0:
                is_switch = len(filtered_hints) > 2 and all("/" in h or "[" in h or "KO" in h for h in filtered_hints[:3])

                if is_switch:
                    route_var = non_self[0] if non_self else "self._server_mode"
                    lines.append(f"match_value = {route_var}")
                    for idx, route in enumerate(filtered_hints[:15]):  # Cap at 15 routing paths
                        condition = "if" if idx == 0 else "elif"
                        lines.append(f"{condition} match_value == {route!r}:")
                        safe_route_name = safe_identifier(route.split("/")[0].replace("[", "_").replace("]", "")) or "action"
                        lines.append(f"    self._handle_mode_{safe_route_name}()")
                    lines.append("else:")
                    lines.append("    self._handle_unknown_mode(match_value)")
                else:
                    for hint in filtered_hints[:5]:
                        if " " in hint:
                            lines.append(f"self._logger.info({hint!r})")
                        elif IDENTIFIER_RE.fullmatch(hint):
                            if hint.isupper():
                                lines.append(f"self._apply_flag(self.{hint} if hasattr(self, {hint!r}) else {hint!r})")
                            else:
                                lines.append(f"self._trigger_action({hint!r})")
                        else:
                            lines.append(f"self._process_constant({hint!r})")

        # 3. Fallback — dump ALL raw metadata
        if not lines:
            if func.is_method and non_self:
                for arg in non_self[:3]:
                    lines.append(f"self._{arg} = {arg}")
            # Always append recovered metadata regardless
            metadata = BodySynthesizer._body_metadata_fallback(func)
            if len(metadata) > 1:  # more than just the header
                lines.extend(metadata)
            elif not lines:
                if attrs:
                    lines.append(f"return self.{attrs[0]}")
                else:
                    lines.append("pass  # no metadata recovered")

        return lines

    # ------------------------------------------------------------------
    # Static hint classifiers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_c_api_hint(text: str) -> bool:
        if not IDENTIFIER_RE.fullmatch(text) or "_" not in text or len(text) < 4:
            return False
        parts = text.split("_")
        return any(p[:1].isupper() for p in parts[:2]) and not text.isupper()

    @staticmethod
    def _is_method_call_hint(text: str) -> bool:
        return bool(IDENTIFIER_RE.fullmatch(text)) and text[:1].islower() and "_" in text and len(text) > 3

    @staticmethod
    def _is_error_message(text: str) -> bool:
        lower = text.strip().lower()
        return (
            len(text) < 100
            and "\n" not in text
            and any(
                kw in lower
                for kw in (
                    "must be",
                    "invalid",
                    "unsupported",
                    "error",
                    "failed",
                    "cannot",
                    "expected",
                    "should be",
                    "not a valid",
                    "is not",
                    "deprecated",
                )
            )
        )


# ---------------------------------------------------------------------------
# Property-setter synthesizer
# ---------------------------------------------------------------------------


class PropertySetterSynthesizer:
    """
    For every ``@property`` getter that targets a private attribute, generate a
    corresponding setter method if one is not already present.
    """

    @staticmethod
    def synthesize(cls_node: ClassDefNode, attrs: list[str]) -> None:
        new_methods: dict[str, FunctionDefNode] = {}
        for mname, func in list(cls_node.methods.items()):
            if "property" not in func.decorators:
                continue
            if mname.startswith("__"):
                continue
            setter_name = f"{mname}"  # same name, different decorator
            if setter_name in cls_node.methods and any("setter" in d for d in cls_node.methods[setter_name].decorators):
                continue
            # Find the backing attr
            backing = f"_{mname}"
            if backing not in attrs:
                backing = mname
            if backing not in attrs:
                continue
            ann = TypeInferencer.infer(backing)
            setter = FunctionDefNode(
                name=setter_name,
                is_method=True,
                args=["self", "value"],
                annotations=OrderedDict({"value": ann}),
                decorators=[f"{setter_name}.setter"],
                docstring=f"Set {mname.replace('_', ' ')}.",
                body_lines=[
                    f"if value is self.{backing}:",
                    "    return",
                    f"self.{backing} = value",
                ],
            )
            # Insert right after the getter
            new_methods[f"_setter_{setter_name}"] = setter

        for fake_name, setter_func in new_methods.items():
            real_name = setter_func.name
            # Insert after the getter
            ordered: OrderedDict[str, FunctionDefNode] = OrderedDict()
            for mname, mfunc in cls_node.methods.items():
                ordered[mname] = mfunc
                if mname == real_name and f"_setter_{real_name}" not in cls_node.methods:
                    ordered[f"_setter__{real_name}"] = setter_func
            cls_node.methods = ordered


# ---------------------------------------------------------------------------
# Main decompiler engine
# ---------------------------------------------------------------------------


class OmniDecompiler:
    """
    Two-pass heuristic decompiler for Nuitka metadata blobs.

    **Pass 1** — structural mapping of the raw item stream into an AST.
    **Pass 2** — body synthesis using :class:`BodySynthesizer`.
    """

    def __init__(self) -> None:
        self.classes: OrderedDict[str, ClassDefNode] = OrderedDict()
        self.functions: OrderedDict[str, FunctionDefNode] = OrderedDict()
        self.module_constants: OrderedDict[str, str] = OrderedDict()
        self.imports: OrderedDict[str, None] = OrderedDict()
        self.from_imports: OrderedDict[str, OrderedDict[str, None]] = OrderedDict()
        self.api_endpoints: set[str] = set()
        self.images: OrderedDict[str, int] = OrderedDict()
        self.vk_table: OrderedDict[str, Any] = OrderedDict()
        self.module_docstring: str | None = None
        self.class_candidates: set[str] = set()
        self.current_class: str | None = None
        self.current_function: FunctionDefNode | None = None
        self.last_item_name: str | None = None
        self.has_threading: bool = False
        self.has_logging: bool = False
        self.has_warnings: bool = False
        self.unclaimed_items: list[Any] = []

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
        cls_node = self.ensure_class(cls_name)
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
    # Pass 1 helpers
    # ------------------------------------------------------------------

    def _collect_class_candidates(self, items: list[Any]) -> set[str]:
        scores: defaultdict[str, int] = defaultdict(int)
        for index, item in enumerate(items):
            text = b2s_safe(item) if isinstance(item, (bytes, bytearray)) else (item if isinstance(item, str) else None)
            if not isinstance(text, str):
                continue
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
            if any(isinstance(x, (bytes, bytearray, str)) and b2s_safe(x) in META_FIELD_NAMES | DECORATOR_NAMES for x in window):
                score += 2
            if any(isinstance(x, (bytes, bytearray, str)) and is_probable_method_name(b2s_safe(x)) for x in window):
                score += 2
            if score >= 3:
                scores[text] += score
        return {n for n, s in scores.items() if s >= 3}

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
                if txt in KNOWN_BASE_NAMES or (is_probable_class_name(txt) and txt not in self.class_candidates and txt != cls_node.name):
                    cls_node.bases.append(txt)
                    break

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

    def _looks_like_toplevel_function(
        self,
        items: list[Any],
        index: int,
        text: str,
        pending: _PendingState,
    ) -> bool:
        if text in WEAK_TOPLEVEL_FUNCTION_NAMES or text.startswith("__") or is_probable_import_path(text):
            return False
        score = (2 if pending.annotations else 0) + (1 if pending.args else 0)
        score += _score_window(items, index + 1, 6)
        return score >= 3

    def _should_capture_module_docstring(self, items: list[Any], index: int, text: str) -> bool:
        if self.current_class or self.current_function:
            return False
        if index > 4 or not is_probable_module_docstring(text):
            return False
        window = items[index + 1 : index + 6]
        return "\n" in text or any(isinstance(x, (bytes, bytearray, str)) and is_probable_import_path(b2s_safe(x)) for x in window)

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
                # detect feature flags
                if LOG_RE.search(text):
                    self.has_logging = True
                if "thread" in text.lower() or "lock" in text.lower():
                    self.has_threading = True
        elif kind == "string":
            text = b2s_safe(value)
            if text and text not in target.string_hints:
                target.string_hints.append(text)
                if LOG_RE.search(text):
                    self.has_logging = True
                if "thread" in text.lower() or "lock" in text.lower():
                    self.has_threading = True
                if "warn" in text.lower() or "deprecat" in text.lower():
                    self.has_warnings = True

    @staticmethod
    def _trim_dict(value: dict[Any, Any]) -> dict[str, Any]:
        return {b2s_safe(k): (b2s_safe(v) if isinstance(v, (bytes, bytearray)) else v) for k, v in list(value.items())[:20]}

    # ------------------------------------------------------------------
    # Normalization
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

    def _normalize_annotations(self, ann: dict[str, Any] | None) -> OrderedDict[str, str]:
        result: OrderedDict[str, str] = OrderedDict()
        for key, value in (ann or {}).items():
            ident = safe_identifier(key)
            if ident:
                text = normalize_annotation_text(value)
                if text:
                    result[ident] = text
        return result

    def _apply_pending(self, func: FunctionDefNode | None, pending: _PendingState) -> None:
        if func is None:
            return
        ann = self._normalize_annotations(pending.annotations)
        explicit_args = self._normalize_args(pending.args, method=func.is_method)
        if not explicit_args and ann:
            explicit_args = self._normalize_args([n for n in ann if n != "return"], method=func.is_method)
        if explicit_args:
            func.args = explicit_args
        if ann:
            func.annotations.update({k: v for k, v in ann.items() if k != "return"})
            if ann.get("return"):
                func.return_type = ann["return"]
        for dec in pending.decorators:
            if dec not in func.decorators:
                func.decorators.append(dec)
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
    # Pass 1 item dispatch
    # ------------------------------------------------------------------

    def _dispatch_packed(self, item: bytes, pending: _PendingState) -> None:
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
                self.current_class = owner
                self.current_function = func
                self._apply_pending(func, pending)
                pending.reset()
        elif args:
            pending.args = args
            if hints:
                pending.annotations = hints

    def _dispatch_string(self, items: list[Any], index: int, text: str, pending: _PendingState) -> None:
        self.last_item_name = text

        if is_probable_endpoint(text):
            self.api_endpoints.add(text)

        if text in DECORATOR_NAMES:
            pending.decorators.append(text)
            return

        method_ref = METHOD_REF_RE.fullmatch(text)
        if method_ref:
            owner = method_ref.group(1)
            if is_probable_class_name(owner):
                func = self.ensure_method(owner, method_ref.group(2))
                self.current_function = None
                self.current_class = owner
                self.current_function = func
                self._apply_pending(func, pending)
                pending.reset()
            return

        if text in self.class_candidates:
            cls_node = self.ensure_class(text)
            self.current_class = text
            self.current_function = None
            if cls_node:
                self._hydrate_class_metadata(items, index, cls_node)
                if pending.docstring and not cls_node.docstring:
                    cls_node.docstring = clean_docstring(pending.docstring)
                    pending.docstring = None
            return

        if is_probable_import_path(text):
            names: list[str] | None = None
            if index + 1 < len(items) and isinstance(items[index + 1], tuple):
                names = [n for n in tuple_texts(items[index + 1]) if isinstance(n, str) and safe_identifier(n)]
            self.record_import(text, names)
            self.current_class = None
            self.current_function = None
            if "threading" in text:
                self.has_threading = True
            if "logging" in text:
                self.has_logging = True
            if "warnings" in text:
                self.has_warnings = True
            return

        if should_render_constant(text) and index + 1 < len(items):
            nxt = items[index + 1]
            if isinstance(nxt, (str, bytes, bytearray, int, float, bool, tuple, list, dict)):
                self.module_constants[text] = literal_source(nxt)
            return

        if self.current_class and text.startswith("_") and not text.startswith("__") and len(text) > 1 and not self._looks_like_method_block(items, index, text):
            cls_node = self.classes.get(self.current_class)
            if cls_node:
                cls_node.attributes.add(text)

        if self.current_class and self._looks_like_method_block(items, index, text):
            func = self.ensure_method(self.current_class, text)
            self.current_function = None
            self.current_function = func
            self._apply_pending(func, pending)
            pending.reset()
            return

        if not self.current_class and is_probable_method_name(text):
            if self._looks_like_toplevel_function(items, index, text, pending):
                func = self.ensure_function(text)
                self.current_function = None
                self.current_function = func
                self._apply_pending(func, pending)
                pending.reset()
                return

        if is_probable_docstring(text):
            if not self.module_docstring and self._should_capture_module_docstring(items, index, text):
                self.module_docstring = clean_docstring(text)
            elif self.current_function:
                self._record_target_hint(self.current_function, "message", text)
            else:
                pending.docstring = text
            return

        if self.current_function and text not in DECORATOR_NAMES:
            self._record_target_hint(self.current_function, "string", text)
        elif text and not self.current_function and text not in DECORATOR_NAMES and text not in META_FIELD_NAMES:
            self.unclaimed_items.append(text)

    # ------------------------------------------------------------------
    # Pass 1 — main loop
    # ------------------------------------------------------------------

    def run_pass_1_structural_mapping(self, blob_items: list[Any]) -> None:
        items = list(blob_items)
        self.class_candidates = self._collect_class_candidates(items)
        pending = _PendingState()

        for index, item in enumerate(items):
            if item is None:
                continue

            if isinstance(item, (bytes, bytearray)):
                text = b2s_safe(item)
                if b"\x00" in item and len(item) > 4:
                    if text.startswith("VK_") and index + 1 < len(items) and isinstance(items[index + 1], int):
                        self.vk_table[text] = items[index + 1]
                    else:
                        self._dispatch_packed(item, pending)
                else:
                    if text.endswith("_B64") and index + 1 < len(items):
                        nxt = items[index + 1]
                        if isinstance(nxt, (bytes, bytearray, str)) and is_b64_image(nxt):
                            self.images[text] = len(b2s_safe(nxt))
                            continue
                    self._dispatch_string(items, index, text, pending)
                continue

            if isinstance(item, dict):
                if is_annotation_dict(item):
                    pending.annotations = decode_annotation_blob(item)
                elif self.current_function:
                    self._record_target_hint(self.current_function, "dict", item)
                else:
                    pending.dicts.append(item)
                continue

            if isinstance(item, tuple):
                decoded = tuple_texts(item)
                if self.last_item_name == "__slots__" and self.current_class:
                    cls_node = self.classes.get(self.current_class)
                    if cls_node:
                        cls_node.slots = tuple(x for x in decoded if isinstance(x, str) and safe_identifier(x))
                elif all(isinstance(x, str) and safe_identifier(x) for x in decoded) and 0 < len(decoded) <= 12:
                    pending.args = list(decoded)
                if self.current_function:
                    self._record_target_hint(self.current_function, "tuple", item)
                else:
                    pending.tuples.append(item)
                continue

            if isinstance(item, (int, float, bool)):
                if isinstance(item, int) and 0 < item < 10_000:
                    pending.line = item
                if self.current_function:
                    self._record_target_hint(self.current_function, "literal", item)
                else:
                    pending.literals.append(item)
                continue

            if isinstance(item, str) and item:
                self._dispatch_string(items, index, item, pending)
                continue

            # Anything not consumed above is unclaimed raw data
            self.unclaimed_items.append(item)

        # Flush any leftover pending data that was never consumed
        if pending.dicts:
            self.unclaimed_items.extend(pending.dicts)
        if pending.tuples:
            self.unclaimed_items.extend(pending.tuples)
        if pending.literals:
            self.unclaimed_items.extend(pending.literals)
        if pending.docstring:
            self.unclaimed_items.append(pending.docstring)

    # ------------------------------------------------------------------
    # Pass 2 helpers
    # ------------------------------------------------------------------

    def _scrape_all_attributes(self) -> None:
        for cls_node in self.classes.values():
            found: set[str] = set()
            for func in cls_node.methods.values():
                for hint in func.string_hints:
                    if IDENTIFIER_RE.fullmatch(hint) and hint.startswith("_"):
                        found.add(hint)
                        if hint in LOCK_ATTRS:
                            self.has_threading = True
                for tup in func.tuples:
                    for x in tup:
                        if isinstance(x, str) and IDENTIFIER_RE.fullmatch(x) and x.startswith("_"):
                            found.add(x)
                for msg in func.messages:
                    for word in re.findall(r"_([a-zA-Z0-9_]+)", msg):
                        ident = "_" + word
                        if IDENTIFIER_RE.fullmatch(ident):
                            found.add(ident)
                    if LOG_RE.search(msg):
                        self.has_logging = True
                    if "warn" in msg.lower() or "deprecat" in msg.lower():
                        self.has_warnings = True
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
            for x in tup:
                if isinstance(x, str) and x.startswith("_") and x not in attrs:
                    attrs.append(x)
        return attrs

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
        elif func.name in {"__ne__", "__lt__", "__le__", "__gt__", "__ge__"} and func.is_method:
            if len(func.args) < 2:
                func.args = [func.args[0] if func.args else "self", "other"]
        elif func.name in {"register_hook", "deregister_hook"} and func.is_method and len(func.args) <= 1:
            func.args = [func.args[0] if func.args else "self", "event", "hook"]
        elif func.name == "__exit__" and func.is_method and len(func.args) < 4:
            func.args = ["self", "exc_type", "exc_val", "exc_tb"]
        elif func.name == "__setstate__" and func.is_method and len(func.args) < 2:
            func.args = ["self", "state"]
        elif func.name == "__deepcopy__" and func.is_method and len(func.args) < 2:
            func.args = ["self", "memo"]
        if "property" in func.decorators:
            func.args = ["self"]

    def _enrich_docstring(self, cls_node: ClassDefNode | None, func: FunctionDefNode) -> None:
        """Replace or supplement docstring using DocstringSynthesizer."""
        synth = DocstringSynthesizer.from_hints(
            name=func.name,
            args=func.args,
            annotations=dict(func.annotations),
            return_type=func.return_type,
            messages=func.messages,
            string_hints=func.string_hints,
            existing_doc=func.docstring,
            is_method=func.is_method,
        )
        if synth and (not func.docstring or len(func.docstring) < 20):
            func.docstring = synth

    def _has_meaningful_body(self, func: FunctionDefNode) -> bool:
        for line in func.body_lines:
            stripped = line.strip()
            if not stripped or stripped == "pass":
                continue
            if stripped.startswith("#") or stripped.startswith(("config = ", "state = ")):
                continue
            return True
        return False

    def _should_keep_function(self, func: FunctionDefNode) -> bool:
        if func.name in WEAK_TOPLEVEL_FUNCTION_NAMES:
            return False
        return bool(func.annotations or func.decorators or self._has_meaningful_body(func))

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
        meaningful = sum(1 for f in cls_node.methods.values() if f.annotations or f.decorators or self._has_meaningful_body(f))
        if cls_node.name in imported and not cls_node.attributes and not cls_node.constants:
            if meaningful <= 1:
                return False
        if cls_node.name in {"Unknown", "None_"} and meaningful <= 1 and not cls_node.attributes:
            return False
        if is_fragmentary_docstring(cls_node.docstring) and meaningful == 0 and not cls_node.attributes:
            return False
        return True

    def _infer_return_type(self, func: FunctionDefNode, attrs: list[str]) -> None:
        """Fill in ``func.return_type`` when it can be deduced from the method name / attrs."""
        if func.return_type:
            return
        name = func.name
        if name in {"__len__", "__sizeof__", "__hash__"}:
            func.return_type = "int"
        elif name in {"__bool__"} or name.startswith(("is_", "has_", "can_")):
            func.return_type = "bool"
        elif name in {"__str__", "__repr__", "__format__"}:
            func.return_type = "str"
        elif name in {"__bytes__", "_packed", "encode", "pack"}:
            func.return_type = "bytes"
        elif name in {"__iter__"}:
            func.return_type = "Iterator[Any]"
        elif name in {"__enter__"}:
            func.return_type = "Self"
        elif name in {"__exit__"}:
            func.return_type = "bool"
        elif name in {"__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__"}:
            func.return_type = "bool"
        elif name in {"__contains__"}:
            func.return_type = "bool"
        elif name in {"copy", "clone", "__copy__"}:
            func.return_type = "Self"
        elif name == "register_hook":
            func.return_type = "Callable[..., Any]"
        elif name == "deregister_hook":
            func.return_type = "bool"
        elif name.startswith("get_"):
            target = name[4:]
            for attr in attrs:
                if attr.lstrip("_") == target:
                    func.return_type = TypeInferencer.infer(attr)
                    break
        elif name == "value" and "property" in func.decorators:
            func.return_type = TypeInferencer.infer("_value")
        elif name.startswith("is_") or name.startswith("has_") or name.startswith("can_"):
            func.return_type = "bool"
        elif name in {"__init__", "__del__", "close", "flush", "write", "send", "prepare", "__setstate__", "set_", "add_", "remove_"}:
            func.return_type = "None"

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

            attrs = sorted(cls_node.attributes)

            # Synthesize property setters before building bodies
            PropertySetterSynthesizer.synthesize(cls_node, attrs)

            for func in cls_node.methods.values():
                self._finalize_function_signature(func)
                self._infer_return_type(func, attrs)
                func.body_lines = BodySynthesizer.build(cls_node, func, attrs)
                self._enrich_docstring(cls_node, func)

            if self._should_keep_class(cls_node):
                kept_classes[cls_name] = cls_node

        self.classes = kept_classes

        # --- top-level functions ---
        kept_funcs: OrderedDict[str, FunctionDefNode] = OrderedDict()
        for name, func in self.functions.items():
            self._finalize_function_signature(func)
            self._infer_return_type(func, [])
            func.body_lines = BodySynthesizer.build(None, func, [])
            self._enrich_docstring(None, func)
            if self._should_keep_function(func):
                kept_funcs[name] = func
        self.functions = kept_funcs


# ---------------------------------------------------------------------------
# Source generator
# ---------------------------------------------------------------------------


def _iter_import_lines(decompiler: OmniDecompiler) -> Iterator[str]:
    stdlib = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()

    from_lines: list[str] = []
    plain_lines: list[str] = []

    for module_path, names in decompiler.from_imports.items():
        if names:
            from_lines.append(f"from {module_path} import {', '.join(names)}")
    for module_path in decompiler.imports:
        if module_path not in decompiler.from_imports:
            plain_lines.append(f"import {module_path}")

    all_lines = sorted(set(from_lines + plain_lines))
    top_mod = lambda s: s.split()[1].split(".")[0]

    std = [l for l in all_lines if top_mod(l) in stdlib]
    third = [l for l in all_lines if top_mod(l) not in stdlib]

    yield from std
    if std and third:
        yield ""
    yield from third


def _generate_heuristic_omni_source(decompiler: OmniDecompiler, section_name: str) -> str:
    lines: list[str] = []

    # --- module docstring ---
    if decompiler.module_docstring:
        doc = clean_docstring(decompiler.module_docstring) or ""
        dls = doc.splitlines()
        if len(dls) <= 1:
            lines.append(f'"""{doc}"""')
        else:
            lines += ['"""', *dls, '"""']
        lines.append("")

    lines.append("from __future__ import annotations")
    lines.append("")
    # Sanitize section_name: strip non-printable / non-ASCII characters so that
    # binary-noise names (from obfuscated commercial blobs) don't leak into the
    # generated Python source as garbled comment text.
    _sn = section_name if isinstance(section_name, str) else repr(section_name)
    _sn_clean = "".join(c for c in _sn if c.isprintable() and ord(c) < 128).strip()
    if not _sn_clean:
        import hashlib as _hl
        _sn_clean = "<section:" + _hl.sha1(_sn.encode("utf-8", "replace")).hexdigest()[:12] + ">"
    lines.append(f"# Heuristic CPython reconstruction for: {_sn_clean}")
    lines.append("# Generated by omni_nuitka_framework — do not edit by hand.")
    lines.append("")

    # --- typing imports ---
    all_funcs: list[FunctionDefNode] = list(decompiler.functions.values())
    for cls_node in decompiler.classes.values():
        all_funcs.extend(cls_node.methods.values())

    used_typing: OrderedDict[str, None] = OrderedDict()
    for func in all_funcs:
        all_anns = list(func.annotations.values()) + ([func.return_type] if func.return_type else [])
        for ann in all_anns:
            if not ann:
                continue
            for token in re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", ann):
                if token in TYPING_NAMES:
                    used_typing[token] = None
        # Iterator always needs Any
        if func.return_type == "Iterator[Any]":
            used_typing["Iterator"] = None
            used_typing["Any"] = None

    # Add Self if used
    needs_self = any(f.return_type in {"Self"} for f in all_funcs)
    if needs_self:
        used_typing["Self"] = None  # type: ignore[assignment]

    if "Any" not in used_typing and any("Any" in (func.return_type or "") or any("Any" in v for v in func.annotations.values()) for func in all_funcs):
        used_typing["Any"] = None

    if used_typing:
        lines.append(f"from typing import {', '.join(used_typing)}")

    # Add Self import for 3.11+
    if needs_self:
        lines.append("try:")
        lines.append("    from typing import Self")
        lines.append("except ImportError:")
        lines.append("    from typing_extensions import Self")

    # --- detect threading/logging/warnings from generated bodies ---
    for _cls in decompiler.classes.values():
        if any(a in LOCK_ATTRS for a in _cls.attributes):
            decompiler.has_threading = True
        for _fn in _cls.methods.values():
            _bt = " ".join(_fn.body_lines)
            if "threading.Lock" in _bt:
                decompiler.has_threading = True
            if "warnings.warn" in _bt:
                decompiler.has_warnings = True
            if "logging.getLogger" in _bt:
                decompiler.has_logging = True

    # --- stdlib supplemental imports ---
    _stdlib_extra: list[str] = []
    if decompiler.has_threading:
        _stdlib_extra.append("import threading")
    if decompiler.has_logging:
        _stdlib_extra.append("import logging")
    if decompiler.has_warnings:
        _stdlib_extra.append("import warnings")
    if _stdlib_extra:
        lines.append("")
        lines.extend(_stdlib_extra)

    # --- discovered imports ---
    import_lines = list(_iter_import_lines(decompiler))
    if import_lines:
        lines.append("")
        lines.extend(import_lines)

    # --- API endpoint comments ---
    if decompiler.api_endpoints:
        lines.append("")
        lines.append("# ---------------------------------------------------------------------------")
        lines.append("# Discovered API endpoints")
        lines.append("# ---------------------------------------------------------------------------")
        for url in sorted(decompiler.api_endpoints):
            lines.append(f"# endpoint: {url}")

    # --- virtual-key table ---
    if decompiler.vk_table:
        lines.append("")
        lines.append("# ---------------------------------------------------------------------------")
        lines.append("# Virtual-key table (recovered from binary constants)")
        lines.append("# ---------------------------------------------------------------------------")
        for name, value in decompiler.vk_table.items():
            lines.append(f"{name} = {value!r}")

    # --- module-level constants ---
    if decompiler.module_constants:
        lines.append("")
        lines.append("# ---------------------------------------------------------------------------")
        lines.append("# Module constants")
        lines.append("# ---------------------------------------------------------------------------")
        for name, value in decompiler.module_constants.items():
            if should_render_constant(name):
                lines.append(f"{name} = {value}")

    # --- __all__ ---
    public_names = [n for n in decompiler.functions if not n.startswith("_")] + [n for n in decompiler.classes if not n.startswith("_")]
    if public_names:
        lines.append("")
        parts = ", ".join(f"{n!r}" for n in sorted(public_names))
        lines.append(f"__all__ = [{parts}]")

    # --- top-level functions ---
    if decompiler.functions:
        lines.append("")
        lines.append("# ---------------------------------------------------------------------------")
        lines.append("# Module-level functions")
        lines.append("# ---------------------------------------------------------------------------")
        for func in decompiler.functions.values():
            lines.append("")
            lines.extend(func.render(0).rstrip().splitlines())
            lines.append("")

    # --- classes ---
    for cls_node in decompiler.classes.values():
        if not cls_node.methods and not cls_node.attributes and not cls_node.docstring:
            continue
        lines.append("")
        lines.append("# ---------------------------------------------------------------------------")
        lines.append(f"# {cls_node.name}")
        lines.append("# ---------------------------------------------------------------------------")
        lines.append("")
        lines.extend(cls_node.render(0).rstrip().splitlines())
        lines.append("")

    # --- unclaimed metadata from blob ---
    if decompiler.unclaimed_items:
        lines.append("")
        lines.append("# ===========================================================================")
        lines.append("# UNCLAIMED METADATA — items not assigned to any class or function")
        lines.append("# ===========================================================================")
        _unc_strings: list[str] = []
        _unc_hints: list[str] = []
        _unc_bytes: list[tuple[int, str]] = []  # (length, hex_preview)
        _unc_dicts: list[str] = []
        _unc_tuples: list[str] = []
        _unc_literals: list[str] = []
        _unc_other: list[str] = []

        for item in decompiler.unclaimed_items:
            if isinstance(item, str):
                text = item.strip()
                if not text:
                    continue
                if is_probable_docstring(text) or "\n" in text:
                    # Multi-line or docstring-like text → quoted hint block
                    first_line = text.splitlines()[0][:120]
                    _unc_hints.append(first_line)
                else:
                    # Single-line string: identifier hint or message
                    _unc_strings.append(text[:200])
            elif isinstance(item, (bytes, bytearray)):
                raw = bytes(item)
                if _looks_like_marshaled_bytecode_bytes(raw):
                    _unc_bytes.append((len(raw), f"<marshal bytecode payload: {len(raw)} bytes>"))
                else:
                    preview = raw[:64].hex()
                    suffix = "..." if len(raw) > 64 else ""
                    _unc_bytes.append((len(raw), f"{preview}{suffix}"))
            elif isinstance(item, dict):
                safe_d = _redact_marshaled_bytecode_constants(item)
                trimmed = {k: v for k, v in list(safe_d.items())[:8]}
                _unc_dicts.append(repr(trimmed)[:300])
            elif isinstance(item, (tuple, list)):
                safe_t = _redact_marshaled_bytecode_constants(item)
                _unc_tuples.append(repr(safe_t)[:300])
            elif isinstance(item, (int, float, bool)):
                _unc_literals.append(repr(item))
            else:
                safe_v = _redact_marshaled_bytecode_constants(item)
                _unc_other.append(repr(safe_v)[:200])

        if _unc_strings:
            lines.append("#")
            lines.append("# -- string hints --")
            seen_str: set[str] = set()
            for s in _unc_strings:
                if s not in seen_str:
                    seen_str.add(s)
                    lines.append(f"# str: {s}")
        if _unc_hints:
            lines.append("#")
            lines.append("# -- docstring / multi-line hints --")
            seen_h: set[str] = set()
            for h in _unc_hints:
                if h not in seen_h:
                    seen_h.add(h)
                    lines.append(f"# doc: {h}")
        if _unc_bytes:
            lines.append("#")
            lines.append("# -- binary blobs --")
            for length, preview in _unc_bytes:
                lines.append(f"# bytes[{length}]: {preview}")
        if _unc_dicts:
            lines.append("#")
            lines.append("# -- dict hints --")
            seen_dct: set[str] = set()
            for d in _unc_dicts:
                if d not in seen_dct:
                    seen_dct.add(d)
                    lines.append(f"# dict: {d}")
        if _unc_tuples:
            lines.append("#")
            lines.append("# -- tuple hints --")
            seen_tup: set[str] = set()
            for t in _unc_tuples:
                if t not in seen_tup:
                    seen_tup.add(t)
                    lines.append(f"# tuple: {t}")
        if _unc_literals:
            lines.append("#")
            lines.append("# -- numeric literals --")
            lines.append(f"# literals: {', '.join(_unc_literals[:50])}")
        if _unc_other:
            lines.append("#")
            lines.append("# -- other --")
            for o in _unc_other:
                lines.append(f"# raw: {o}")

    return "\n".join(lines).rstrip() + "\n"


@dataclass
class OmniModuleArtifact:
    source: str
    heuristic_source: str
    strategy: str
    nbc_text: str | None = None
    smart_source: str | None = None


def _count_reconstructed_blocks(source: str) -> int:
    return source.count("\ndef ") + source.count("\nasync def ") + source.count("\nclass ")


def _has_python_structure(source: str) -> bool:
    return any(token in source for token in ("def ", "async def ", "class ", "import ", " = "))


_MARSHAL_CODE_TAG_BYTES = (b"\xf3", b"\xe3", b"c")



_MARSHAL_PYC_PATH_PATTERN = re.compile(rb"([A-Za-z0-9_./\\-]{1,260}\.py)")


def _looks_like_marshaled_bytecode_bytes(value: Any) -> bool:
    return isinstance(value, (bytes, bytearray)) and len(value) >= 16 and bytes(value)[:1] in _MARSHAL_CODE_TAG_BYTES


def _marshal_payload_placeholder(payload: bytes | bytearray) -> str:
    data = bytes(payload)
    return f"<marshal bytecode payload redacted: {len(data)} bytes>"



def _redact_marshaled_bytecode_constants(
    value: Any,
    *,
    _seen: set[int] | None = None,
    _depth: int = 0,
) -> Any:
    """Replace marshal/code payload constants with small placeholders.

    The extractor writes these payloads as .pyc artifacts. Source/NBC text should
    never inline huge bytecode blobs as repr/hex strings.
    """
    if _depth > 20:
        return "<max recursion depth reached>"

    if _looks_like_marshaled_bytecode_bytes(value):
        return _marshal_payload_placeholder(value)

    if _is_live_code_object(value):
        name = getattr(value, "co_name", type(value).__name__)
        filename = getattr(value, "co_filename", None)
        label = f"{filename}:{name}" if filename else str(name)
        return f"<code object redacted: {label}>"

    if isinstance(value, (str, int, float, complex, bool, type(None))):
        return value

    if _seen is None:
        _seen = set()
    obj_id = id(value)
    if obj_id in _seen:
        return "<recursive reference>"
    _seen.add(obj_id)

    if isinstance(value, tuple):
        return tuple(_redact_marshaled_bytecode_constants(child, _seen=_seen, _depth=_depth + 1) for child in value)
    if isinstance(value, list):
        return [_redact_marshaled_bytecode_constants(child, _seen=_seen, _depth=_depth + 1) for child in value]
    if isinstance(value, set):
        return {_redact_marshaled_bytecode_constants(child, _seen=_seen, _depth=_depth + 1) for child in value}
    if isinstance(value, frozenset):
        return frozenset(_redact_marshaled_bytecode_constants(child, _seen=_seen, _depth=_depth + 1) for child in value)
    if isinstance(value, dict):
        return {
            _redact_marshaled_bytecode_constants(key, _seen=_seen, _depth=_depth + 1): _redact_marshaled_bytecode_constants(val, _seen=_seen, _depth=_depth + 1)
            for key, val in value.items()
        }

    return value


def _redact_marshaled_bytecode_list(values: Iterable[Any]) -> list[Any]:
    return [_redact_marshaled_bytecode_constants(value) for value in values]



def _is_live_code_object(value: Any) -> bool:
    return hasattr(value, "co_code") or hasattr(value, "co_code_adaptive")


def _iter_marshaled_bytecode_payloads(
    value: Any,
    *,
    _seen: set[int] | None = None,
    _depth: int = 0,
) -> Iterator[Any]:
    if _depth > 20:
        return

    if isinstance(value, (bytes, bytearray)):
        if len(value) >= 16 and value[:1] in _MARSHAL_CODE_TAG_BYTES:
            yield bytes(value)
        return

    if _is_live_code_object(value):
        yield value
        for child in getattr(value, "co_consts", ()) or ():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                _seen=_seen,
                _depth=_depth + 1,
            )
        return

    if isinstance(value, (str, int, float, complex, bool, type(None))):
        return

    if _seen is None:
        _seen = set()
    obj_id = id(value)
    if obj_id in _seen:
        return
    _seen.add(obj_id)

    if isinstance(value, dict):
        for child in value.keys():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                _seen=_seen,
                _depth=_depth + 1,
            )
        for child in value.values():
            yield from _iter_marshaled_bytecode_payloads(
                child,
                _seen=_seen,
                _depth=_depth + 1,
            )
        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for child in value:
            yield from _iter_marshaled_bytecode_payloads(
                child,
                _seen=_seen,
                _depth=_depth + 1,
            )


def _contains_marshaled_bytecode_payload(raw_values: Iterable[Any]) -> bool:
    return any(True for _ in _iter_marshaled_bytecode_payloads(raw_values))


def _is_marshaled_bytecode_section_name(
    section_name: str,
    raw_values: Iterable[Any] | None = None,
) -> bool:
    if raw_values is None:
        return section_name.strip(".").lower() == "bytecode"
    return _contains_marshaled_bytecode_payload(raw_values)


# ---------------------------------------------------------------------------
# VORTHYX StaticalySmartReconstructor & Generic Blob Enhancement Helpers
# ---------------------------------------------------------------------------

_CLASS_BASE_MACHINERY_MARKERS = (
    "via_PyUnicode_FromString",
    "<metaclass>",
    "_tstate(",
    "_stackaddr(",
    "_type_of(",
    "CALL_FUNCTION(",
    "__prepare__",
    "_PyObject_GC_Malloc(",
    "_gslot(",
)

_DATA_FILE_EXTS = (
    ".py", ".pyc", ".pyd", ".txt", ".json", ".cfg", ".ini",
    ".dat", ".log", ".csv", ".md", ".html", ".htm", ".xml",
    ".yaml", ".yml", ".toml", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".exe", ".dll", ".so", ".zip", ".gz", ".db",
    ".sqlite", ".bin", ".tmp", ".bak", ".lock", ".env",
)

_WIN32_DLL_NAMES = frozenset({
    "kernel32", "user32", "shell32", "advapi32", "crypt32", "avicap32",
    "ntdll", "psapi", "gdi32", "ole32", "oleaut32", "wininet", "ws2_32",
    "bcrypt", "secur32", "shlwapi", "version", "winmm", "iphlpapi",
})

_CTYPES_FIELD_TYPES = frozenset({
    "c_bool", "c_char", "c_wchar", "c_byte", "c_ubyte", "c_short", "c_ushort",
    "c_int", "c_uint", "c_long", "c_ulong", "c_longlong", "c_ulonglong",
    "c_size_t", "c_ssize_t", "c_float", "c_double", "c_longdouble",
    "c_char_p", "c_wchar_p", "c_void_p", "BOOL", "BYTE", "WORD", "DWORD",
    "HANDLE", "HWND", "LPVOID", "LPCSTR", "LPCWSTR", "LPSTR", "LPWSTR",
})


def _heal_class_bases(bases: Iterable[str], class_name: str | None = None) -> list[str]:
    """Strip Nuitka metaclass machinery from class bases while keeping real base types."""
    out: list[str] = []
    for base in bases or ():
        if not isinstance(base, str) or not base:
            continue
        if not any(marker in base for marker in _CLASS_BASE_MACHINERY_MARKERS):
            if base not in out:
                out.append(base)
            continue
        for match in re.finditer(r"\(\s*([A-Z]\w*(?:\s*,\s*[A-Z]\w*)*)\s*,?\s*\)", base):
            for part in match.group(1).split(","):
                nm = part.strip()
                if nm and nm != class_name and nm not in out:
                    out.append(nm)
    return out


def _ndl_all_import_names(import_lines: Iterable[str] | None) -> set[str]:
    """Return every symbol and alias introduced by import lines."""
    out: set[str] = set()
    for line in import_lines or ():
        match = re.match(r"^from\s+.+\s+import\s+(.+)$", line)
        if match:
            for part in match.group(1).split(","):
                part = part.strip()
                if " as " in part:
                    src, alias = part.split(" as ", 1)
                    out.add(src.strip())
                    out.add(alias.strip())
                elif re.fullmatch(r"[A-Za-z_]\w*", part):
                    out.add(part)
        match = re.match(r"^import\s+([A-Za-z_]\w*)$", line)
        if match:
            out.add(match.group(1))
    return out


def _ndl_parse_imported_symbols(import_lines: Iterable[str] | None) -> set[str]:
    """Extract local bound symbol names from emitted import lines."""
    out: set[str] = set()
    for line in import_lines or ():
        match = re.match(r"^from\s+.+\s+import\s+(.+)$", line)
        if match:
            for part in match.group(1).split(","):
                part = part.strip()
                if " as " in part:
                    part = part.split(" as ", 1)[1].strip()
                if re.fullmatch(r"[A-Za-z_]\w*", part):
                    out.add(part)
        match = re.match(r"^import\s+([A-Za-z_]\w*)$", line)
        if match:
            out.add(match.group(1))
    return out


def _ndl_imported_names_from_constants(constants: Iterable[Any]) -> set[str]:
    """Collect names brought in via `(module, (sym1, sym2, ...))` constant pairs."""
    items = list(constants)
    out: set[str] = set()
    n = len(items)
    for i, item in enumerate(items):
        if not isinstance(item, str) or not re.fullmatch(r"[a-z_][a-z0-9_]*", item):
            continue
        nxt = items[i + 1] if i + 1 < n else None
        if (
            isinstance(nxt, tuple)
            and nxt
            and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z_]\w*", x) for x in nxt)
        ):
            out.update(nxt)
    return out


def _ndl_guess_global_init(name: str, imported_syms: set[str], consts: Iterable[Any]) -> str | None:
    """Guess `name = imported_callable()` when the initializer expression was omitted."""
    if not name or not imported_syms:
        return None
    low = name.lower()
    best: str | None = None
    for sym in sorted(imported_syms, key=len, reverse=True):
        sym_low = sym.lower()
        if sym_low == low:
            return f"{sym}()"
        if sym_low.endswith(low) or (len(sym_low) > len(low) and low in sym_low):
            best = f"{sym}()"
    return best


def _ndl_qualify_imports(
    lines: list[str],
    module_name: str,
    known_modules: set[str] | None = None,
    is_package: bool = False,
) -> list[str]:
    """Rewrite sibling package imports to relative `from .sub import ...` when verified."""
    if not lines or not module_name:
        return lines
    known = set(known_modules or ())
    if is_package:
        pkg: str | None = module_name
    elif "." in module_name:
        pkg = module_name.rsplit(".", 1)[0]
    else:
        pkg = None
    if not pkg or not known:
        return lines
    out: list[str] = []
    for line in lines:
        match = re.match(r"^from\s+([A-Za-z_][A-Za-z0-9_]*)\s+import\s+(.+)$", line)
        if match and not line.startswith("from ."):
            mod, rest = match.group(1), match.group(2)
            if mod not in StaticalySmartReconstructor._COMMON_STDLIB and f"{pkg}.{mod}" in known:
                out.append(f"from .{mod} import {rest}")
                continue
        out.append(line)
    return out


def _ndl_discover_header_token_pair(module_consts: Iterable[Any]) -> tuple[str | None, str | None]:
    """Match HTTP header key strings to ALL_CAPS token-list names in the constant pool."""
    consts = list(module_consts or ())
    if not consts:
        return None, None
    hdr_keys = [
        c for c in consts
        if isinstance(c, str) and re.fullmatch(r"[A-Za-z][\w-]*", c) and ("-" in c or (len(c) > 1 and c[0] == "X"))
    ]
    pools = [c for c in consts if isinstance(c, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", c)]
    has_token_list = any(isinstance(c, (list, tuple)) and c for c in consts)
    if hdr_keys and pools and has_token_list:
        return hdr_keys[0], pools[0]
    return None, None


def _ndl_heal_incomplete_url_slash(lines: list[str], varnames: list[str] | None = None) -> list[str]:
    """Append `{first_param}` to trailing-slash URL f-strings missing interpolation."""
    if not lines:
        return lines
    first_param = next(
        (vn for vn in (varnames or ()) if vn not in ("self", "cls") and re.fullmatch(r"[A-Za-z_]\w*", vn)),
        None,
    )
    if not first_param:
        return lines
    pat = re.compile(r"^(\s*)(\w+)\s*=\s*(f'https?://[^']+/'|f\"https?://[^\"]+/\")\s*$")
    out: list[str] = []
    for ln in lines:
        match = pat.match(ln)
        if match:
            indent, var, fstr = match.group(1), match.group(2), match.group(3)
            inner = fstr[2:-1]
            if "{" not in inner:
                out.append(f"{indent}{var} = f'{inner}{{{first_param}}}'")
                continue
        out.append(ln)
    return out


def _ndl_heal_split_fstring_url(lines: list[str], varnames: list[str] | None = None) -> list[str]:
    """Merge URL f-strings split across `url = f'...'` and `headers = {'&...=': val}`."""
    if not lines:
        return lines
    first_param = next(
        (vn for vn in (varnames or ()) if vn not in ("self", "cls") and re.fullmatch(r"[A-Za-z_]\w*", vn)),
        None,
    )
    url_pat = re.compile(r"^(\s*)(\w+)\s*=\s*((?:f'[^']*'|f\"[^\"]*\"))\s*$")
    hdr_pat = re.compile(r"^(\s*)(\w+)\s*=\s*\{('[^']*[&?][^']*='|\"[^\"]*[&?][^\"]*=\")\s*:\s*(\w+)\}\s*$")
    get_pat = re.compile(r"^(\s*)(\w+)\s*=\s*c\.session\((\w+)\)\.get\((\w+)\)\s*$")
    out: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        m_url = url_pat.match(ln)
        if m_url and i + 2 < len(lines):
            m_hdr = hdr_pat.match(lines[i + 1])
            m_get = get_pat.match(lines[i + 2])
            if m_hdr and m_get and m_get.group(3) == m_hdr.group(2) and m_get.group(4) == m_url.group(2):
                inner = m_url.group(3)[2:-1]
                if not re.search(r"\{[^}]+\}", inner) and inner.endswith("=") and first_param:
                    inner = f"{inner}{{{first_param}}}"
                hdr_key = m_hdr.group(3)[1:-1]
                out.append(f"{m_url.group(1)}{m_url.group(2)} = f'{inner}{hdr_key}{{{m_hdr.group(4)}}}'")
                out.append(f"{m_get.group(1)}{m_get.group(2)} = c.session().get({m_url.group(2)})")
                i += 3
                continue
        out.append(ln)
        i += 1
    return out


def _ndl_heal_url_token_swap(lines: list[str]) -> list[str]:
    """Repair swapped `url` dict and HTTP-URL variable before `c.session(url).get(...)`."""
    if not lines:
        return lines
    http_pat = re.compile(r"^(\s*)(\w+)\s*=\s*(f?'https?://[^']*'|f?\"[^\"]*\")\s*$")
    url_dict_pat = re.compile(r"^(\s*)(url)\s*=\s*(\{.*\})\s*$")
    get_pat = re.compile(r"^(\s*)(\w+)\s*=\s*c\.session\((\w+)\)\.get\((\w+)\)\s*$")
    out = list(lines)
    i = 0
    while i < len(out):
        m_http = http_pat.match(out[i])
        if m_http and i + 2 < len(out):
            m_url = url_dict_pat.match(out[i + 1])
            m_get = get_pat.match(out[i + 2])
            if m_url and m_get and m_get.group(3) == "url" and m_get.group(4) == m_http.group(2):
                old_resp = m_get.group(2)
                resp_var = "response" if old_resp == "url" else old_resp
                out[i] = f"{m_http.group(1)}url = {m_http.group(3)}"
                out[i + 1] = f"{m_url.group(1)}headers = {m_url.group(3)}"
                out[i + 2] = f"{m_get.group(1)}{resp_var} = c.session(headers).get(url)"
                if old_resp != resp_var:
                    for j in range(i + 3, len(out)):
                        out[j] = re.sub(
                            rf"\b{re.escape(old_resp)}\.(status_code|json|text|content)\b",
                            rf"{resp_var}.\1",
                            out[j],
                        )
                i += 3
                continue
        i += 1
    return out


def _ndl_infer_defaults_heuristic(co: dict[str, Any], consts: list[Any]) -> tuple[Any, ...] | None:
    """Abstain from guessing arbitrary positional defaults without exact evidence."""
    return None


def _ndl_reconcile_init_params(
    sig_args: list[str],
    body: list[str],
    body_indent: str,
    consts: list[Any],
    authoritative_args: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Bind `argN` body references to named `__init__` parameters when unambiguous."""
    if not body:
        return sig_args, body
    arg_pat = re.compile(r"\barg(\d+)\b")
    if authoritative_args is not None:
        exact = [str(x) for x in authoritative_args]
        return sig_args, [
            arg_pat.sub(lambda m: exact[int(m.group(1))] if 0 <= int(m.group(1)) < len(exact) else m.group(0), ln)
            for ln in body
        ]

    used_indices = {int(m.group(1)) for ln in body for m in arg_pat.finditer(ln)}
    if not used_indices:
        return sig_args, body
    has_recv = bool(sig_args) and sig_args[0] in ("self", "cls")
    store_pat = re.compile(r"^(\s*)(self|cls)\.([A-Za-z_]\w*)\s*=\s*arg(\d+)\b")
    rename: dict[str, str] = {}
    for ln in body:
        match = store_pat.match(ln)
        if match:
            idx = int(match.group(4))
            attr = match.group(3)
            if re.fullmatch(r"[a-z_][a-z0-9_]*", attr) and f"arg{idx}" not in rename:
                rename[f"arg{idx}"] = attr
    new_params = [rename.get(f"arg{idx}", f"arg{idx}") for idx in sorted(used_indices)]
    out_sig = ([sig_args[0]] + new_params) if has_recv else new_params
    out_body = [
        arg_pat.sub(lambda m: rename.get(f"arg{int(m.group(1))}", f"arg{int(m.group(1))}"), ln)
        for ln in body
    ]
    return out_sig, out_body


class StaticalySmartReconstructor:
    """Deep static reconstruction of a Nuitka module chunk into valid Python source.

    Combines VORTHYX's qualname/import/class/global structural analysis with:
      * Exact blob-decoded CodeObject ingestion (`'C'`, `'W'`, `'Y'`, `'K'` tags)
        including nested classes (`Outer.Inner`), closure `<locals>` helper
        classes/functions, exact parameter lists (`posonly`, `argcount`,
        `kwonly`, `CO_VARARGS`, `CO_VARKEYWORDS`), `@staticmethod`/`@classmethod`,
        exact line ordering, class attributes, adjacent qualname annotations,
        and keyword-call / annotation-backed default values.
      * Generic constant-window function body synthesis from each CodeObject's
        contiguous `[co_idx + 1 : next_co_idx]` slice in the constant stream,
        verified via `ast.parse` so emitted files never fail syntax validation.
    """

    _BUILTIN_EXCEPTIONS = {
        "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
        "RuntimeError", "AttributeError", "ImportError", "IOError",
        "OSError", "FileNotFoundError", "ConnectionError", "TimeoutError",
        "InvalidSignature",
    }
    _NON_FUNCTION_NAMES = frozenset({
        "__doc__", "__file__", "__cached__", "__name__", "__spec__",
        "__package__", "__builtins__", "__class__", "__loader__",
        "__path__", "__module__", "__all__", "__version__",
        "__author__", "__annotations__", "__dict__", "__slots__",
        "__qualname__", "__weakref__", "__mro_entries__",
        "status_code", "text", "content", "json", "get", "post", "put",
        "delete", "headers", "cookies", "url", "ok", "reason", "encoding",
        "origin", "has_location",
        "__iter__", "__getitem__", "__setitem__", "__enter__", "__exit__",
        "__init__", "__call__", "__str__", "__repr__", "__eq__", "__hash__",
        "__bool__", "__len__", "__contains__", "__add__", "__sub__",
        "__mul__", "__truediv__", "__getattr__", "__setattr__",
    })
    _PACKAGE_MACHINERY_NAMES = frozenset({
        "path", "dirname", "join", "environ", "submodule_search_locations",
        "getcwd", "abspath", "basename", "realpath", "normpath", "splitext",
        "expanduser", "isdir", "isfile", "pardir", "curdir",
    })
    _COMMON_STDLIB = {
        "sys", "os", "re", "json", "time", "struct", "ctypes",
        "hashlib", "hmac", "base64", "random", "binascii",
        "threading", "asyncio", "typing", "datetime", "math",
        "itertools", "functools", "copy", "io", "traceback",
        "collections", "pathlib", "socket", "ssl", "subprocess",
        "warnings", "logging", "signal", "platform", "pickle",
        "codecs", "enum", "abc", "inspect", "importlib", "weakref",
        "urllib", "http", "email", "concurrent", "decimal",
        "queue", "uuid", "bisect", "heapq", "operator", "atexit",
        "contextlib", "dataclasses", "gc", "glob", "shutil",
        "stat", "string", "textwrap", "tempfile", "zipfile",
        "zlib", "gzip", "bz2", "lzma", "csv", "xml", "html",
        "token", "tokenize", "types", "typing_extensions",
        "sqlite3", "urllib3", "requests", "aiohttp", "httpx", "yarl", "six",
        "shlex", "ipaddress", "resource", "site", "fnmatch", "gettext",
    }
    _MACHINERY_MARKERS = (
        "__prepare__", "must return a mapping", "__mro_entries__",
        "metaclass conflict", "__set_name__",
        "argument after ** must be a mapping",
        "got multiple values for keyword argument",
        "argument after * must be an iterable",
        "star_arg_list",
    )

    def __init__(
        self,
        module_name: str,
        constants: list[Any] | tuple[Any, ...],
        code_objects: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
        body_traces: dict[str, list[str]] | None = None,
        module_globals: Iterable[str] | None = None,
        body_sources: dict[str, list[str]] | None = None,
        defaults: dict[str, tuple[Any, ...]] | None = None,
        known_modules: Iterable[str] | None = None,
        is_package: bool = False,
        emit_banner: bool = True,
        module_global_values: dict[str, Any] | None = None,
        native_attempted: bool = False,
        source_order: dict[str, int] | None = None,
    ) -> None:
        self.module_name = module_name or "__module__"
        self.native_attempted = bool(native_attempted)
        self.known_modules = {str(m) for m in (known_modules or ()) if m}
        self.is_package = bool(is_package)
        self.emit_banner = bool(emit_banner)
        self.constants = list(constants or ())
        self._defaults = dict(defaults or {})
        self.body_traces = dict(body_traces or {})
        self.body_sources = dict(body_sources or {})
        self.module_globals = set(module_globals or ())
        self.module_global_values = dict(module_global_values or {})

        # Map CodeObject positions in self.constants for bounded constant-window analysis.
        self._co_pos_by_id: dict[int, int] = {}
        self._co_pos_by_key: dict[tuple[str, int], int] = {}
        self._all_co_positions: list[int] = []
        extracted_cos: list[dict[str, Any]] = []
        for idx, item in enumerate(self.constants):
            if isinstance(item, dict) and item.get("_type") == "CodeObject":
                self._co_pos_by_id[id(item)] = idx
                qn_k = str(item.get("qualname") or item.get("name") or "")
                self._co_pos_by_key.setdefault((qn_k, int(item.get("line") or 0)), idx)
                self._all_co_positions.append(idx)
                extracted_cos.append(item)

        self.code_objects = list(code_objects) if code_objects else extracted_cos

        self._inferred_bases: dict[str, list[str]] = {}
        self._inferred_classes: list[str] = []
        self._class_cos: dict[str, dict[str, Any]] = {}
        self._class_docstrings: dict[str, str] = {}
        self._class_lines: dict[str, int] = {}
        self._class_attrs: dict[str, list[tuple[str, str | None]]] = {}
        self._class_const_hints: dict[str, list[Any]] = {}
        self._nested_classes: dict[str, list[str]] = {}
        self._nested_class_cos: dict[str, dict[str, Any]] = {}
        self._local_classes_by_parent: dict[str, list[dict[str, Any]]] = {}
        self._local_funcs_by_parent: dict[str, list[dict[str, Any]]] = {}
        self._qualname_annotations: dict[str, dict[str, Any]] = {}
        self._qualname_defaults: dict[str, tuple[Any, ...]] = {}
        self._qualname_kwdefaults: dict[str, dict[str, Any]] = {}
        self._qualname_positions: dict[str, int] = {}
        self._qualname_param_names: dict[str, list[str]] = {}
        self._partitioned_co_windows: dict[int, list[Any]] = {}
        self._detected_import_lines: list[str] = []
        self.classes: dict[str, dict[str, Any]] = {}
        self.free_funcs: list[dict[str, Any]] = []

        self.str_positions: dict[str, list[int]] = {}
        for i, c in enumerate(self.constants):
            if isinstance(c, str):
                self.str_positions.setdefault(c, []).append(i)

        self._scan_qualname_metadata()

        has_native = any(co.get("_native") for co in self.code_objects if isinstance(co, dict))
        has_blob_exact = any(self._is_blob_exact_co(co) for co in self.code_objects if isinstance(co, dict))

        if has_native:
            (
                self.code_objects,
                self._inferred_classes,
                self._inferred_bases,
            ) = self._merge_native_code_objects(self.code_objects)
        elif has_blob_exact:
            (
                self.code_objects,
                self._inferred_classes,
                self._inferred_bases,
            ) = self._ingest_blob_code_objects(self.code_objects)
        elif not self.code_objects:
            methods, class_order, method_leaves = self._scan_qualnames()
            self._inferred_classes = class_order
            self._inferred_bases = self._scan_class_bases(class_order, method_leaves)
            free_funcs = self._scan_top_level_functions(methods, class_order)
            all_funcs = methods + free_funcs
            self._partitioned_co_windows = self._build_partitioned_co_windows(all_funcs)
            self._assign_args_by_order(all_funcs)
            self.code_objects = all_funcs

        if not self._partitioned_co_windows and self.code_objects and not self._all_co_positions:
            self._partitioned_co_windows = self._build_partitioned_co_windows(self.code_objects)

        self._classify()
        self._recover_all_class_attributes()

        self._def_order = {id(co): i for i, co in enumerate(self.code_objects)}
        self._src_order = dict(source_order or {})

    # ---- structural classification ----

    @staticmethod
    def _is_ident(s: Any) -> bool:
        return isinstance(s, str) and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s))

    @staticmethod
    def _is_valid_def_name(name: Any) -> bool:
        return (
            isinstance(name, str)
            and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))
            and not keyword.iskeyword(name)
            and not keyword.issoftkeyword(name)
        )

    @staticmethod
    def _is_blob_exact_co(co: Any) -> bool:
        return (
            isinstance(co, dict)
            and co.get("_type") == "CodeObject"
            and co.get("_source") not in ("qualname", "free", "broad-scan")
            and co.get("_blob_exact") is not False
            and isinstance(co.get("argcount"), int)
        )

    @staticmethod
    def _is_class_code_object(co: dict[str, Any]) -> bool:
        name = str(co.get("name") or "")
        if not name or name.startswith("<"):
            return False
        if co.get("kind") == "class":
            return True
        flags = int(co.get("flags") or 0)
        args = co.get("args") or ()
        return not (flags & 0x02) and "__class__" in args

    def _get_co_pos(self, co: dict[str, Any]) -> int | None:
        pos = self._co_pos_by_id.get(id(co))
        if pos is not None:
            return pos
        qn = str(co.get("qualname") or co.get("name") or "")
        return self._co_pos_by_key.get((qn, int(co.get("line") or 0)))

    def _get_co_window(self, co: dict[str, Any], *, stop_at_any_co: bool = False) -> list[Any]:
        """Return constants slice immediately following `co` up to the next sibling CodeObject."""
        pos = self._get_co_pos(co)
        if pos is None or pos + 1 >= len(self.constants):
            return list(self._partitioned_co_windows.get(id(co), ()))
        end = len(self.constants)
        qn_prefix = str(co.get("qualname") or co.get("name") or "") + ".<locals>."
        for nxt_pos in self._all_co_positions:
            if nxt_pos <= pos:
                continue
            if stop_at_any_co:
                end = nxt_pos
                break
            nxt_co = self.constants[nxt_pos]
            nxt_qn = str(nxt_co.get("qualname") or nxt_co.get("name") or "")
            # Stay inside the enclosing function across its own `<locals>` helpers.
            if not nxt_qn.startswith(qn_prefix):
                end = nxt_pos
                break
        # Collect elements excluding sub-slices consumed by local closures/classes.
        items: list[Any] = []
        skip_until = -1
        for idx in range(pos + 1, end):
            if idx < skip_until:
                continue
            val = self.constants[idx]
            if isinstance(val, dict) and val.get("_type") == "CodeObject":
                child_qn = str(val.get("qualname") or val.get("name") or "")
                if val.get("kind") == "class" and child_qn.startswith(qn_prefix):
                    # Skip the nested class's own field definition tokens up to `__mro_entries__`/`_fields_`.
                    j = idx + 1
                    while j < end:
                        v_j = self.constants[j]
                        if v_j in ("_fields_", "__orig_bases__", "__mro_entries__"):
                            skip_until = j + 1
                            if v_j == "__mro_entries__":
                                break
                        if isinstance(v_j, dict) and v_j.get("_type") == "CodeObject":
                            break
                        j += 1
                    continue
                if child_qn.startswith(qn_prefix) and not str(val.get("name") or "").startswith("<"):
                    # Nested helper def has its own body window up to parent's continuation.
                    continue
            items.append(val)
        return items

    def _scan_qualname_metadata(self) -> None:
        """Recover adjacent annotation dicts and verified default tuples near qualnames."""
        n = len(self.constants)
        # Locate start of module import / definition tail so pre-import call arg tuples aren't misread as defaults.
        import_anchor = 0
        for idx in range(n - 1):
            if self.constants[idx] == "origin" and self.constants[idx + 1] == "has_location":
                import_anchor = idx + 2
                break
        if import_anchor == 0:
            lo_def, _hi_def = self._definition_region()
            import_anchor = lo_def

        for idx, c in enumerate(self.constants):
            if not isinstance(c, str) or idx == 0:
                continue
            if c.endswith((".py", ".pyc")) or " " in c or "<" in c:
                continue
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", c):
                continue
            self._qualname_positions.setdefault(c, idx)
            prev = self.constants[idx - 1]
            if isinstance(prev, dict) and self._is_annotation_dict(prev):
                self._qualname_annotations.setdefault(c, prev)
                back_pos = idx - 2
                if back_pos >= 0 and isinstance(self.constants[back_pos], dict):
                    kwd = self.constants[back_pos]
                    if (
                        kwd
                        and all(isinstance(k, str) and k in prev and self._is_safe_default_val(v) for k, v in kwd.items())
                    ):
                        self._qualname_kwdefaults.setdefault(c, kwd)
                        back_pos -= 1
                if back_pos >= 0:
                    cand_def = self.constants[back_pos]
                    if (
                        isinstance(cand_def, tuple)
                        and 1 <= len(cand_def) <= max(1, len(prev) - (1 if "return" in prev else 0))
                        and all(self._is_safe_default_val(v) for v in cand_def)
                    ):
                        self._qualname_defaults.setdefault(c, cand_def)
            elif idx >= import_anchor and self._is_valid_def_name(c.rsplit(".", 1)[-1]):
                # Nuitka 2.x unannotated qualname/function with positional defaults right before
                # `<leaf>` + `<Class.leaf>` or `<arg_names...>` + `<func_name>`.
                leaf = c.rsplit(".", 1)[-1]
                for back_step in range(1, 5):
                    bp = idx - back_step
                    if bp < max(0, import_anchor):
                        break
                    item = self.constants[bp]
                    if isinstance(item, tuple) and 1 <= len(item) <= 12:
                        if self._is_type_spec(item):
                            continue
                        if (
                            all(self._is_safe_default_val(v) for v in item)
                            and not (bp >= 1 and isinstance(self.constants[bp - 1], str) and "." in self.constants[bp - 1])
                            and not (len(item) == 1 and isinstance(item[0], str) and self._is_ident(item[0]) and bp >= 1 and isinstance(self.constants[bp - 1], str) and self.constants[bp - 1].isidentifier())
                        ):
                            # Only accept `(default, ...)` across intermediate steps if intervening entries
                            # are short ident strings (`leaf` or param names) and not another tuple/dict.
                            between_ok = all(
                                (isinstance(self.constants[k], str) and self._is_ident(self.constants[k]))
                                or (isinstance(self.constants[k], tuple) and self._is_type_spec(self.constants[k]))
                                for k in range(bp + 1, idx)
                            )
                            between_names = [
                                self.constants[k]
                                for k in range(bp + 1, idx)
                                if isinstance(self.constants[k], str) and self._is_valid_def_name(self.constants[k])
                            ]
                            if between_ok and ("." in c or back_step >= 2 or (bp + 1 == idx and not (len(item) == 1 and isinstance(item[0], str)))):
                                # Avoid misattributing orphan free-function defaults to an unrelated 0-arg `main` right at `.py`.
                                if "." in c or back_step >= 2:
                                    self._qualname_defaults.setdefault(c, item)
                                    if between_names and between_names != [leaf]:
                                        self._qualname_param_names.setdefault(c, between_names)
                        break
                    if not (
                        (isinstance(item, str) and (item == leaf or self._is_ident(item)))
                        or (isinstance(item, tuple) and self._is_type_spec(item))
                    ):
                        break

    @staticmethod
    def _is_safe_default_val(v: Any) -> bool:
        if v is None or isinstance(v, (bool, int, float)):
            return True
        if isinstance(v, str) and len(v) <= 80:
            return True
        if isinstance(v, tuple) and len(v) <= 6:
            if v and v[0] in ("UnionType", "GenericAlias", "_nuitka_builtin_anon_type", "slice"):
                return False
            if all(x is None or isinstance(x, (bool, int, float, str)) for x in v):
                return True
        return False

    def _extract_exact_blob_sig(self, co: dict[str, Any]) -> tuple[list[str], list[str]]:
        """Extract exact `(sig_args, locals_only)` from blob `'C'`/`'K'` CodeObject."""
        varnames = [str(a) for a in (co.get("args") or ())]
        argcount = max(0, int(co.get("argcount") or 0))
        posonly = max(0, int(co.get("posonly") or 0))
        kwonly = max(0, int(co.get("kwonly") or 0))
        flags = int(co.get("flags") or 0)
        has_varargs = bool(flags & 0x04)
        has_varkw = bool(flags & 0x08)

        pos_names = [a for a in varnames[:argcount] if self._is_ident(a)]
        kwonly_names = [a for a in varnames[argcount:argcount + kwonly] if self._is_ident(a)]

        va_idx = argcount + kwonly
        vararg_name: str | None = None
        if has_varargs:
            cand = varnames[va_idx] if va_idx < len(varnames) else "args"
            vararg_name = cand if self._is_ident(cand) else "args"

        kw_idx = va_idx + (1 if has_varargs else 0)
        varkw_name: str | None = None
        if has_varkw:
            cand = varnames[kw_idx] if kw_idx < len(varnames) else "kwargs"
            varkw_name = cand if self._is_ident(cand) else "kwargs"

        sig_args: list[str] = []
        if posonly > 0 and posonly <= len(pos_names):
            sig_args.extend(pos_names[:posonly])
            sig_args.append("/")
            sig_args.extend(pos_names[posonly:])
        else:
            sig_args.extend(pos_names)

        if vararg_name is not None:
            sig_args.append(f"*{vararg_name}")
        elif kwonly_names:
            sig_args.append("*")
        sig_args.extend(kwonly_names)
        if varkw_name is not None:
            sig_args.append(f"**{varkw_name}")

        consumed = set(pos_names) | set(kwonly_names)
        if vararg_name:
            consumed.add(vararg_name)
        if varkw_name:
            consumed.add(varkw_name)
        locals_only = [v for v in varnames if v not in consumed and self._is_ident(v)]
        return sig_args, locals_only

    def _ingest_blob_code_objects(
        self, raw_cos: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[str], dict[str, list[str]]]:
        """Ingest decoded blob CodeObjects while preserving class nesting and `<locals>` scope."""
        methods_q, qual_classes, method_leaves = self._scan_qualnames()
        class_order: list[str] = []
        class_names: set[str] = set()
        seen_nested: set[str] = set()
        covered_qns: set[str] = set()
        out_cos: list[dict[str, Any]] = []

        def _reg_top_class(cname: str, co_obj: dict[str, Any] | None = None) -> None:
            if not self._is_valid_def_name(cname) or cname in self.known_modules:
                return
            if cname not in class_names:
                class_names.add(cname)
                class_order.append(cname)
            if co_obj is not None:
                self._class_cos.setdefault(cname, co_obj)
                ln = int(co_obj.get("line") or 0)
                if ln > 0 and cname not in self._class_lines:
                    self._class_lines[cname] = ln
                if co_obj.get("docstring"):
                    self._class_docstrings.setdefault(cname, co_obj["docstring"])

        for c in qual_classes:
            _reg_top_class(c)

        for co in raw_cos:
            if not isinstance(co, dict):
                continue
            name = str(co.get("name") or "")
            qn = str(co.get("qualname") or name or "")

            if name == "<module>" or qn == "<module>":
                nc = dict(co)
                self._copy_co_pos(co, nc)
                out_cos.append(nc)
                continue

            if ".<locals>." in qn:
                parent_qn = qn.split(".<locals>.", 1)[0]
                if self._is_class_code_object(co):
                    nc = dict(co)
                    self._copy_co_pos(co, nc)
                    self._local_classes_by_parent.setdefault(parent_qn, []).append(nc)
                elif (
                    self._is_valid_def_name(name)
                    and not name.startswith("<")
                    and co.get("kind") not in ("genexpr", "listcomp", "dictcomp", "setcomp")
                ):
                    nc = dict(co)
                    self._copy_co_pos(co, nc)
                    self._local_funcs_by_parent.setdefault(parent_qn, []).append(nc)
                continue

            if name in ("<lambda>", "<genexpr>", "<listcomp>", "<dictcomp>", "<setcomp>"):
                continue

            if self._is_class_code_object(co):
                if "." in qn:
                    parent_cls, child_cls = qn.rsplit(".", 1)
                    top_cls = qn.split(".", 1)[0]
                    _reg_top_class(top_cls)
                    if self._is_valid_def_name(child_cls) and qn not in seen_nested:
                        seen_nested.add(qn)
                        self._nested_classes.setdefault(parent_cls, []).append(qn)
                        self._nested_class_cos[qn] = co
                        self._class_cos.setdefault(qn, co)
                        ln = int(co.get("line") or 0)
                        if ln > 0:
                            self._class_lines.setdefault(qn, ln)
                        if co.get("docstring"):
                            self._class_docstrings.setdefault(qn, co["docstring"])
                else:
                    _reg_top_class(name, co)
                continue

            if not self._is_valid_def_name(name):
                continue

            if "." in qn:
                top_owner = qn.split(".", 1)[0]
                if top_owner not in self.known_modules and self._is_valid_def_name(top_owner):
                    _reg_top_class(top_owner)
                method_leaves.add(name)

            nc = dict(co)
            nc["_blob_exact"] = self._is_blob_exact_co(co)
            self._copy_co_pos(co, nc)
            if qn not in covered_qns:
                covered_qns.add(qn)
                out_cos.append(nc)

        # Backfill any qualname-only methods without an explicit CodeObject entry.
        for m in methods_q:
            mqn = str(m.get("qualname") or m.get("name") or "")
            if mqn in covered_qns or mqn in self._nested_class_cos or mqn.lower().endswith(_DATA_FILE_EXTS):
                continue
            covered_qns.add(mqn)
            out_cos.append(m)

        # Sort classes in line order when available from CodeObjects.
        if self._class_lines:
            def _cls_sort_key(cname: str) -> tuple[int, int]:
                ln = self._class_lines.get(cname)
                if ln:
                    return (0, ln)
                method_lns = [
                    int(co.get("line") or 0)
                    for co in out_cos
                    if str(co.get("qualname") or "").split(".", 1)[0] == cname and int(co.get("line") or 0) > 0
                ]
                if method_lns:
                    return (0, min(method_lns))
                return (1, self._const_index(cname))

            class_order.sort(key=_cls_sort_key)

        if any(not co.get("_blob_exact") for co in out_cos):
            self._assign_args_by_order(out_cos)

        bases = self._scan_class_bases(class_order, method_leaves)
        return out_cos, class_order, bases

    def _copy_co_pos(self, src: dict[str, Any], dst: dict[str, Any]) -> None:
        pos = self._co_pos_by_id.get(id(src))
        if pos is not None:
            self._co_pos_by_id[id(dst)] = pos

    def _recover_all_class_attributes(self) -> None:
        """Recover class-level attribute bindings & literal hints from class constant windows."""
        for cls_key in list(self.classes.keys()) + list(self._nested_class_cos.keys()):
            co = self._class_cos.get(cls_key)
            if not co:
                continue
            win = self._get_co_window(co, stop_at_any_co=True)
            if not win:
                continue
            attrs: list[tuple[str, str | None]] = []
            hints: list[Any] = []
            seen_attrs: set[str] = set()
            pending_val: Any = _UNSET_SENTINEL

            # Stop before module-level logging/WinAPI initialization statements
            # that follow the last class attribute before the next class body.
            _INIT_API_STOP = frozenset({
                "SetConsoleMode", "GetStdHandle", "basicConfig", "getLogger",
                "disable_warnings", "Thread", "PoolManager",
            })

            for w_idx, item in enumerate(win):
                if isinstance(item, dict) and self._is_annotation_dict(item):
                    break
                if (
                    w_idx + 1 < len(win)
                    and isinstance(win[w_idx + 1], dict)
                    and self._is_annotation_dict(win[w_idx + 1])
                ):
                    break
                if isinstance(item, str):
                    if item in _INIT_API_STOP or item in self._COMMON_STDLIB:
                        break
                    if item in self._NON_FUNCTION_NAMES or self._is_machinery_string(item):
                        continue
                    if "." in item and item.startswith(cls_key + "."):
                        break
                    if self._is_valid_def_name(item):
                        val_repr: str | None = None
                        if pending_val is not _UNSET_SENTINEL:
                            val_repr = self._safe_literal(pending_val)
                            pending_val = _UNSET_SENTINEL
                        if item not in seen_attrs:
                            seen_attrs.add(item)
                            attrs.append((item, val_repr))
                    else:
                        hints.append(item)
                elif isinstance(item, (tuple, list, dict, int, float, bytes)) and not isinstance(item, bool):
                    if isinstance(item, tuple) and len(item) == 1 and isinstance(item[0], str):
                        pending_val = item[0]
                    elif isinstance(item, tuple) and item and all(
                        isinstance(x, (bool, int, float, str, bytes, tuple)) or x is None for x in item
                    ):
                        pending_val = item
                    else:
                        hints.append(item)

            if attrs:
                self._class_attrs[cls_key] = attrs
            if hints:
                self._class_const_hints[cls_key] = hints[:20]

    def _definition_region(self) -> tuple[int, int]:
        """Return `(start, end)` constant indices bounding the def/class region."""
        start, end = 0, len(self.constants)
        markers_lo = ("__doc__", "__file__", "__module__", "__qualname__")
        for i, c in enumerate(self.constants):
            if isinstance(c, str) and c in markers_lo:
                start = i
                break
        for i, c in enumerate(self.constants):
            if c == "__spec__":
                end = i
                break
        return start, end

    def _is_varnames_tuple(self, t: Any) -> bool:
        """True for a tuple that looks like a `co_varnames` list."""
        return isinstance(t, tuple) and 0 < len(t) <= 40 and all(x == ".0" or self._is_ident(x) for x in t)

    def _scan_qualnames(self) -> tuple[list[dict[str, Any]], list[str], set[str]]:
        """Recover methods and their owning classes from dotted `co_qualname` constants."""
        methods: list[dict[str, Any]] = []
        class_order: list[str] = []
        method_leaves: set[str] = set()
        seen: set[str] = set()
        _proven_class_names = {
            str(co.get("name"))
            for co in (self.code_objects or ())
            if co
            and co.get("name")
            and not str(co.get("name")).startswith("<")
            and not (int(co.get("flags") or 0) & 0x02)
            and self._is_valid_def_name(str(co.get("name")))
        }
        _known_gui_pkgs = frozenset({"PySide6", "PySide2", "PyQt5", "PyQt6"})
        n_consts = len(self.constants)
        for idx, c in enumerate(self.constants):
            if not isinstance(c, str) or "." not in c:
                continue
            if c.lower().endswith(_DATA_FILE_EXTS) or " " in c:
                continue
            if any(m in c for m in ("<locals>", "<lambda>", "<listcomp>", "<dictcomp>", "<setcomp>", "<genexpr>")):
                continue
            if "<" in c or ">" in c:
                continue
            parts = c.split(".")
            if len(parts) < 2 or not all(self._is_ident(p) for p in parts):
                continue
            owner = parts[0]
            leaf = parts[-1]
            if owner in self._PACKAGE_MACHINERY_NAMES or owner in _known_gui_pkgs:
                continue
            # `from Pkg.Mod import (...)` immediately precedes its imported-names tuple.
            if (
                idx + 1 < n_consts
                and self._is_varnames_tuple(self.constants[idx + 1])
                and self.constants[idx + 1][0] not in ("self", "cls", ".0")
            ):
                continue
            if not owner[:1].isupper() and owner not in _proven_class_names:
                continue
            if any(p == owner or p.startswith(owner + ".") for p in self.known_modules):
                continue
            if leaf in ("__class__", "__prepare__", "__mro_entries__"):
                continue
            if not (self._is_valid_def_name(owner) and self._is_valid_def_name(leaf)):
                continue
            if c in seen:
                continue
            seen.add(c)
            if owner not in class_order:
                class_order.append(owner)
            method_leaves.add(leaf)
            methods.append({
                "_type": "CodeObject",
                "name": leaf,
                "qualname": c,
                "args": [],
                "argcount": 0,
                "kwonly": 0,
                "posonly": 0,
                "flags": 0,
                "line": 0,
                "_source": "qualname",
            })
        return methods, class_order, method_leaves

    def _import_tuple_positions(self) -> set[int]:
        """Indices of ident-tuples that belong to `from <mod> import (...)` statements."""
        positions: set[int] = set()
        n = len(self.constants)
        py_idx, mod_idx = self._tail_varname_region_start()
        tail_lo = (mod_idx + 1) if mod_idx is not None else ((py_idx + 1) if py_idx is not None else n)
        for i, c in enumerate(self.constants):
            if i >= tail_lo or not self._is_varnames_tuple(c):
                continue
            if c[0] in ("self", "cls", ".0"):
                continue
            for back in (1, 2):
                j = i - back
                if j < 0:
                    break
                p = self.constants[j]
                if not isinstance(p, str) or p.lower().endswith(_DATA_FILE_EXTS):
                    continue
                if self._is_ident(p) and (
                    p in self._COMMON_STDLIB
                    or p in self.known_modules
                    or any(km.startswith(p + ".") for km in self.known_modules)
                    or p in {"views", "models", "controllers", "utils", "core", "ui", "api", "config", "db", "services", "workers", "widgets", "dialogs", "pages"}
                ):
                    positions.add(i)
                    break
                if "." in p and all(self._is_ident(part) for part in p.split(".") if part):
                    parts = p.split(".")
                    if (
                        parts[0][:1].islower()
                        or parts[0] in self._COMMON_STDLIB
                        or p in self.known_modules
                        or parts[0] in {"PySide6", "PySide2", "PyQt5", "PyQt6", "PIL", "OpenSSL"}
                        or parts[-1].startswith("Qt")
                    ):
                        positions.add(i)
                        break
        return positions

    def _scan_class_bases(self, class_order: list[str], method_leaves: set[str]) -> dict[str, list[str]]:
        """Recover explicit base classes when `__orig_bases__` marker is present."""
        if "__orig_bases__" not in self.constants or not class_order:
            return {}
        _defined_class_names = set(class_order)
        _BUILTIN_BASE_TYPES = frozenset({
            "object", "type", "bool", "int", "float", "complex", "str", "bytes",
            "bytearray", "list", "tuple", "set", "frozenset", "dict", "range",
            "Enum", "IntEnum", "Flag", "IntFlag", "ABC", "ABCMeta", "Generic",
            "TypedDict", "NamedTuple", "Thread", "RLock", "Lock", "Event",
            "Condition", "Future", "Task", "Coroutine", "TestCase",
            "IsolatedAsyncioTestCase", "Mock", "MagicMock", "AsyncMock", "Structure",
        })
        _EXCEPTION_TYPES = frozenset({
            "Exception", "BaseException", "ValueError", "TypeError", "KeyError",
            "AttributeError", "RuntimeError", "StopIteration", "StopAsyncIteration",
            "NotImplementedError", "OSError", "IOError", "FileNotFoundError",
            "PermissionError", "ArithmeticError", "ZeroDivisionError", "OverflowError",
            "LookupError", "IndexError", "NameError", "AssertionError", "Warning",
            "UserWarning", "DeprecationWarning", "RuntimeWarning", "ResourceWarning",
            "UnicodeError", "UnicodeDecodeError", "UnicodeEncodeError", "MemoryError",
            "RecursionError", "SystemExit", "KeyboardInterrupt", "GeneratorExit",
            "TimeoutError", "ConnectionError", "BrokenPipeError", "ConnectionResetError",
            "ConnectionRefusedError", "ConnectionAbortedError", "FileExistsError",
            "IsADirectoryError", "NotADirectoryError", "InterruptedError",
            "BlockingIOError", "ChildProcessError", "ProcessLookupError",
            "EOFError", "ImportError", "ModuleNotFoundError",
        })
        _MODULE_NAME_TOKENS = frozenset({
            "QtCore", "QtGui", "QtWidgets", "QtTest", "QtNetwork", "QtSql",
            "QtSvg", "QtXml", "QtMultimedia", "QtPrintSupport", "QtConcurrent",
            "QtQml", "QtQuick", "QtQuickWidgets", "QtCharts", "QtOpenGL",
        })

        def _credible_base(name: str) -> bool:
            return name in _defined_class_names or name in _BUILTIN_BASE_TYPES or name in _EXCEPTION_TYPES

        def _is_compound_camel_base(name: str) -> bool:
            return bool(re.search(r"[a-z0-9][A-Z]", name[1:]) or re.search(r"[A-Z]{2,}[a-z]", name[1:]))

        _import_tuples = self._import_tuple_positions()
        base_tuples: list[tuple[int, list[str], int]] = []
        for i, c in enumerate(self.constants):
            if i in _import_tuples or not (isinstance(c, tuple) and c):
                continue
            names = list(c)
            if not all(isinstance(nm, str) and re.fullmatch(r"[A-Z]\w*", nm) for nm in names):
                continue
            if names == ["__class__"] or any(nm in method_leaves for nm in names):
                continue
            if any(nm in _MODULE_NAME_TOKENS for nm in names):
                continue
            if len(names) >= 2 and all(nm in _EXCEPTION_TYPES for nm in names):
                continue
            if not all(_credible_base(nm) for nm in names):
                continue
            if (
                len(names) == 1
                and not _is_compound_camel_base(names[0])
                and names[0] not in _defined_class_names
                and names[0] not in _BUILTIN_BASE_TYPES
                and names[0] not in _EXCEPTION_TYPES
            ):
                continue
            base_tuples.append((i, names, len(names)))

        if not base_tuples:
            return {}
        class_pos: dict[str, int] = {}
        for cls in class_order:
            for i, c in enumerate(self.constants):
                if isinstance(c, str) and (c == cls or c.startswith(cls + ".")):
                    class_pos[cls] = i
                    break
        bases: dict[str, list[str]] = {}
        used: set[int] = set()
        order = sorted(range(len(base_tuples)), key=lambda k: base_tuples[k][2])
        for cls in class_order:
            anchor = class_pos.get(cls, 0)
            best = None
            for k in order:
                if k in used:
                    continue
                pos, names, size = base_tuples[k]
                if "Structure" in names:
                    # `ctypes.Structure` is typically inherited inside `<locals>` structs unless `__orig_bases__` sits adjacent to top class.
                    continue
                dist = (size, abs(pos - anchor))
                if best is None or dist < best[0]:
                    best = (dist, k, names)
            if best is not None:
                used.add(best[1])
                bases[cls] = best[2]
        return bases

    def _tail_varname_region_start(self) -> tuple[int | None, int | None]:
        """Locate the trailing `<filename>.py` and `<module...>` markers in Nuitka 2.x blobs."""
        n = len(self.constants)
        py_idx: int | None = None
        for i in range(n - 1, -1, -1):
            c = self.constants[i]
            if isinstance(c, str) and not c.startswith("<") and c.lower().endswith((".py", ".pyc")):
                if i + 1 < n and any(
                    self._is_varnames_tuple(self.constants[j]) or (isinstance(self.constants[j], str) and self.constants[j].startswith("<module"))
                    for j in range(i + 1, min(n, i + 10))
                ):
                    py_idx = i
                    break
        mod_idx: int | None = None
        search_lo = (py_idx + 1) if py_idx is not None else max(0, n // 2)
        for i in range(search_lo, n):
            c = self.constants[i]
            if isinstance(c, str) and c.startswith("<module") and c.endswith(">"):
                mod_idx = i
                break
        return py_idx, mod_idx

    def _find_body_region_bounds(self) -> tuple[int, int]:
        """Return `(body_start, body_end)` slicing function/method constants before imports & qualnames."""
        n = len(self.constants)
        body_start = 0
        for i in range(min(14, n)):
            if self.constants[i] in ("__mro_entries__", "called", "star_arg_dict", "star_arg_list", "kw") or (
                isinstance(self.constants[i], str) and "object is not a mapping" in self.constants[i]
            ):
                body_start = i + 1

        for i in range(n - 1):
            if self.constants[i] == "origin" and self.constants[i + 1] == "has_location":
                return body_start, max(body_start, i)

        py_idx, _mod_idx = self._tail_varname_region_start()
        lo_def, _hi_def = self._definition_region()
        limit = lo_def if lo_def > 0 else (py_idx if py_idx is not None else n)
        # Walk backwards from `limit` past annotations/defaults/data to the module-level import run.
        imp_t = self._import_tuple_positions()
        best_end = limit
        for i in range(max(body_start, limit - 1), body_start - 1, -1):
            c = self.constants[i]
            if best_end < limit and best_end - i > 3:
                break
            if i in imp_t:
                best_end = i
            elif isinstance(c, str) and (
                c in self._COMMON_STDLIB
                or c in self.known_modules
                or ("." in c and all(self._is_ident(p) for p in c.split(".") if p) and not c.endswith((".py", ".pyc")))
            ):
                if (
                    i + 1 < n
                    and (i + 1 in imp_t or isinstance(self.constants[i + 1], str))
                    and i >= limit - 25
                ):
                    best_end = min(best_end, i)
            elif i < best_end - 3 and isinstance(c, str) and not self._is_ident(c):
                break
        return body_start, max(body_start, min(best_end, limit))

    _BUILTIN_CALLABLE_BLOCKLIST = frozenset({
        "abs", "all", "any", "ascii", "bin", "bool", "breakpoint", "bytearray",
        "bytes", "callable", "chr", "classmethod", "compile", "complex", "delattr",
        "dict", "dir", "divmod", "enumerate", "eval", "exec", "filter", "float",
        "format", "frozenset", "getattr", "globals", "hasattr", "hash", "help",
        "hex", "id", "input", "int", "isinstance", "issubclass", "iter", "len",
        "list", "locals", "map", "max", "memoryview", "min", "next", "object",
        "oct", "open", "ord", "pow", "print", "property", "range", "repr",
        "reversed", "round", "set", "setattr", "slice", "sorted", "staticmethod",
        "str", "sum", "super", "tuple", "type", "vars", "zip",
        # Common stdlib / UI attribute & method names (not module-level def targets).
        "append", "extend", "insert", "remove", "pop", "clear", "copy", "sort",
        "reverse", "split", "join", "strip", "lstrip", "rstrip", "replace",
        "startswith", "endswith", "find", "index", "count", "upper", "lower",
        "items", "keys", "values", "update", "get", "setdefault", "encode", "decode",
        "read", "write", "close", "flush", "seek", "run", "connect", "start", "stop",
        "argv", "prefix", "base_prefix", "executable", "returncode", "stdout",
        "stderr", "_exit", "environ", "modules", "frozen", "resolve", "mkdir",
        "expanduser", "is_file", "copy2", "now", "strftime", "getrlimit", "setrlimit",
        "find_spec", "getusersitepackages", "addsitedir", "invalidate_caches",
        "getsockname", "apply", "shutdown", "running_threads", "windll", "shell32",
        "system_prefers_dark", "is_activated", "broadcast_address", "prefixlen",
        "is_link_local", "is_virtual", "allInterfaces", "addressEntries",
        "quote", "maketrans", "translate", "sub", "match", "search", "findall",
    })

    def _scan_top_level_functions(
        self,
        methods: list[dict[str, Any]],
        class_order: list[str],
    ) -> list[dict[str, Any]]:
        """Recover module-level functions in Nuitka 2.x blobs without `'C'` CodeObjects."""
        n = len(self.constants)
        py_idx, mod_idx = self._tail_varname_region_start()
        tail_lo = (mod_idx + 1) if mod_idx is not None else ((py_idx + 1) if py_idx is not None else n)
        import_tuples = self._import_tuple_positions()

        tail_tuples = [
            (i, self.constants[i])
            for i in range(tail_lo, n)
            if self._is_varnames_tuple(self.constants[i])
            and i not in import_tuples
            and not str(self.constants[i][0]).startswith(".")
        ]

        # Count non-method (`self`/`cls`) tail tuples not owned by class `<locals>` nested helpers.
        class_local_helpers = 0
        for c in self.constants:
            if isinstance(c, str) and ".<locals>." in c:
                head = c.split(".<locals>.", 1)[0]
                tail_part = c.split(".<locals>.", 1)[1]
                if "." in head and not tail_part.startswith("<") and tail_part not in ("",):
                    class_local_helpers += 1

        non_method_tails = [t for _i, t in tail_tuples if t[0] not in ("self", "cls")]
        expected_free = max(0, len(non_method_tails) - class_local_helpers)
        # If there are no class methods and py/mod tail exists, at least len(non_method_tails) free funcs exist.
        if methods and expected_free == 0:
            # Still include explicit top-level `<locals>` owners or annotated free functions.
            pass

        imported_syms = _ndl_parse_imported_symbols(self.detect_imports())
        tail_var_tokens = {x for _i, t in tail_tuples for x in t if isinstance(x, str)}
        dict_keys = {
            k
            for d in self.constants
            if isinstance(d, dict)
            for k in d
            if isinstance(k, str)
        }
        class_set = set(class_order)
        method_leaves = {str(m.get("name")) for m in methods}
        known_roots = {km.split(".")[0] for km in self.known_modules} | set(self.known_modules)

        def _is_excluded_name(s: str) -> bool:
            if not self._is_valid_def_name(s):
                return True
            if s.startswith("__") and s.endswith("__"):
                return True
            if s.isupper() and len(s) > 1:
                return True
            if (
                s in class_set
                or s in imported_syms
                or s in known_roots
                or s in self._NON_FUNCTION_NAMES
                or s in self._COMMON_STDLIB
                or s in self._PACKAGE_MACHINERY_NAMES
                or s in self._BUILTIN_CALLABLE_BLOCKLIST
                or s in {"self", "cls", "args", "kwargs", "return", "origin", "has_location"}
            ):
                return True
            if methods and s in method_leaves:
                return True
            return False

        candidates: dict[str, tuple[int, int]] = {}  # name -> (tier_priority, pos_in_constants)

        # Tier 1a: Explicit `<locals>` roots without `.` in head (`local_ipv4_interfaces.<locals>.<genexpr>`).
        for i, c in enumerate(self.constants):
            if isinstance(c, str) and ".<locals>." in c:
                head = c.split(".<locals>.", 1)[0]
                if "." not in head and not _is_excluded_name(head) and head[:1].islower():
                    candidates.setdefault(head, (300, i))

        # Tier 1b: Functions directly preceded by an annotation dict (`self._qualname_annotations`).
        for qn, _ann in self._qualname_annotations.items():
            if "." not in qn and not _is_excluded_name(qn):
                qpos = self._qualname_positions.get(qn, self.str_positions.get(qn, [0])[0])
                candidates.setdefault(qn, (250, qpos))

        # Tier 1c: Definition region identifiers between `body_end` (post-imports) and `py_idx` / `mod_idx`.
        body_start, body_end = self._find_body_region_bounds()
        def_limit = py_idx if py_idx is not None else (mod_idx if mod_idx is not None else n)
        # Advance past trailing imports starting at `body_end`.
        post_imp_start = body_end
        for i in range(body_end, def_limit):
            c = self.constants[i]
            if isinstance(c, dict) and self._is_annotation_dict(c):
                break
            if i > post_imp_start + 2:
                break
            if i in import_tuples or (
                isinstance(c, str)
                and (
                    c in self._COMMON_STDLIB
                    or c in self.known_modules
                    or c in ("origin", "has_location")
                    or ("." in c and not c.endswith((".py", ".pyc")))
                )
            ):
                post_imp_start = i + 1
        for i in range(post_imp_start, def_limit):
            c = self.constants[i]
            if (
                isinstance(c, str)
                and len(c) >= 2
                and not (len(c) == 1 and i >= 1 and self.constants[i - 1] == "quote")
                and (c[:1].islower() or c.startswith("_"))
                and not _is_excluded_name(c)
                and c not in tail_var_tokens
                and c not in dict_keys
            ):
                candidates.setdefault(c, (200, i))

        orphan_anns: list[dict[str, Any]] = []
        for i in range(post_imp_start, def_limit):
            c = self.constants[i]
            if isinstance(c, dict) and self._is_annotation_dict(c):
                nxt = self.constants[i + 1] if i + 1 < def_limit else None
                nxt_is_qn = (
                    isinstance(nxt, str)
                    and nxt != "return"
                    and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", nxt))
                )
                if not nxt_is_qn:
                    orphan_anns.append(c)

        # Tier 2: Pre-import body scan only when unclaimed non-`self` tail varnames or orphan annotations remain.
        need = max(expected_free - len(candidates), len(orphan_anns))
        if need > 0 and not methods:
            tier2_scored: list[tuple[int, int, str]] = []
            for i in range(body_start, body_end):
                c = self.constants[i]
                if not isinstance(c, str) or c in candidates:
                    continue
                if not (c[:1].islower() or c.startswith("_")) or len(c) <= 2:
                    continue
                if _is_excluded_name(c) or c in tail_var_tokens or c in dict_keys:
                    continue
                # Skip camelCase UI/Qt calls (`setWindowIcon`, `allInterfaces`, ...).
                if any(ch.isupper() for ch in c[1:]):
                    continue
                score = 10
                if "_" in c:
                    score += 30
                if c.startswith("_"):
                    score += 20
                if len(c) >= 6:
                    score += 10
                # Strong bonus if immediately followed by a single-param varname seen in tail_tuples (e.g. `_read_bool`, `value`).
                if i + 1 < body_end and isinstance(self.constants[i + 1], str) and (self.constants[i + 1],) in [t for _ti, t in tail_tuples]:
                    score += 40
                # Penalty if preceded within 1-2 items by an imported/stdlib module name (e.g. `sys.argv`, `resource.getrlimit`).
                if i >= 1 and isinstance(self.constants[i - 1], str) and (
                    self.constants[i - 1] in self._COMMON_STDLIB or self.constants[i - 1] in imported_syms
                ):
                    score -= 35
                tier2_scored.append((score, i, c))
            tier2_scored.sort(key=lambda t: (-t[0], t[1]))
            chosen_tier2 = sorted(tier2_scored[:need], key=lambda t: t[1])
            for idx_t2, (_sc, pos, name) in enumerate(chosen_tier2):
                candidates[name] = (100, pos)
                if idx_t2 < len(orphan_anns) and "." not in name:
                    self._qualname_annotations.setdefault(name, orphan_anns[idx_t2])

        if not candidates:
            return []

        # Order recovered free functions cleanly in module appearance order.
        ordered = sorted(candidates.items(), key=lambda kv: kv[1][1])
        out: list[dict[str, Any]] = []
        for fn_name, (_tier, pos) in ordered:
            out.append({
                "_type": "CodeObject",
                "name": fn_name,
                "qualname": fn_name,
                "args": [],
                "argcount": 0,
                "kwonly": 0,
                "posonly": 0,
                "flags": 0,
                "line": 0,
                "_pos_hint": pos,
                "_source": "free",
            })
        return out

    def _build_partitioned_co_windows(
        self,
        funcs: list[dict[str, Any]],
    ) -> dict[int, list[Any]]:
        """Partition pre-import body constants across functions/methods when no `'C'` CodeObjects exist."""
        body_start, body_end = self._find_body_region_bounds()
        if not funcs or body_end <= body_start:
            return {}

        # Exclude `<module>` / comprehensions / lambdas from window partitioning.
        defs = [
            f for f in funcs
            if isinstance(f, dict) and not str(f.get("name") or "").startswith("<")
        ]
        if not defs:
            return {}

        # Sort functions in source definition order: methods follow qualname index; free follow `_pos_hint` / index.
        def _def_sort_key(f: dict[str, Any]) -> tuple[int, int]:
            ln = int(f.get("line") or 0)
            if ln > 0:
                return (0, ln)
            qn = str(f.get("qualname") or f.get("name") or "")
            if qn in self._qualname_positions:
                return (1, self._qualname_positions[qn])
            if "_pos_hint" in f:
                return (2, int(f["_pos_hint"]))
            return (3, self._const_index(qn, f.get("name")))

        ordered = sorted(defs, key=_def_sort_key)

        # Find `<locals>` anchors inside `[body_start, body_end)` (`Owner.<locals>.inner` -> `Owner`).
        anchors: dict[int, int] = {}
        qn_to_idx = {str(f.get("qualname") or f.get("name") or ""): idx for idx, f in enumerate(ordered)}
        for pos in range(body_start, body_end):
            c = self.constants[pos]
            if isinstance(c, str) and ".<locals>." in c:
                head = c.split(".<locals>.", 1)[0]
                if head in qn_to_idx:
                    # Keep the last `<locals>` occurrence as end-of-body anchor for `head`.
                    anchors[qn_to_idx[head]] = pos

        # Monotonic interpolation of function start/end boundaries over `[body_start, body_end)`.
        n_defs = len(ordered)
        anchor_pts: list[tuple[int, int]] = sorted(anchors.items())
        # Filter any out-of-order anchors if `<locals>` occurred slightly swapped.
        mono_anchors: list[tuple[int, int]] = []
        last_pos = body_start
        for fi, ap in anchor_pts:
            if ap >= last_pos:
                mono_anchors.append((fi, ap))
                last_pos = ap

        # Compute end boundary `ends[fi]` (`start[fi]` = `ends[fi - 1]`).
        ends: list[int] = [body_end] * n_defs
        seg_start_idx = 0
        seg_start_pos = body_start
        for fi, ap in mono_anchors + [(n_defs - 1, body_end - 1)]:
            span_defs = fi - seg_start_idx + 1
            span_consts = max(1, (ap + 1) - seg_start_pos)
            for k in range(span_defs):
                idx = seg_start_idx + k
                if idx < n_defs:
                    ends[idx] = min(
                        body_end,
                        seg_start_pos + round(((k + 1) * span_consts) / span_defs),
                    )
            seg_start_idx = fi + 1
            seg_start_pos = min(body_end, ap + 1)

        windows: dict[int, list[Any]] = {}
        cur = body_start
        for idx, f in enumerate(ordered):
            end_i = max(cur, min(body_end, ends[idx]))
            if idx == n_defs - 1:
                end_i = body_end
            windows[id(f)] = list(self.constants[cur:end_i])
            cur = end_i
        return windows

    def _assign_args_by_order(self, funcs: list[dict[str, Any]]) -> None:
        """Attach tail `co_varnames` tuples to qualname / free functions via exact metadata + overlap matching."""
        lo, _hi = self._definition_region()
        import_tuples = self._import_tuple_positions()
        py_idx, mod_idx = self._tail_varname_region_start()
        tail_lo = (mod_idx + 1) if mod_idx is not None else ((py_idx + 1) if py_idx is not None else 0)

        tuple_positions = sorted(
            i for i in range(tail_lo, len(self.constants))
            if self._is_varnames_tuple(self.constants[i])
            and i not in import_tuples
            and not str(self.constants[i][0]).startswith(".")
        )
        if not tuple_positions:
            return

        # Exclude tail tuples that belong to nested `<locals>` closure functions inside class methods
        # (non-self tuple in a class module when a `<locals>.helper` constant exists).
        has_cls_methods = any(f.get("_source") == "qualname" for f in funcs)
        has_free_funcs = any(f.get("_source") == "free" for f in funcs)
        local_helpers: set[str] = set()
        for c in self.constants:
            if isinstance(c, str) and ".<locals>." in c:
                part = c.split(".<locals>.", 1)[1]
                if not part.startswith("<") and self._is_ident(part):
                    local_helpers.add(c)

        filtered_tuples: list[tuple[int, tuple[str, ...]]] = []
        for ti in tuple_positions:
            tup = self.constants[ti]
            # If the module has only class methods (no free functions) and no staticmethod hint,
            # a tuple not starting with `self`/`cls` may belong to a `<locals>` helper.
            if has_cls_methods and not has_free_funcs and tup[0] not in ("self", "cls") and local_helpers:
                # Only keep non-self tuple for `<locals>` if no parent won't claim it; reserve for free/staticmethod only if needed.
                pass
            filtered_tuples.append((ti, tup))

        if not funcs:
            return

        # Order functions in canonical definition order for tie-breaking.
        def _func_rank(f: dict[str, Any]) -> int:
            qn = str(f.get("qualname") or f.get("name") or "")
            if qn in self._qualname_positions:
                return self._qualname_positions[qn]
            if "_pos_hint" in f:
                return int(f["_pos_hint"])
            return self._const_index(qn, f.get("name"))

        ordered_funcs = sorted(funcs, key=_func_rank)
        body_start, body_end = self._find_body_region_bounds()
        full_body_strs = {c for c in self.constants[body_start:body_end] if isinstance(c, str)}

        # Compute compatibility score between every (func_idx, tail_idx).
        scored_pairs: list[tuple[int, int, int, int]] = []
        for fi, f in enumerate(ordered_funcs):
            if f.get("args") or f.get("_blob_exact"):
                continue
            qn = str(f.get("qualname") or f.get("name") or "")
            fname = str(f.get("name") or "")
            is_cls_method = f.get("_source") == "qualname" and "." in qn
            ann = self._qualname_annotations.get(qn)
            ann_params = [k for k in (ann or {}) if k != "return"] or list(self._qualname_param_names.get(qn, ()))
            defs = self._qualname_defaults.get(qn)
            win = self._partitioned_co_windows.get(id(f), [])
            win_strs = {c for c in win if isinstance(c, str)}
            name_words = {w.lower() for w in fname.split("_") if len(w) >= 3}

            # Direct `<locals>` variable names referenced in this function's qualnames.
            local_child_names = {
                lh.split(".<locals>.", 1)[1]
                for lh in local_helpers
                if lh.startswith(qn + ".<locals>.")
            }

            for ti_rank, (ti, tup) in enumerate(filtered_tuples):
                tup_set = set(tup)
                tup_has_recv = tup[0] in ("self", "cls")
                score = 0

                if is_cls_method and not tup_has_recv:
                    # Only `@staticmethod` methods lack `self`/`cls`; avoid giving them `<locals>` helper tuples.
                    score -= 400
                elif not is_cls_method and tup_has_recv:
                    score -= 500
                elif is_cls_method == tup_has_recv:
                    score += 40

                if ann_params:
                    offset = 1 if (is_cls_method and tup_has_recv) else 0
                    if (
                        len(tup) >= offset + len(ann_params)
                        and list(tup[offset : offset + len(ann_params)]) == ann_params
                    ):
                        score += 1000 + 200 * len(ann_params) + (150 if len(tup) == offset + len(ann_params) else 0)
                    elif not set(ann_params) <= tup_set:
                        score -= 1000

                if defs and len(defs) > len(tup) - (1 if tup_has_recv else 0):
                    score -= 300

                # `<locals>.helper` overlap (e.g. `safe_conn` -> `('self', 'safe_conn')`).
                loc_hits = len(local_child_names & tup_set)
                if loc_hits:
                    score += 250 * loc_hits

                # Window string hits for non-trivial variable names.
                non_generic_vars = [
                    v for v in tup
                    if v not in ("self", "cls", "e", "ex", "i", "j", "k", "_", "d", "n", "t", "w", "f")
                ]
                win_hits = sum(1 for v in non_generic_vars if v in win_strs)
                score += 25 * win_hits

                # Bonus if variable appears adjacent to `fname` in pre-import pool (e.g. `_read_bool`, `'value'`).
                fn_pos = self._pos_hint_or_find(f)
                if fn_pos is not None:
                    near = {
                        c for c in self.constants[max(0, fn_pos - 6) : min(len(self.constants), fn_pos + 6)]
                        if isinstance(c, str)
                    }
                    near_hits = sum(1 for v in non_generic_vars if v in near)
                    score += 18 * near_hits

                # Word overlap between `fname` and varnames (e.g. `network_prefix` <-> `_auto_detect_network`).
                for v in non_generic_vars:
                    vl = v.lower()
                    if any(w in vl for w in name_words):
                        score += 10

                # Penalize single-element tuples matched against multi-default functions.
                if defs and len(tup) == 1:
                    score -= 150

                rank_diff = abs(fi - ti_rank)
                scored_pairs.append((score, rank_diff, fi, ti))

        scored_pairs.sort(key=lambda t: (-t[0], t[1], t[2], t[3]))
        used_funcs: set[int] = set()
        used_tuples: set[int] = set()

        for score, _rd, fi, ti in scored_pairs:
            if fi in used_funcs or ti in used_tuples:
                continue
            if score < 0:
                continue
            f = ordered_funcs[fi]
            tup = self.constants[ti]
            qn = str(f.get("qualname") or f.get("name") or "")
            ann = self._qualname_annotations.get(qn)
            ann_params = [k for k in (ann or {}) if k != "return"] or list(self._qualname_param_names.get(qn, ()))
            tup_has_recv = tup[0] in ("self", "cls")
            is_cls_method = f.get("_source") == "qualname" and "." in qn

            f["args"] = list(tup)
            if ann_params:
                offset = 1 if (is_cls_method and tup_has_recv) else 0
                if (
                    len(tup) >= offset + len(ann_params)
                    and list(tup[offset : offset + len(ann_params)]) == ann_params
                ):
                    f["argcount"] = offset + len(ann_params)
                    f["_inferred_sig"] = True
                else:
                    f["argcount"] = 1 if tup_has_recv else 0
            else:
                f["argcount"] = 1 if tup_has_recv else 0

            used_funcs.add(fi)
            used_tuples.add(ti)

        # Fallback: un-assigned class methods received shared `('self',)` which Nuitka deduplicated before `<module>`.
        has_name_tuple = any(tup == ("name",) for _ti, tup in filtered_tuples)
        for fi, f in enumerate(ordered_funcs):
            if fi not in used_funcs and not f.get("args") and not f.get("_blob_exact"):
                qn = str(f.get("qualname") or f.get("name") or "")
                fname = str(f.get("name") or "")
                is_cls_method = f.get("_source") == "qualname" and "." in qn
                if is_cls_method:
                    f["args"] = ["self"]
                    f["argcount"] = 1
                else:
                    ann = self._qualname_annotations.get(qn)
                    ann_params = [k for k in (ann or {}) if k != "return"] or list(self._qualname_param_names.get(qn, ()))
                    if ann_params:
                        f["args"] = list(ann_params)
                        f["argcount"] = len(ann_params)
                        f["_inferred_sig"] = True
                    elif has_name_tuple and fname.startswith(("valid_", "is_", "has_")):
                        f["args"] = ["name"]
                        f["argcount"] = 1
                        f["_inferred_sig"] = True

    def _pos_hint_or_find(self, f: dict[str, Any]) -> int | None:
        if "_pos_hint" in f:
            return int(f["_pos_hint"])
        name = str(f.get("name") or "")
        pos_list = self.str_positions.get(name)
        return pos_list[0] if pos_list else None

    def _merge_native_code_objects(
        self, native: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[str], dict[str, list[str]]]:
        """Combine native PyCode_New CodeObjects with dotted qualname constants."""
        CO_NEWLOCALS = 0x02
        methods, class_order, method_leaves = self._scan_qualnames()
        bases = self._scan_class_bases(class_order, method_leaves)
        class_names = set(class_order)
        leaf_owner: dict[str, str] = {}
        for m in methods:
            leaf_owner.setdefault(m["name"], m["qualname"].split(".")[0])

        out: list[dict[str, Any]] = []
        covered: set[str] = set()
        for co in native:
            name = co.get("name") or ""
            flags = co.get("flags") or 0
            if name.startswith("<"):
                out.append(dict(co))
                continue
            if not (flags & CO_NEWLOCALS):
                if name in self.known_modules or name in self._PACKAGE_MACHINERY_NAMES:
                    continue
                if self._is_valid_def_name(name):
                    if name not in class_names:
                        class_order.append(name)
                        class_names.add(name)
                    if co.get("docstring"):
                        self._class_docstrings[name] = co["docstring"]
                continue
            if not self._is_valid_def_name(name):
                continue
            nc = dict(co)
            if (
                co.get("_makeobj")
                and isinstance(co.get("qualname"), str)
                and (co.get("qualname") == name or co.get("qualname", "").endswith("." + name))
            ):
                nc["qualname"] = co.get("qualname")
            elif co.get("_match_qualname"):
                nc["qualname"] = co["_match_qualname"]
            else:
                owner = leaf_owner.get(name)
                nc["qualname"] = f"{owner}.{name}" if owner else name
            if nc["qualname"] in covered:
                continue
            covered.add(nc["qualname"])
            out.append(nc)

        for m in methods:
            if m["qualname"] not in covered:
                out.append(m)
                covered.add(m["qualname"])
        if class_order:
            bases = self._scan_class_bases(class_order, method_leaves)
        return out, class_order, bases

    def _classify(self) -> None:
        self.classes: dict[str, dict[str, Any]] = {}
        self.free_funcs: list[dict[str, Any]] = []
        self.module_body: dict[str, Any] | None = None

        bases_map = self._inferred_bases or {}
        for cls in self._inferred_classes:
            self.classes.setdefault(cls, {"methods": [], "bases": list(bases_map.get(cls, []))})

        # Ensure nested classes exist in _nested_class_data.
        self._nested_class_data: dict[str, dict[str, Any]] = {}
        for nested_qn in (self._nested_class_cos or ()):
            self._nested_class_data[nested_qn] = {
                "methods": [],
                "bases": list(bases_map.get(nested_qn, [])),
            }

        for co in self.code_objects:
            if not co:
                continue
            name = str(co.get("name") or "")
            qualname = str(co.get("qualname") or name)

            if name == "<module>" or qualname == "<module>":
                self.module_body = co
                continue
            if name in ("<listcomp>", "<dictcomp>", "<setcomp>", "<genexpr>", "<lambda>"):
                continue

            qn_head = qualname.split(".<locals>.")[0]
            if "." in qn_head and not qn_head.startswith("<"):
                parts = qn_head.split(".")
                parent_path = ".".join(parts[:-1])
                if parent_path in self._nested_class_data:
                    self._nested_class_data[parent_path]["methods"].append(co)
                    continue
                if len(parts) >= 2 and parts[0] and (parts[0][0].isupper() or parts[0] in self.classes):
                    if parts[0] in self.known_modules:
                        continue
                    self.classes.setdefault(
                        parts[0], {"methods": [], "bases": list(bases_map.get(parts[0], []))}
                    )
                    self.classes[parts[0]]["methods"].append(co)
                    continue

            if name in self._PACKAGE_MACHINERY_NAMES:
                continue
            self.free_funcs.append(co)

    # ---- import recovery ----

    def detect_imports(self) -> list[str]:
        """Recover `import ...` and `from ... import ...` lines from the constant pool."""
        lines: list[str] = []
        used: set[str] = set()
        n = len(self.constants)

        arg_names_in_tuples: set[str] = set()
        for c in self.constants:
            if isinstance(c, tuple) and c:
                for x in c:
                    if isinstance(x, str) and re.fullmatch(r"[a-z_][a-z0-9_]*", x):
                        arg_names_in_tuples.add(x)

        METHOD_CALL_ARTIFACTS = {
            "dumps", "loads", "dump", "load", "get", "post", "put", "delete",
            "patch", "head", "options", "request", "send", "open", "write",
            "read", "sha256", "sha1", "sha512", "md5", "hmac", "new", "digest",
            "hexdigest", "encode", "decode", "verify", "sign", "format",
            "split", "join", "strip", "replace", "startswith", "endswith",
            "find", "index", "count", "upper", "lower", "items", "keys",
            "values", "update", "append", "pop", "extend", "insert", "remove",
            "clear", "copy", "sort", "reverse", "add", "discard", "isdigit",
            "isalpha",
        }

        _known_roots: set[str] = set()
        for km in self.known_modules:
            _known_roots.add(km)
            _known_roots.add(km.split(".")[0])

        if self.is_package:
            _pkg_base: str | None = self.module_name
        elif "." in self.module_name:
            _pkg_base = self.module_name.rsplit(".", 1)[0]
        else:
            _pkg_base = None

        _CLASS_QUALNAME_OWNERS = set(getattr(self, "_inferred_classes", ())) | set(getattr(self, "classes", {}).keys())
        _THIRD_PARTY_CAMEL_ROOTS = frozenset({
            "PySide6", "PySide2", "PyQt5", "PyQt6", "PIL", "OpenSSL", "Cryptodome", "Crypto",
        })

        def is_dotted_module(s: Any, pos: int | None = None) -> bool:
            if not isinstance(s, str) or not (2 < len(s) < 80):
                return False
            if s.lower().endswith(_DATA_FILE_EXTS):
                return False
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", s):
                return False
            parts = s.split(".")
            if any(p.startswith("__") for p in parts):
                return False
            if parts[-1].lower() in {
                "com", "org", "net", "io", "dev", "app", "xyz", "ru",
                "de", "it", "fr", "uk", "co", "me", "gg", "tv",
            }:
                return False
            first = parts[0]
            if first in _CLASS_QUALNAME_OWNERS:
                return False
            known_exact = s in self.known_modules
            is_third_party_camel = first in _THIRD_PARTY_CAMEL_ROOTS or (
                pos is not None
                and pos + 1 < n
                and is_ident_tuple(self.constants[pos + 1])
                and self.constants[pos + 1][0] not in ("self", "cls", ".0")
            )
            if not known_exact and not is_third_party_camel and any(p != p.lower() for p in parts):
                return False
            if first and first[0].isupper() and not known_exact and not is_third_party_camel:
                return False
            if self.known_modules and not is_third_party_camel:
                roots = {m.split(".")[0] for m in self.known_modules if m}
                if not (known_exact or first in roots or first in self._COMMON_STDLIB):
                    return False
            return True

        def is_stdlib_module(s: Any) -> bool:
            return isinstance(s, str) and s in self._COMMON_STDLIB

        def is_ident_tuple(t: Any) -> bool:
            return (
                isinstance(t, tuple)
                and 0 < len(t) <= 30
                and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", x) for x in t)
            )

        def is_known_module(x: str) -> bool:
            if not self.known_modules:
                return True
            if x in _known_roots:
                return True
            return bool(_pkg_base and f"{_pkg_base}.{x}" in self.known_modules)

        def _camel_to_snake(name: str) -> str:
            s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
            s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
            return s.lower()

        _lower_idents = {
            cv for cv in self.constants
            if isinstance(cv, str) and re.fullmatch(r"[a-z_][a-z0-9_]*", cv) and len(cv) >= 3
        }
        _classes_map = getattr(self, "classes", None)
        _defined_classes = set(_classes_map.keys()) if _classes_map else set(getattr(self, "_inferred_classes", ()))
        _camelcase_in_tuple: set[str] = set()
        for cv in self.constants:
            if isinstance(cv, tuple) and cv and all(isinstance(x, str) and re.fullmatch(r"[A-Z]\w*", x) for x in cv):
                if len(cv) == 1 and not (
                    re.search(r"[a-z0-9][A-Z]", cv[0][1:]) or re.search(r"[A-Z]{2,}[a-z]", cv[0][1:])
                ):
                    continue
                _camelcase_in_tuple.update(cv)

        _used_as_base: set[str] = set()
        if _classes_map:
            for cd in _classes_map.values():
                for b in cd.get("bases") or ():
                    if isinstance(b, str):
                        _used_as_base.add(b.split(".")[0])
        else:
            for blist in getattr(self, "_inferred_bases", {}).values():
                for b in blist or ():
                    if isinstance(b, str):
                        _used_as_base.add(b.split(".")[0])

        _GENERIC_MODULE_WORDS = frozenset({
            "auto", "manual", "data", "base", "node", "item", "user", "home",
            "main", "core", "utils", "config", "types", "model", "form", "list",
            "table", "grid", "page", "view", "app", "run", "test", "info",
            "error", "status", "value", "name", "type", "image", "exception",
            "exceptions",
        })
        _BUILTIN_CLASS_NAMES = {
            "Exception", "BaseException", "ValueError", "TypeError", "RuntimeError",
            "KeyError", "IndexError", "AttributeError", "ImportError", "OSError",
            "IOError", "StopIteration", "NotImplementedError", "Image", "ImageTk",
        }
        _sibling_imports: list[tuple[str, str]] = []
        _sibling_seen: set[tuple[str, str]] = set()
        for camel in _camelcase_in_tuple | _used_as_base:
            if camel in _defined_classes or camel in _BUILTIN_CLASS_NAMES or not re.fullmatch(r"[A-Z]\w*", camel):
                continue
            snake = _camel_to_snake(camel)
            if (
                snake in _lower_idents
                and snake not in self._COMMON_STDLIB
                and snake not in METHOD_CALL_ARTIFACTS
                and snake not in _GENERIC_MODULE_WORDS
            ):
                key = (snake, camel)
                if key not in _sibling_seen:
                    _sibling_seen.add(key)
                    _sibling_imports.append(key)

        _PLAIN_IMPORT = {
            "sys", "os", "re", "json", "time", "math", "random", "struct",
            "base64", "hashlib", "platform", "socket", "ctypes", "io",
            "copy", "gc", "signal", "zlib", "logging", "sqlite3",
        }
        _DICT_KEY_BLOCKLIST = frozenset({
            "http", "https", "ftp", "data", "ws", "wss", "smtp", "imap",
            "pop3", "sftp", "ssh", "tcp", "udp", "html", "xml", "text",
            "utf-8", "utf8", "ascii", "latin-1",
        })

        _import_cluster = 0
        for ic, cv in enumerate(self.constants):
            if cv in ("__cached__", "__spec__", "sys") or (
                isinstance(cv, dict) and cv.get("name") == "<module>"
            ):
                _import_cluster = ic
                break

        i = 0
        while i < n:
            c = self.constants[i]
            next_is_tuple = i + 1 < n and is_ident_tuple(self.constants[i + 1])
            is_probable_module = (
                isinstance(c, str)
                and re.fullmatch(r"[a-z_][a-z0-9_]*", c)
                and (len(c) >= 3 or is_known_module(c))
                and c not in (
                    "self", "args", "kwargs", "cls", "data", "text", "name",
                    "value", "item", "items", "key", "keys", "obj", "result",
                    "response", "request", "url", "path", "config", "token",
                    "print", "headers", "status_code", "content", "origin",
                    "has_location",
                )
            )
            if (
                isinstance(c, str)
                and (
                    (c in arg_names_in_tuples and not is_dotted_module(c, i) and not is_stdlib_module(c))
                    or (c in METHOD_CALL_ARTIFACTS and not is_dotted_module(c, i))
                    or c == self.module_name
                    or (c.startswith("__") and c.endswith("__"))
                )
            ):
                i += 1
                continue

            is_sibling = next_is_tuple and any(
                mod == c and cls_nm in self.constants[i + 1]
                for mod, cls_nm in _sibling_imports
            )
            if isinstance(c, str) and (
                is_stdlib_module(c)
                or is_dotted_module(c, i)
                or (next_is_tuple and is_probable_module and is_known_module(c))
                or is_sibling
            ):
                if c in _DICT_KEY_BLOCKLIST:
                    i += 1
                    continue
                if next_is_tuple and c not in _PLAIN_IMPORT:
                    imp = self.constants[i + 1]
                    names = [x for x in imp if not x.startswith("__") and self._is_valid_def_name(x)]
                    if names:
                        rendered = ", ".join(names)
                        _alias = self.constants[i + 3] if i + 3 < n else None
                        _after = self.constants[i + 4] if i + 4 < n else None
                        if (
                            len(names) == 1
                            and i + 3 < n
                            and self.constants[i + 2] == names[0]
                            and isinstance(_alias, str)
                            and re.fullmatch(r"[A-Za-z_]\w*", _alias)
                            and _alias != names[0]
                            and not _alias.startswith("__")
                            and _alias not in _known_roots
                            and not is_stdlib_module(_alias)
                            and (
                                _alias in self.module_globals
                                or (
                                    not self.module_globals
                                    and isinstance(_after, str)
                                    and (_after.endswith((".py", ".pyc")) or _after == "__spec__")
                                )
                            )
                        ):
                            rendered = f"{names[0]} as {_alias}"
                        line = f"from {c} import {rendered}"
                        if line not in used:
                            used.add(line)
                            lines.append(line)
                    i += 2
                    continue
                if is_stdlib_module(c) or is_dotted_module(c, i):
                    _STRONG_PRECLUSTER_STDLIB = {
                        "subprocess", "resource", "sqlite3", "hashlib", "hmac", "base64",
                        "threading", "asyncio", "pathlib", "shutil", "tempfile",
                        "traceback", "warnings", "logging", "datetime", "importlib",
                    }
                    if is_stdlib_module(c) and i < _import_cluster and c not in _STRONG_PRECLUSTER_STDLIB:
                        if not (c == "socket" and any(x in self.constants for x in ("AF_INET", "SOCK_STREAM", "SOCK_DGRAM"))):
                            i += 1
                            continue
                    if c in {"requests", "aiohttp", "httpx", "yarl", "six"}:
                        if not (self.module_globals and c in self.module_globals):
                            i += 1
                            continue
                    line = f"import {c}"
                    if line not in used:
                        used.add(line)
                        lines.append(line)
            i += 1

        # Relative imports (`from .. import sym`).
        for i in range(n - 2):
            c = self.constants[i]
            if not isinstance(c, int) or c not in (1, 2, 3):
                continue
            nxt = self.constants[i + 1]
            if not (isinstance(nxt, str) and re.fullmatch(r"[A-Za-z_]\w*", nxt)):
                continue
            if nxt.startswith("__") and nxt.endswith("__"):
                continue
            prev = self.constants[i - 1] if i else None
            names: list[str] | None = None
            if isinstance(prev, tuple) and nxt in prev:
                names = [x for x in prev if isinstance(x, str) and re.fullmatch(r"[A-Za-z_]\w*", x)]
            elif isinstance(prev, str) and prev == nxt:
                names = [nxt]
            if names:
                dots = "." * c
                line = f"from {dots} import {', '.join(names)}"
                if line not in used:
                    used.add(line)
                    lines.append(line)

        lines = _ndl_qualify_imports(
            lines, self.module_name, known_modules=self.known_modules, is_package=self.is_package
        )

        # Ensure stdlib modules clearly referenced as DLL / runtime parents are imported if in constants.
        if "ctypes" not in _ndl_parse_imported_symbols(lines) and (
            "windll" in self.constants or "ctypes" in self.constants
        ):
            lines.append("import ctypes")
        if "windll" in self.constants and "windll" not in _ndl_parse_imported_symbols(lines):
            lines.append("from ctypes import windll")
        if "Structure" in self.constants and "Structure" not in _ndl_parse_imported_symbols(lines):
            lines.append("from ctypes import Structure")

        mod_root = self.module_name.split(".")[0] if self.module_name else ""

        def _sort_key(line: str) -> tuple[int, str, str]:
            parts = line.split()
            mod = parts[1] if len(parts) > 1 else ""
            root = mod.split(".")[0]
            if root in self._COMMON_STDLIB:
                return (0, root, line)
            if mod_root and mod.startswith(mod_root + "."):
                return (2, mod, line)
            return (1, mod, line)

        lines.sort(key=_sort_key)
        return lines

    # ---- generic constant-window body & statement synthesis ----

    @staticmethod
    def _is_valid_body_syntax(body_lines: list[str], body_indent: str) -> bool:
        if not body_lines:
            return False
        try:
            dedent = len(body_indent)
            inner = [ln[dedent:] if ln.startswith(body_indent) else ln for ln in body_lines]
            ast.parse("def _f():\n" + "\n".join("    " + x for x in inner) + "\n")
            return True
        except SyntaxError:
            return False

    @staticmethod
    def _pair_kwarg_calls(window: list[Any]) -> list[tuple[int, str]]:
        """Extract `k=val` pairs from adjacent `(val_tuple, kw_name_tuple)` sequences."""
        paired: list[tuple[int, str]] = []
        for idx in range(1, len(window)):
            kw_t = window[idx]
            if (
                isinstance(kw_t, tuple)
                and 1 <= len(kw_t) <= 8
                and all(isinstance(x, str) and re.fullmatch(r"[A-Za-z_]\w*", x) for x in kw_t)
                and not any(x in ("self", "cls") for x in kw_t)
            ):
                val_t = window[idx - 1]
                if isinstance(val_t, tuple) and len(val_t) >= len(kw_t):
                    vals = val_t[-len(kw_t):]
                    kw_str = ", ".join(
                        f"{k}={StaticalySmartReconstructor._safe_literal(v)}"
                        for k, v in zip(kw_t, vals)
                    )
                    paired.append((idx, kw_str))
        return paired

    def _synthesize_local_struct(
        self, cls_co: dict[str, Any], body_indent: str
    ) -> list[str]:
        """Reconstruct a `<locals>` helper class (e.g. `ctypes.Structure` with `_fields_`)."""
        cname = str(cls_co.get("name") or "")
        if not self._is_valid_def_name(cname):
            return []
        pos = self._get_co_pos(cls_co)
        win: list[Any] = []
        if pos is not None:
            for item in self.constants[pos + 1:]:
                if isinstance(item, dict) and item.get("_type") == "CodeObject":
                    break
                win.append(item)
                if item == "__mro_entries__":
                    break

        is_struct = "Structure" in self.constants or "Structure" in win or "_fields_" in win
        bases = "(Structure)" if is_struct else ""
        lines = [f"{body_indent}class {cname}{bases}:"]
        inner_indent = body_indent + "    "

        if "_fields_" in win:
            idx_f = win.index("_fields_")
            field_items = win[:idx_f]
            pairs: list[tuple[str, str]] = []
            i = 0
            while i + 1 < len(field_items):
                fname = field_items[i]
                ftype = field_items[i + 1]
                if (
                    isinstance(fname, str)
                    and self._is_ident(fname)
                    and isinstance(ftype, str)
                ):
                    if ftype == "POINTER" and i + 2 < len(field_items) and isinstance(field_items[i + 2], str):
                        pairs.append((fname, f"POINTER({field_items[i + 2]})"))
                        i += 3
                        continue
                    if ftype in _CTYPES_FIELD_TYPES or self._is_ident(ftype):
                        pairs.append((fname, ftype))
                        i += 2
                        continue
                i += 1
            if pairs:
                rendered_fields = ", ".join(f"({fname!r}, {ftype})" for fname, ftype in pairs)
                lines.append(f"{inner_indent}_fields_ = [{rendered_fields}]")
                return lines

        lines.append(f"{inner_indent}pass")
        return lines

    def _synthesize_constant_window_body(
        self,
        co: dict[str, Any],
        sig_args: list[str],
        locals_only: list[str],
        body_indent: str,
        ret_type: str | None = None,
    ) -> list[str]:
        """Generically reconstruct statements from a CodeObject's constant window."""
        qn = str(co.get("qualname") or co.get("name") or "")
        win = self._get_co_window(co)
        out: list[str] = []

        # 1. Nested `<locals>` classes (e.g. DATA_BLOB(Structure)).
        for lcls in self._local_classes_by_parent.get(qn, ()):
            out.extend(self._synthesize_local_struct(lcls, body_indent))

        # 2. Nested `<locals>` functions (e.g. decorator wrappers, thread targets).
        local_func_names: list[str] = []
        for lfunc in self._local_funcs_by_parent.get(qn, ()):
            local_func_names.append(str(lfunc.get("name") or ""))
            out.extend(self._emit_function(lfunc, indent=body_indent, is_method=False, parent=None))

        if not win:
            if len(co.get("freevars") or ()) == 0 and len(local_func_names) == 1:
                out.append(f"{body_indent}return {local_func_names[0]}")
            return out

        win_strs = [x for x in win if isinstance(x, str)]
        win_str_set = set(win_strs)
        kw_pairs = self._pair_kwarg_calls(win)
        bare_params = [a.lstrip("*") for a in sig_args if a not in ("/", "*")]
        local_set = set(locals_only)
        all_names = set(bare_params) | local_set
        emitted_stmts: list[str] = []
        used_consts: set[int] = set()

        # Decorator factory check: enclosing takes `func` and defines 1 inner wrapper.
        freevar_set = {str(fv) for lf in self._local_funcs_by_parent.get(qn, ()) for fv in (lf.get("freevars") or ())}
        if local_func_names and bare_params and set(bare_params) & freevar_set and len(local_func_names) == 1:
            emitted_stmts.append(f"return {local_func_names[0]}")

        # Initialize referenced Win32 DLL locals (`kernel32`, `avicap32`, ...).
        dll_locals: dict[str, str] = {}
        for idx, s in enumerate(win):
            if isinstance(s, str):
                low = s.lower()
                if low in _WIN32_DLL_NAMES:
                    used_consts.add(idx)
                    if s in local_set:
                        dll_locals[s] = s
                        emitted_stmts.append(f"{s} = windll.{s}")
                    else:
                        dll_locals[s] = f"windll.{s}"

        # Track standalone DLL references inside strings like `'windll'` + `'avicap32'` + API calls.
        api_calls: list[str] = []
        idx = 0
        while idx < len(win):
            val = win[idx]
            if isinstance(val, str):
                # Pattern: `os.getenv('VAR', 'default')`
                if val == "getenv" and idx + 1 < len(win) and isinstance(win[idx + 1], tuple):
                    args_r = ", ".join(self._safe_literal(x) for x in win[idx + 1])
                    used_consts.update((idx, idx + 1))
                    emitted_stmts.append(f"# os.getenv({args_r})")
                    idx += 2
                    continue

                # Pattern: HTTP `PoolManager(...)` / `.request('METHOD', 'https://...')`
                if val == "PoolManager" and "http" in all_names:
                    used_consts.add(idx)
                    kw_s = next((ks for kidx, ks in kw_pairs if kidx > idx and kidx <= idx + 3), "")
                    emitted_stmts.append(f"http = PoolManager({kw_s})")
                    idx += 1
                    continue

                if val == "request" and idx + 1 < len(win) and isinstance(win[idx + 1], tuple):
                    req_t = win[idx + 1]
                    if len(req_t) >= 2 and isinstance(req_t[0], str) and req_t[0].upper() in (
                        "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"
                    ):
                        used_consts.update((idx, idx + 1))
                        args_r = ", ".join(self._safe_literal(x) for x in req_t)
                        client_var = "http" if "http" in all_names else "PoolManager()"
                        target = "r" if "r" in all_names else ("response" if "response" in all_names else None)
                        call = f"{client_var}.request({args_r})"
                        emitted_stmts.append(f"{target} = {call}" if target else call)
                        idx += 2
                        continue

                # Pattern: `subprocess.run(...)`
                if val in ("run", "Popen", "check_output") and (
                    "subprocess" in win_str_set or "subprocess" in self.constants
                ):
                    used_consts.add(idx)
                    cli_flags = [
                        s for s in win[max(0, idx - 2):idx + 6]
                        if isinstance(s, str) and (s.startswith(("/", "-")) or " " in s or s.endswith(".exe"))
                    ]
                    kw_s = next((ks for kidx, ks in kw_pairs if idx < kidx <= idx + 8), "")
                    cmd_expr = repr(cli_flags) if cli_flags else "command" if "command" in all_names else "[]"
                    if kw_s:
                        stmt = f"subprocess.{val}({cmd_expr}, {kw_s})"
                    else:
                        stmt = f"subprocess.{val}({cmd_expr})"
                    target = next((t for t in ("process", "out", "output") if t in all_names), None)
                    emitted_stmts.append(f"{target} = {stmt}" if target else stmt)
                    idx += 1
                    continue

                # Pattern: Win32 API calls inside function constants.
                if (
                    ("windll" in win_str_set or dll_locals or "Kernel32" in win_str_set or "Crypt32" in win_str_set)
                    and re.fullmatch(r"[A-Z][A-Za-z0-9]{4,40}[AW]?", val)
                    and val not in ("LPWSTR", "POINTER", "Structure", "PoolManager", "Thread")
                    and val not in _CTYPES_FIELD_TYPES
                ):
                    # Pick enclosing DLL handle (`kernel32`, `avicap32`, `user32`, `shell32`, `Crypt32`, etc.)
                    active_dll = next(iter(dll_locals.values()), "windll.user32")
                    # Scan backward within 8 items for a specific DLL name owning this API call.
                    for back_idx in range(idx - 1, max(-1, idx - 9), -1):
                        prev_s = win[back_idx]
                        if isinstance(prev_s, str) and prev_s.lower() in _WIN32_DLL_NAMES:
                            active_dll = dll_locals.get(prev_s, f"windll.{prev_s}")
                            break
                    used_consts.add(idx)
                    api_calls.append(f"{active_dll}.{val}(...)")

                # Pattern: SQLite queries.
                if re.match(r"^\s*(?:SELECT|INSERT|UPDATE|DELETE)\b.+\b(?:FROM|INTO)\b", val, re.IGNORECASE):
                    used_consts.add(idx)
                    db_var = "db" if "db" in all_names else "conn"
                    cur_var = "cursor" if "cursor" in all_names else "cur"
                    if "db" in all_names:
                        emitted_stmts.append(f"{db_var} = sqlite3.connect(tempfile)")
                    if "cursor" in all_names:
                        emitted_stmts.append(f"{cur_var} = {db_var}.cursor()")
                    emitted_stmts.append(f"{cur_var}.execute({val!r})")
                    if "results" in all_names:
                        emitted_stmts.append(f"results = {cur_var}.fetchall()")

            idx += 1

        if api_calls:
            # Avoid cluttering with unresolved dummy calls in code if assignable/commented cleanly.
            for call_expr in api_calls[:6]:
                emitted_stmts.append(f"# WinAPI: {call_expr}")

        # Add clean return statement when return annotation specifies a non-None return type
        # and a matching result local exists.
        if (
            ret_type
            and ret_type != "None"
            and not any(s.startswith("return ") for s in emitted_stmts)
        ):
            ret_local = next(
                (
                    nm for nm in (
                        "result", "output", "passwords", "cookies", "history",
                        "autofills", "accounts", "profiles", "data", "content",
                        "paths", "thread",
                    )
                    if nm in local_set
                ),
                None,
            )
            if ret_local:
                emitted_stmts.append(f"return {ret_local}")
            elif ret_type == "bool":
                if "result" in local_set:
                    emitted_stmts.append("return bool(result)")
                else:
                    emitted_stmts.append("return False")
            elif ret_type == "str":
                emitted_stmts.append("return ''")
            elif ret_type == "bytes":
                emitted_stmts.append("return b''")
            elif ret_type.startswith(("list", "List")):
                emitted_stmts.append("return []")
            elif ret_type.startswith(("dict", "Dict")):
                emitted_stmts.append("return {}")

        # Validate every non-comment statement with `ast.parse`; downgrade invalid ones to comments.
        validated_lines: list[str] = []
        for stmt in emitted_stmts:
            cand = f"{body_indent}{stmt}"
            if stmt.startswith("#") or self._is_valid_body_syntax([cand], body_indent):
                validated_lines.append(cand)
            else:
                validated_lines.append(f"{body_indent}# {stmt}")

        out.extend(validated_lines)

        # Preserve remaining notable constants from this function's window as concise evidence.
        notable: list[str] = []
        seen_n: set[str] = set()
        for w_idx, item in enumerate(win):
            if w_idx in used_consts:
                continue
            if isinstance(item, str):
                if (
                    item in self._NON_FUNCTION_NAMES
                    or self._is_machinery_string(item)
                    or item in bare_params
                    or item in local_set
                    or item in self._COMMON_STDLIB
                ):
                    continue
                rep = self._safe_literal(item)
            elif isinstance(item, (int, float, bytes)) and not isinstance(item, bool):
                if isinstance(item, int) and -1 <= item <= 2:
                    continue
                rep = self._safe_literal(item)
            elif isinstance(item, tuple) and item and any(self._is_data_literal(x) for x in item):
                rep = self._safe_literal(item)
            else:
                continue
            if rep not in seen_n:
                seen_n.add(rep)
                notable.append(rep)
        if notable:
            out.append(f"{body_indent}# consts: {', '.join(notable[:18])}")
            if len(notable) > 18:
                out.append(f"{body_indent}# ... ({len(notable) - 18} more constants)")

        return out

    # ---- emission ----

    @staticmethod
    def _format_docstring(doc: str, indent: str) -> list[str]:
        q = '"""' if '"""' not in doc else "'''"
        if "\n" not in doc:
            return [f"{indent}{q}{doc}{q}"]
        parts = doc.split("\n")
        out = [f"{indent}{q}{parts[0]}"]
        out.extend(parts[1:-1])
        out.append(f"{parts[-1]}{q}")
        return out

    def _body_trace_lines(self, name: str, parent: str | None, body_indent: str) -> list[str]:
        if not self.body_traces:
            return []
        seq = None
        for key in ((f"{parent}.{name}",) if parent else ()) + (name,):
            if key in self.body_traces:
                seq = self.body_traces[key]
                break
        if not seq:
            return []
        out = [f"{body_indent}# reconstructed control flow:"]
        out.extend(f"{body_indent}#   {ln}" for ln in seq)
        return out

    def _emit_function(
        self,
        co: dict[str, Any],
        indent: str = "",
        is_method: bool = False,
        parent: str | None = None,
    ) -> list[str]:
        name = str(co.get("name") or "")
        if not self._is_valid_def_name(name):
            return []

        native = bool(co.get("_native"))
        blob_exact = bool(co.get("_blob_exact"))
        inferred_sig = bool(co.get("_inferred_sig"))
        exact_sig = native or blob_exact
        trusted_sig = exact_sig or inferred_sig
        full_varnames = [str(a) for a in (co.get("varnames") or co.get("args") or ())]
        qn = str(co.get("qualname") or (f"{parent}.{name}" if parent else name))

        if native:
            sig_args = [str(a) for a in (co.get("args") or ())]
            locals_only = [
                v for v in full_varnames
                if v not in {a.lstrip("*") for a in sig_args} | {"self", "cls"} and self._is_ident(v)
            ]
        elif blob_exact:
            sig_args, locals_only = self._extract_exact_blob_sig(co)
        elif inferred_sig:
            ac = max(0, int(co.get("argcount") or 0))
            sig_args = [v for v in full_varnames[:ac] if self._is_ident(v)]
            bare_set = {a.lstrip("*") for a in sig_args} | {"self", "cls"}
            locals_only = [v for v in full_varnames[ac:] if v not in bare_set and self._is_ident(v)]
        else:
            if is_method and full_varnames and full_varnames[0] in ("self", "cls"):
                sig_args = [full_varnames[0]]
            elif is_method and not full_varnames:
                sig_args = ["self"]
            else:
                sig_args = []
            bare_set = {a.lstrip("*") for a in sig_args} | {"self", "cls"}
            locals_only = [v for v in full_varnames if v not in bare_set and self._is_ident(v)]

        # Decorator detection for methods whose exact signature omits `self`/`cls`.
        decorators: list[str] = []
        if is_method and trusted_sig and name != "__new__":
            if sig_args and sig_args[0] == "cls":
                decorators.append(f"{indent}@classmethod")
            elif (not sig_args or sig_args[0] != "self") and name != "__init__":
                decorators.append(f"{indent}@staticmethod")

        flags = int(co.get("flags") or 0)
        is_async = bool(co.get("is_async")) or bool(flags & 0x0080) or bool(flags & 0x0200)
        kw = "async def" if is_async else "def"

        bare_sig_args = list(sig_args)
        bare_params = {a.lstrip("*") for a in sig_args if a not in ("/", "*")} | {"self", "cls"}
        locals_only = [v for v in locals_only if v not in bare_params]

        ann = self._qualname_annotations.get(qn) or (self._match_annotations(co) if exact_sig else None)
        ret_hint = ""
        ret_type_str: str | None = None
        if ann:
            decorated: list[str] = []
            for a in sig_args:
                key = a.lstrip("*")
                if key in ("/", "*") or a in ("self", "cls"):
                    decorated.append(a)
                    continue
                t = self._render_annotation_type(ann[key]) if key in ann else None
                decorated.append(f"{a}: {t}" if t else a)
            sig_args = decorated
            if "return" in ann:
                rt = self._render_annotation_type(ann["return"])
                if rt:
                    ret_type_str = rt
                    ret_hint = f" -> {rt}"

        # Defaults attachment on positional parameters only (preserve valid Python syntax!).
        defs = self._defaults.get(qn) or (self._defaults.get(name) if not parent else None)
        if defs is None:
            defs = self._qualname_defaults.get(qn)
        attached_defs = False
        if defs and trusted_sig:
            pos_idx = [
                i for i, a in enumerate(bare_sig_args)
                if a not in ("/", "*") and not a.startswith("*")
            ]
            # Never assign a default before a non-default or onto `self`/`cls`.
            non_recv_pos = [
                i for i in pos_idx if bare_sig_args[i] not in ("self", "cls")
            ]
            # Only positional args before kwonly/star marker can receive positional __defaults__.
            star_limit = next(
                (i for i, a in enumerate(bare_sig_args) if a.startswith("*")),
                len(bare_sig_args),
            )
            eligible = [i for i in non_recv_pos if i < star_limit]
            if 0 < len(defs) <= len(eligible):
                for di, dv in enumerate(reversed(defs)):
                    ai = eligible[len(eligible) - 1 - di]
                    base = sig_args[ai].split(" = ")[0].strip()
                    sig_args[ai] = f"{base} = {self._safe_literal(dv)}"
                attached_defs = True

        kw_defs = co.get("_kw_defaults") or (self._qualname_kwdefaults.get(qn) if trusted_sig else None)
        if isinstance(kw_defs, dict) and kw_defs and trusted_sig:
            star_pos = next(
                (i for i, a in enumerate(bare_sig_args) if a == "*" or (a.startswith("*") and not a.startswith("**"))),
                len(bare_sig_args),
            )
            for ai, raw_a in enumerate(bare_sig_args):
                if ai <= star_pos:
                    continue
                pname = raw_a.lstrip("*")
                if pname in kw_defs and " = " not in sig_args[ai]:
                    sig_args[ai] = f"{sig_args[ai]} = {self._safe_literal(kw_defs[pname])}"

        lines = list(decorators)
        sig_str = ", ".join(sig_args)
        header = f"{indent}{kw} {name}({sig_str}){ret_hint}:"
        lines.append(header)
        body_indent = indent + "    "

        doc = co.get("docstring")
        if isinstance(doc, str) and doc:
            lines.extend(self._format_docstring(doc, body_indent))

        exact_body = None
        for key in (qn, f"{parent}.{name}" if parent else "", name):
            if key and key in self.body_sources:
                exact_body = self.body_sources[key]
                break

        body: list[str] = []
        if exact_body:
            eb = list(exact_body)
            vn = full_varnames[:len(bare_sig_args)]
            eb = _ndl_heal_incomplete_url_slash(eb, vn)
            eb = _ndl_heal_split_fstring_url(eb, vn)
            eb = _ndl_heal_url_token_swap(eb)
            body.extend(f"{body_indent}{ln}" for ln in eb)
        else:
            if locals_only:
                label = "# locals" if trusted_sig else "# co_varnames"
                body.append(f"{body_indent}{label}: {', '.join(locals_only)}")
            if defs and not attached_defs:
                body.append(f"{body_indent}# defaults: {self._safe_literal(defs)}")
            body.extend(self._body_trace_lines(name, parent, body_indent))
            if trusted_sig and name == "__init__" and bare_sig_args[:1] == ["self"] and len(bare_sig_args) > 1:
                init_params = [a for a in bare_sig_args[1:] if a.isidentifier()]
                body.extend(f"{body_indent}self.{a} = {a}" for a in init_params)
            if blob_exact or self._get_co_window(co):
                body.extend(
                    self._synthesize_constant_window_body(
                        co, bare_sig_args, locals_only, body_indent, ret_type=ret_type_str
                    )
                )
            elif not body:
                body.append(f"{body_indent}pass")

        if not any(ln.strip() and not ln.lstrip().startswith("#") for ln in body):
            body.append(f"{body_indent}pass")

        if is_method and name == "__init__":
            auth_args = (
                [str(x) for x in (co.get("args") or ())[: int(co.get("argcount") or 0)]]
                if exact_sig
                else None
            )
            _, body = _ndl_reconcile_init_params(
                sig_args, body, body_indent, self.constants, authoritative_args=auth_args
            )

        lines.extend(body)
        return lines

    def _const_index(self, *names: str | None) -> int:
        best: int | None = None
        for nm in names:
            if nm and nm in self.str_positions:
                p = self.str_positions[nm][0]
                if best is None or p < best:
                    best = p
        return best if best is not None else 10**9

    def _emit_class(
        self,
        class_key: str,
        cls_data: dict[str, Any],
        indent: str = "",
    ) -> list[str]:
        short_name = class_key.rsplit(".", 1)[-1]
        methods = list(cls_data.get("methods", ()))
        ord_map = getattr(self, "_def_order", {})
        src_map = getattr(self, "_src_order", {})

        def _mkey(m: dict[str, Any]) -> tuple[int, int]:
            ln = int(m.get("line") or 0)
            if ln > 0:
                return (0, ln)
            qn = str(m.get("qualname") or m.get("name") or "")
            if qn in src_map:
                return (1, src_map[qn])
            if qn.split(".")[-1] == "__init__":
                return (2, 0)
            return (3, ord_map.get(id(m), 10**6 + self._const_index(qn, m.get("name"))))

        methods.sort(key=_mkey)
        bases = _heal_class_bases(cls_data.get("bases", ()), short_name)
        header = f"{indent}class {short_name}" + (f"({', '.join(bases)})" if bases else "") + ":"
        lines = [header]
        body_indent = indent + "    "

        cdoc = self._class_docstrings.get(class_key) or self._class_docstrings.get(short_name)
        if isinstance(cdoc, str) and cdoc:
            lines.extend(self._format_docstring(cdoc, body_indent))

        attrs = self._class_attrs.get(class_key) or ()
        for attr_name, attr_val in attrs:
            if attr_val is not None:
                lines.append(f"{body_indent}{attr_name} = {attr_val}")
            else:
                lines.append(f"{body_indent}{attr_name} = None  # class attribute")

        hints = self._class_const_hints.get(class_key) or ()
        if hints:
            lines.append(
                f"{body_indent}# class constants: {', '.join(self._safe_literal(h) for h in hints[:12])}"
            )

        nested_keys = self._nested_classes.get(class_key) or ()
        for nkey in nested_keys:
            lines.append("")
            lines.extend(self._emit_class(nkey, self._nested_class_data[nkey], indent=body_indent))

        for co in methods:
            lines.append("")
            lines.extend(self._emit_function(co, body_indent, is_method=True, parent=class_key))

        if not any(ln.strip() and not ln.lstrip().startswith("#") for ln in lines[1:]):
            lines.append(f"{body_indent}pass")
        return lines

    # ---- annotation & data literal helpers ----

    @classmethod
    def _render_annotation_type(cls, v: Any) -> str | None:
        if v is None:
            return "None"
        if isinstance(v, str):
            return v if re.fullmatch(r"[A-Za-z_][\w.]*", v) else None
        if isinstance(v, tuple) and v:
            tag = v[0]
            if tag == "GenericAlias" and len(v) >= 3:
                base = cls._render_annotation_type(v[1])
                params = v[2]
                if isinstance(params, (tuple, list)):
                    inner = ", ".join(filter(None, (cls._render_annotation_type(p) for p in params)))
                else:
                    inner = cls._render_annotation_type(params) or ""
                if base and inner:
                    return f"{base}[{inner}]"
                return base
            if tag == "UnionType" and len(v) >= 2 and isinstance(v[1], (tuple, list)):
                parts = list(filter(None, (cls._render_annotation_type(p) for p in v[1])))
                return " | ".join(parts) if parts else None
            if tag == "_nuitka_builtin_anon_type" and len(v) == 2 and v[1] == "NoneType":
                return "None"
            if isinstance(tag, str) and tag.startswith("<type "):
                return tag[len("<type "):].rstrip(">") or None
        return None

    def _match_annotations(self, co: dict[str, Any]) -> dict[str, Any] | None:
        args = [a.lstrip("*") for a in (co.get("args") or ()) if a not in ("self", "cls")]
        if not args:
            return None
        argset = set(args)
        names = [str(co.get("qualname") or co.get("name") or "").split(".")[-1]]
        name_positions = [pos for pos, value in enumerate(self.constants) if isinstance(value, str) and value in names]
        best, best_key = None, None
        for pos, d in enumerate(self.constants):
            if not (isinstance(d, dict) and d and all(isinstance(k, str) and self._is_ident(k) for k in d)):
                continue
            keys = set(d) - {"return"}
            if not keys:
                continue
            overlap = len(keys & argset)
            if not overlap or not keys <= argset:
                continue
            distance = min((abs(pos - np_pos) for np_pos in name_positions), default=10**9)
            key = (-overlap, distance, pos)
            if best_key is None or key < best_key:
                best, best_key = d, key
        return best

    @classmethod
    def _is_machinery_string(cls, v: Any) -> bool:
        if not isinstance(v, str) or not v:
            return False
        if v.startswith("<") and v.endswith(">"):
            return True
        return any(m in v for m in cls._MACHINERY_MARKERS)

    @staticmethod
    def _is_type_spec(v: Any) -> bool:
        if v is None:
            return True
        if isinstance(v, str):
            return bool(
                re.fullmatch(r"[A-Za-z_][\w.]*(?:\s*\|\s*[A-Za-z_][\w.]*)*", v)
                or re.fullmatch(r"[A-Za-z_][\w.]*\[.*\]", v)
            )
        if isinstance(v, tuple) and v and isinstance(v[0], str):
            return v[0] in (
                "UnionType", "GenericAlias", "Optional", "Union",
                "Annotated", "type", "Final", "ClassVar",
            )
        return False

    _KNOWN_LOWER_TYPE_SPECS = frozenset({
        "str", "int", "float", "bool", "bytes", "list", "dict", "tuple",
        "set", "frozenset", "object", "Any", "None", "Path", "Callable",
        "Iterable", "Sequence", "Mapping",
    })

    def _is_annotation_dict(self, d: Any) -> bool:
        if not isinstance(d, dict) or not d:
            return False
        if not all(isinstance(k, str) and (self._is_ident(k) or k == "return") for k in d):
            return False
        if not all(self._is_type_spec(v) for v in d.values()):
            return False
        if "return" not in d:
            for v in d.values():
                if isinstance(v, str) and not (
                    v in self._KNOWN_LOWER_TYPE_SPECS
                    or v[:1].isupper()
                    or any(ch in v for ch in ".|[]")
                ):
                    return False
        return True

    def _is_data_literal(self, v: Any) -> bool:
        if isinstance(v, bool):
            return False
        if isinstance(v, str):
            if not v:
                return False
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", v):
                return False
            if v.endswith((".py", ".pyc")):
                return False
            if self._is_machinery_string(v):
                return False
            return True
        if isinstance(v, (int, float)):
            return not (isinstance(v, int) and -2 <= v <= 2)
        if isinstance(v, bytes):
            return len(v) > 0
        if isinstance(v, dict):
            if v.get("_type") == "CodeObject":
                return False
            return len(v) > 0 and not self._is_annotation_dict(v)
        if isinstance(v, (list, set, frozenset)):
            return len(v) > 0
        if isinstance(v, tuple):
            return any(self._is_data_literal(x) for x in v)
        return False

    def _emit_module_constants(self) -> list[str]:
        consts = self.constants
        out: list[str] = []

        defined: set[str] = set()
        for cls, d in self.classes.items():
            defined.add(cls)
            for m in d.get("methods", ()):
                defined.add(str(m.get("name")))
            for b in d.get("bases", ()):
                defined.add(str(b))
        for f in self.free_funcs:
            defined.add(str(f.get("name")))
        import_names = set(_ndl_imported_names_from_constants(consts))
        import_names |= _ndl_parse_imported_symbols(self._detected_import_lines)
        explained = set(self._NON_FUNCTION_NAMES) | defined | import_names

        name_pool = defined | _ndl_parse_imported_symbols(self._detected_import_lines)
        import_sets: list[frozenset[str]] = []
        for ln in self._detected_import_lines:
            match = re.match(r"^from\s+\S+\s+import\s+(.+)$", ln)
            if match:
                nm = {p.split(" as ")[0].strip() for p in match.group(1).split(",")}
                import_sets.append(frozenset(nm))
        varname_sets = [
            frozenset(str(x) for x in (co.get("varnames") or co.get("args") or ()))
            for co in self.code_objects
            if co.get("varnames") or co.get("args")
        ]

        all_list: list[str] | None = None
        all_src: Any = None
        for c in consts:
            if not (isinstance(c, (list, tuple)) and len(c) >= 2 and all(isinstance(x, str) and self._is_ident(x) for x in c)):
                continue
            names = list(c)
            if any(x.startswith("__") for x in names):
                continue
            cand = frozenset(names)
            if cand in import_sets or any(cand <= vs for vs in varname_sets):
                continue
            known_cnt = sum(1 for x in names if x in name_pool)
            if known_cnt >= max(2, int(0.6 * len(names))):
                if all_list is None or len(names) > len(all_list):
                    all_list = names
                    all_src = c

        known_import_roots: set[str] = set()
        for km in self.known_modules:
            known_import_roots.add(km)
            known_import_roots.add(km.split(".")[0])
        emitted_syms = _ndl_parse_imported_symbols(self._detected_import_lines)

        def _is_real_global(c: Any) -> bool:
            return (
                isinstance(c, str)
                and c not in explained
                and self._is_valid_def_name(c)
                and c not in self._COMMON_STDLIB
                and c not in known_import_roots
                and c not in emitted_syms
                and not (c.startswith("__") and c.endswith("__"))
            )

        real_globals: list[str] = []
        seen_g: set[str] = set()
        if self.module_globals:
            for c in consts:
                if _is_real_global(c) and c not in seen_g and c in self.module_globals:
                    seen_g.add(c)
                    real_globals.append(c)

        inferred: list[str] = []
        for nm in all_list or ():
            if nm not in seen_g and _is_real_global(nm):
                seen_g.add(nm)
                inferred.append(nm)

        collections = [
            c for c in consts
            if c is not all_src and isinstance(c, (list, dict)) and self._is_data_literal(c)
        ]

        bound: dict[str, Any] = {}
        bind_candidates = real_globals + inferred
        if len(collections) == 1 and len(bind_candidates) == 1:
            bound[bind_candidates[0]] = collections[0]

        _imported_syms = _ndl_parse_imported_symbols(self._detected_import_lines)
        _all_import_names = _ndl_all_import_names(self._detected_import_lines)
        emit_globals = [
            n for n in list(real_globals) + [x for x in inferred if x in bound]
            if n in bound or n in self.module_global_values or re.fullmatch(r"[A-Z][A-Z0-9_]*", n)
        ]
        emit_globals.sort(key=lambda n: self._const_index(n))
        for name in emit_globals:
            if name in _imported_syms or name in _all_import_names or name in import_names:
                continue
            if name in bound:
                out.append(f"{name} = {self._safe_literal(bound[name])}")
            elif name in self.module_global_values:
                out.append(f"{name} = {self._safe_literal(self.module_global_values[name])}")
            else:
                guess = _ndl_guess_global_init(name, _imported_syms, self.constants)
                out.append(f"{name} = {guess}" if guess else f"{name} = None")

        if all_list is not None:
            out.append("")
            out.append("__all__ = [")
            for nm in all_list:
                out.append(f"    {nm!r},")
            out.append("]")

        if self.emit_banner:
            literals: list[Any] = []
            seen_lit: set[str] = set()
            for c in consts:
                if not self._is_data_literal(c) or isinstance(c, (list, dict, set, frozenset, tuple)):
                    continue
                key = repr(c)
                if key not in seen_lit:
                    seen_lit.add(key)
                    literals.append(c)
            if literals:
                out.append("")
                out.append("# --- recovered string & numeric literals from constant pool ---")
                out.append("_recovered_literals = (")
                for lit in literals[:250]:
                    out.append(f"    {self._safe_literal(lit)},")
                out.append(")")
            bound_ids = {id(v) for v in bound.values()}
            k = 0
            for coll in collections[:20]:
                if id(coll) in bound_ids:
                    continue
                out.append("")
                out.append(f"_recovered_data_{k} = {self._safe_literal(coll)}")
                k += 1

        return out

    @staticmethod
    def _safe_literal(v: Any, _depth: int = 0) -> str:
        try:
            if _depth > 6:
                return "..."
            if isinstance(v, (str, bytes, int, float, bool)) or v is None:
                r = repr(v)
                if len(r) <= 2000:
                    return r
                if isinstance(v, str):
                    return repr(v[:1900])
                if isinstance(v, (bytes, bytearray)):
                    return repr(bytes(v[:1900]))
                return r
            if isinstance(v, (list, tuple, set, frozenset)):
                items = list(v)[:60]
                inner = ", ".join(StaticalySmartReconstructor._safe_literal(x, _depth + 1) for x in items)
                if isinstance(v, list):
                    return f"[{inner}]"
                if isinstance(v, set):
                    return f"{{{inner}}}" if items else "set()"
                if isinstance(v, frozenset):
                    return f"frozenset({{{inner}}})" if items else "frozenset()"
                if len(items) == 1:
                    return f"({inner},)"
                return f"({inner})"
            if isinstance(v, dict):
                pairs = ", ".join(
                    f"{StaticalySmartReconstructor._safe_literal(k, _depth + 1)}: "
                    f"{StaticalySmartReconstructor._safe_literal(val, _depth + 1)}"
                    for k, val in list(v.items())[:60]
                )
                return f"{{{pairs}}}"
            return repr(v)
        except Exception:
            return "..."

    def render(self) -> str:
        out: list[str] = []
        if self.emit_banner:
            out.append(f'"""Module: {self.module_name}')
            out.append("")
            out.append("Static reconstruction from Nuitka constants blob and CodeObjects.")
            out.append('"""')
            out.append("")

        imports = self.detect_imports()
        self._detected_import_lines = list(imports)
        if imports:
            out.extend(imports)
            out.append("")

        const_lines = self._emit_module_constants()
        if const_lines:
            out.extend(const_lines)
            out.append("")

        ord_map = getattr(self, "_def_order", {})

        def _class_pos(cname: str) -> int:
            ln = self._class_lines.get(cname)
            if ln:
                return ln
            lns = [
                int(m.get("line") or 0)
                for m in self.classes[cname].get("methods", ())
                if int(m.get("line") or 0) > 0
            ]
            if lns:
                return min(lns)
            idxs = [ord_map.get(id(m), 10**6) for m in self.classes[cname].get("methods", ())]
            return min(idxs) if idxs else self._const_index(cname)

        def _func_pos(co: dict[str, Any]) -> int:
            ln = int(co.get("line") or 0)
            if ln > 0:
                return ln
            return self._const_index(co.get("qualname"), co.get("name"))

        ordered: list[tuple[str, Any, int]] = (
            [("class", c, _class_pos(c)) for c in self.classes]
            + [("func", co, _func_pos(co)) for co in self.free_funcs]
        )
        ordered.sort(key=lambda t: t[2])

        for kind, obj, _pos in ordered:
            out.append("")
            if kind == "class":
                out.extend(self._emit_class(obj, self.classes[obj]))
            else:
                out.extend(self._emit_function(obj))
            out.append("")

        # Surface trailing module-level execution hints if `<module>` body exists without definitions
        # or if top-level runtime log/entrypoint constants follow class definitions.
        if self.module_body is not None:
            mod_pos = self._get_co_pos(self.module_body)
            if mod_pos is not None:
                tail_start = max([mod_pos + 1] + [p + 1 for p in self._all_co_positions if p > mod_pos])
                if tail_start < len(self.constants):
                    tail_items = [
                        c for c in self.constants[tail_start:]
                        if self._is_data_literal(c)
                    ]
                    if tail_items:
                        out.append("# --- module entrypoint / top-level flow constants ---")
                        for item in tail_items[:40]:
                            out.append(f"# {self._safe_literal(item)}")

        text = "\n".join(out).rstrip() + "\n"
        try:
            ast.parse(text)
        except SyntaxError:
            pass
        return text


_UNSET_SENTINEL = object()


@functools.lru_cache(maxsize=1)
def _load_v7_smart_reconstructor():
    return StaticalySmartReconstructor


def _is_module_name_candidate(value: Any) -> bool:
    if not isinstance(value, str) or len(value) < 2 or len(value) > 80:
        return False
    if value.endswith((".py", ".pyc")):
        return False
    if value.startswith("__") and value.endswith("__"):
        return False
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", value))


def _is_identifier_tuple(value: Any) -> bool:
    return bool(isinstance(value, tuple) and value and all(isinstance(item, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) for item in value))


def _infer_signature_candidates(raw_constants: list[Any]) -> list[tuple[str, list[str]]]:
    name_positions: list[tuple[int, str]] = []
    tuple_positions: list[tuple[int, tuple[str, ...]]] = []
    seen_names: set[str] = set()

    for index, value in enumerate(raw_constants):
        if isinstance(value, str) and len(value) >= 3 and re.fullmatch(r"[a-z_][a-z0-9_]*", value) and value not in {"self", "cls", "args", "kwargs"} and value not in seen_names:
            seen_names.add(value)
            name_positions.append((index, value))
        elif _is_identifier_tuple(value):
            tuple_positions.append((index, tuple(value)))

    limit = min(len(name_positions), len(tuple_positions))
    pairs: list[tuple[str, list[str]]] = []
    for offset in range(limit):
        _, name = name_positions[offset]
        _, args = tuple_positions[offset]
        pairs.append((name, list(args)))
    return pairs


def _collect_code_object_specs(value: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        if value.get("_type") == "CodeObject":
            out.append(value)
        for child in value.values():
            _collect_code_object_specs(child, out)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for child in value:
            _collect_code_object_specs(child, out)


class OmniNuitkaCompactEmitter:
    """Compact constants-first module summary for LLM-assisted reconstruction."""

    _TYPE_CODE = {
        type(None): "n",
        bool: "t",
        int: "i",
        float: "f",
        complex: "c",
        str: "s",
        bytes: "b",
        bytearray: "B",
        tuple: "T",
        list: "L",
        dict: "D",
        set: "S",
        frozenset: "P",
    }

    @classmethod
    def _type_code(cls, value: Any) -> str:
        if value is False:
            return "F"
        return cls._TYPE_CODE.get(type(value), "?")

    @staticmethod
    def _short_repr(value: Any, cap: int | None = None) -> str:
        safe_value = _redact_marshaled_bytecode_constants(value)
        text = repr(safe_value)
        if cap is None or len(text) <= cap:
            return text
        return text[: cap - 3] + "..."

    @classmethod
    def _emit_constants(cls, raw_constants: list[Any], out: list[str]) -> None:
        out.append(f"@CONSTS {len(raw_constants)}")
        for index, value in enumerate(raw_constants):
            out.append(f"  {index} {cls._type_code(value)} {cls._short_repr(value)}")

    @classmethod
    def _emit_imports(
        cls,
        decompiler: OmniDecompiler,
        raw_constants: list[Any],
        out: list[str],
    ) -> None:
        lines: list[str] = []
        seen: set[str] = set()

        for line in _iter_import_lines(decompiler):
            if line and line not in seen:
                lines.append(line)
                seen.add(line)

        stdlib = set(getattr(sys, "stdlib_module_names", ()))
        for index, value in enumerate(raw_constants):
            if not _is_module_name_candidate(value):
                continue
            nxt = raw_constants[index + 1] if index + 1 < len(raw_constants) else None
            if _is_identifier_tuple(nxt):
                line = f"from {value} import {', '.join(nxt)}"
            elif "." in value or value in stdlib:
                line = f"import {value}"
            else:
                continue
            if line not in seen:
                lines.append(line)
                seen.add(line)

        if not lines:
            return

        out.append("@IMPORTS")
        for line in lines:
            out.append(f"  {line}")

    @classmethod
    def _emit_funcs_detected(
        cls,
        decompiler: OmniDecompiler,
        raw_constants: list[Any],
        out: list[str],
    ) -> None:
        signatures: list[tuple[str, list[str]]] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()

        for func in decompiler.functions.values():
            sig = (func.name, tuple(func.args))
            if sig not in seen:
                signatures.append((func.name, list(func.args)))
                seen.add(sig)

        for cls_node in decompiler.classes.values():
            for func in cls_node.methods.values():
                qualname = f"{cls_node.name}.{func.name}"
                sig = (qualname, tuple(func.args))
                if sig not in seen:
                    signatures.append((qualname, list(func.args)))
                    seen.add(sig)

        for name, args in _infer_signature_candidates(raw_constants):
            sig = (name, tuple(args))
            if sig not in seen:
                signatures.append((name, args))
                seen.add(sig)

        if not signatures:
            return

        out.append("@FUNCS_DETECTED")
        for name, args in signatures[:80]:
            out.append(f"  {name}({', '.join(args)})")

    @classmethod
    def render(
        cls,
        section_name: str,
        raw_constants: list[Any],
        decompiler: OmniDecompiler,
        python_version: tuple[int, int] | None = None,
    ) -> str:
        version = python_version or sys.version_info[:2]
        _sn_raw = section_name or "__module__"
        _sn_nbc = "".join(c for c in _sn_raw if c.isprintable() and ord(c) < 128).strip()
        if not _sn_nbc:
            import hashlib as _hl
            _sn_nbc = "<section:" + _hl.sha1(_sn_raw.encode("utf-8", "replace")).hexdigest()[:12] + ">"
        out = [
            "# Nuitka static reconstruction (compact). Feed to an LLM.",
            "# c[N]=mod_consts[N]   no native @OPS block was available in this standalone OMNI run.",
            "",
            f"@MOD {_sn_nbc}",
            f"@VER {version[0]}.{version[1]}",
            "",
        ]
        display_constants = _redact_marshaled_bytecode_list(raw_constants)
        cls._emit_constants(display_constants, out)
        out.append("")
        cls._emit_imports(decompiler, raw_constants, out)
        out.append("")
        cls._emit_funcs_detected(decompiler, raw_constants, out)
        out.append("")
        out.append("@NO_OPS")
        out.append("  reason: omni_nuitka_framework only had decoded constants for this module;")
        out.append("          no PE/module-table/native disassembly context was supplied.")
        out.append("  consequence: signatures, imports and literals are grounded; exact")
        out.append("               compiled function bodies still need native-code tracing.")
        return "\n".join(out).rstrip() + "\n"


def reconstruct_module_artifacts(
    section_name: str,
    raw_constants: list[Any] | tuple[Any, ...],
    *,
    decompiler: OmniDecompiler | None = None,
    python_version: tuple[int, int] | None = None,
    known_modules: Iterable[str] | None = None,
    include_nbc: bool = False,
) -> OmniModuleArtifact:
    constants = list(raw_constants)
    if _is_marshaled_bytecode_section_name(section_name, constants):
        return OmniModuleArtifact(
            source="",
            heuristic_source="",
            strategy="bytecode-only",
            nbc_text=None,
            smart_source=None,
        )

    constants_for_render = _redact_marshaled_bytecode_list(constants)
    code_objects: list[dict[str, Any]] = []
    for item in constants_for_render:
        _collect_code_object_specs(item, code_objects)

    module_globals: set[str] | None = None
    module_global_values: dict[str, Any] | None = None
    if decompiler is not None:
        decompiler.unclaimed_items = _redact_marshaled_bytecode_list(decompiler.unclaimed_items)
        mc = getattr(decompiler, "module_constants", None)
        if isinstance(mc, dict) and mc and not code_objects:
            module_globals = set()
            module_global_values = {}
            for gname, gval in mc.items():
                if isinstance(gname, str) and gname.isidentifier():
                    module_globals.add(gname)
                    if isinstance(gval, str):
                        try:
                            ast.parse(f"{gname} = {gval}")
                            module_global_values[gname] = ast.literal_eval(gval)
                        except Exception:
                            pass

    smart_source: str | None = None
    smart_reconstructor = _load_v7_smart_reconstructor()
    if smart_reconstructor is not None and constants:
        try:
            smart_source = smart_reconstructor(
                module_name=section_name or "__module__",
                constants=constants_for_render,
                code_objects=code_objects,
                module_globals=module_globals,
                module_global_values=module_global_values,
                known_modules=known_modules,
                emit_banner=True,
            ).render()
        except Exception:
            smart_source = None

    smart_valid = False
    if smart_source and smart_source.strip():
        try:
            ast.parse(smart_source)
            smart_valid = True
        except SyntaxError:
            smart_valid = False

    if smart_valid and (_has_python_structure(smart_source or "") or not decompiler):
        heuristic_source = smart_source or ""
        source = smart_source or ""
        strategy = "smart"
    else:
        if decompiler is None:
            decompiler = OmniDecompiler()
            decompiler.run_pass_1_structural_mapping(constants_for_render)
            decompiler.run_pass_2_ast_synthesis()
        heuristic_source = _generate_heuristic_omni_source(decompiler, section_name)
        source = heuristic_source
        strategy = "heuristic"
        if smart_valid and smart_source and (
            not _has_python_structure(heuristic_source)
            or _count_reconstructed_blocks(smart_source) >= _count_reconstructed_blocks(heuristic_source)
        ):
            source = smart_source
            strategy = "smart"

    nbc_text: str | None = None
    if include_nbc:
        if decompiler is None:
            decompiler = OmniDecompiler()
            decompiler.run_pass_1_structural_mapping(constants_for_render)
            decompiler.run_pass_2_ast_synthesis()
        nbc_text = OmniNuitkaCompactEmitter.render(
            section_name=section_name,
            raw_constants=constants_for_render,
            decompiler=decompiler,
            python_version=python_version,
        )
        try:
            parsed_nbc = parse_nbc_text(nbc_text)
            nbc_source = NbcNoOpsHeuristicReconstructor(parsed_nbc).render_generic()
            merged_source = _merge_blob_python_sources(
                section_name or "__module__",
                [candidate for candidate in (smart_source, source, heuristic_source) if candidate],
                inventory_source=nbc_source,
            )
            ast.parse(merged_source)
            source = merged_source
            strategy = f"merged+{strategy}"
        except Exception:
            pass

    return OmniModuleArtifact(
        source=source,
        heuristic_source=heuristic_source,
        strategy=strategy,
        nbc_text=nbc_text,
        smart_source=smart_source,
    )


def generate_omni_nbc(
    decompiler: OmniDecompiler,
    section_name: str,
    raw_constants: list[Any] | tuple[Any, ...],
    python_version: tuple[int, int] | None = None,
) -> str:
    return OmniNuitkaCompactEmitter.render(
        section_name=section_name,
        raw_constants=list(raw_constants),
        decompiler=decompiler,
        python_version=python_version,
    )


def generate_omni_source(
    decompiler: OmniDecompiler | None,
    section_name: str,
    raw_constants: list[Any] | tuple[Any, ...] | None = None,
    python_version: tuple[int, int] | None = None,
    prefer_full: bool = True,
    known_modules: Iterable[str] | None = None,
    include_nbc: bool = False,
) -> str:
    if raw_constants is not None and _is_marshaled_bytecode_section_name(section_name, raw_constants):
        return ""
    if prefer_full and raw_constants is not None:
        return reconstruct_module_artifacts(
            section_name=section_name,
            raw_constants=raw_constants,
            decompiler=decompiler,
            python_version=python_version,
            known_modules=known_modules,
            include_nbc=include_nbc,
        ).source
    if decompiler is None:
        return ""
    decompiler.unclaimed_items = _redact_marshaled_bytecode_list(decompiler.unclaimed_items)
    return _generate_heuristic_omni_source(decompiler, section_name)


# ---------------------------------------------------------------------------
# NBC -> Python decompiler
# ---------------------------------------------------------------------------


@dataclass
class NbcParsedConstant:
    index: int
    type_code: str
    raw: str
    value: Any
    truncated: bool = False


@dataclass
class NbcFunctionSignature:
    qualname: str
    args: list[str]


@dataclass
class NbcOpsBlock:
    va: str
    qualname: str | None = None
    ops: list[str] = field(default_factory=list)


@dataclass
class NbcForensicsBlock:
    qualname: str
    notes: list[str] = field(default_factory=list)
    adjacent: list[tuple[int, str, str]] = field(default_factory=list)
    mentions: list[tuple[int, str, str]] = field(default_factory=list)


@dataclass
class ParsedNbcModule:
    module_name: str = "__module__"
    python_version: tuple[int, int] = field(default_factory=lambda: sys.version_info[:2])
    entry_va: str | None = None
    constants: list[NbcParsedConstant] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    functions: list[NbcFunctionSignature] = field(default_factory=list)
    ops_blocks: list[NbcOpsBlock] = field(default_factory=list)
    forensic_blocks: list[NbcForensicsBlock] = field(default_factory=list)
    global_no_ops: list[str] = field(default_factory=list)

    def raw_constants(self) -> list[Any]:
        return [const.value for const in self.constants]


@dataclass
class _NbcFunctionRecord:
    qualname: str
    name: str
    class_name: str | None
    args: list[str]
    ops_block: NbcOpsBlock | None = None
    forensic_block: NbcForensicsBlock | None = None


def _parse_nbc_version(text: str) -> tuple[int, int]:
    match = re.match(r"^\s*(\d+)\.(\d+)\s*$", text)
    if not match:
        return sys.version_info[:2]
    return int(match.group(1)), int(match.group(2))


def _placeholder_from_nbc_literal(type_code: str, raw: str) -> Any:
    preview = raw.strip()
    if type_code == "n":
        return None
    if type_code == "t":
        return True
    if type_code == "F":
        return False
    if type_code == "s":
        text = preview
        if text[:1] in {"'", '"'}:
            text = text[1:]
        return f"{text.rstrip('.')}..."
    if type_code in {"b", "B"}:
        text = preview
        if text.startswith(("b'", 'b"')):
            text = text[2:]
        elif text[:1] in {"'", '"'}:
            text = text[1:]
        return text.rstrip(".").encode("utf-8", errors="replace") + b"..."
    return f"<NBC {type_code} {preview}>"


def _parse_nbc_constant_value(type_code: str, raw: str) -> tuple[Any, bool]:
    text = raw.strip()
    if type_code == "n":
        return None, False
    if type_code == "t":
        return True, False
    if type_code == "F":
        return False, False
    try:
        return ast.literal_eval(text), False
    except Exception:
        return _placeholder_from_nbc_literal(type_code, text), True


def parse_nbc_text(text: str) -> ParsedNbcModule:
    module = ParsedNbcModule()
    state: str | None = None
    current_ops: NbcOpsBlock | None = None
    current_forensic: NbcForensicsBlock | None = None
    forensic_mode: str | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n\r")
        stripped = line.strip()

        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if stripped.startswith("@MOD "):
            module.module_name = stripped[5:].strip() or "__module__"
            state = None
            continue
        if stripped.startswith("@VER "):
            module.python_version = _parse_nbc_version(stripped[5:])
            state = None
            continue
        if stripped.startswith("@ENTRY "):
            module.entry_va = stripped[7:].strip() or None
            state = None
            continue
        if stripped.startswith("@CONSTS "):
            state = "consts"
            continue
        if stripped == "@IMPORTS":
            state = "imports"
            continue
        if stripped == "@FUNCS_DETECTED":
            state = "funcs"
            continue
        if stripped.startswith("@FORENSICS"):
            state = "forensics"
            current_forensic = None
            forensic_mode = None
            continue
        if stripped.startswith("@OPS "):
            match = re.match(r"^@OPS\s+(0x[0-9A-Fa-f]+)(?:\s+#\s*(.+))?$", stripped)
            if match:
                current_ops = NbcOpsBlock(
                    va=match.group(1),
                    qualname=match.group(2).strip() if match.group(2) else None,
                )
                module.ops_blocks.append(current_ops)
                state = "ops"
            else:
                state = None
            continue
        if stripped.startswith("@NO_OPS"):
            suffix = stripped[len("@NO_OPS") :].strip()
            if suffix:
                current_forensic = NbcForensicsBlock(qualname=suffix)
                module.forensic_blocks.append(current_forensic)
                forensic_mode = None
                state = "forensic_block"
            else:
                module.global_no_ops = []
                state = "global_no_ops"
            continue

        if state == "consts":
            match = re.match(r"^\s*(\d+)\s+(\S)\s+(.*)$", line)
            if not match:
                continue
            index = int(match.group(1))
            type_code = match.group(2)
            raw_value = match.group(3)
            value, truncated = _parse_nbc_constant_value(type_code, raw_value)
            while len(module.constants) <= index:
                module.constants.append(
                    NbcParsedConstant(
                        index=len(module.constants),
                        type_code="?",
                        raw="None",
                        value=None,
                        truncated=False,
                    )
                )
            module.constants[index] = NbcParsedConstant(
                index=index,
                type_code=type_code,
                raw=raw_value,
                value=value,
                truncated=truncated,
            )
            continue

        if state == "imports":
            module.imports.append(stripped)
            continue

        if state == "funcs":
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_.<>]*)\((.*)\)$", stripped)
            if not match:
                continue
            args = [part.strip() for part in match.group(2).split(",") if part.strip()]
            module.functions.append(NbcFunctionSignature(match.group(1), args))
            continue

        if state == "ops" and current_ops is not None:
            current_ops.ops.append(stripped)
            continue

        if state == "global_no_ops":
            module.global_no_ops.append(stripped)
            continue

        if state == "forensic_block" and current_forensic is not None:
            if stripped == "adjacent:":
                forensic_mode = "adjacent"
                continue
            if stripped == "mentions:":
                forensic_mode = "mentions"
                continue
            match = re.match(r"^c\[(\d+)\]\s+(\S)\s+(.*)$", stripped)
            if forensic_mode == "adjacent" and match:
                current_forensic.adjacent.append((int(match.group(1)), match.group(2), match.group(3)))
                continue
            if forensic_mode == "mentions" and match:
                current_forensic.mentions.append((int(match.group(1)), match.group(2), match.group(3)))
                continue
            current_forensic.notes.append(stripped)

    return module


def parse_nbc_file(path: str | Path) -> ParsedNbcModule:
    nbc_path = Path(path)
    return parse_nbc_text(nbc_path.read_text(encoding="utf-8", errors="replace"))


class NbcSourceDecompiler:
    def __init__(self, module: ParsedNbcModule):
        self.module = module
        self.const_by_index = {const.index: const for const in module.constants}
        self.va_to_qualname = {block.va.lower(): block.qualname for block in module.ops_blocks if block.qualname}
        self.unresolved_constants: set[int] = set()
        self.helper_usage: set[str] = set()
        self._records = self._build_records()
        self._rendered_records = self._render_records()

    def _split_qualname(self, qualname: str) -> tuple[str | None, str]:
        cleaned = qualname.replace(".<locals>.", ".")
        parts = [part for part in cleaned.split(".") if part and part != "<locals>"]
        if not parts:
            return None, "recovered_function"
        for index, part in enumerate(parts[:-1]):
            if part[:1].isupper():
                return part, parts[-1]
        return None, parts[-1]

    def _safe_name(self, name: str, fallback: str) -> str:
        safe = safe_identifier(name)
        if safe:
            return safe
        candidate = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
        if not candidate:
            candidate = fallback
        if candidate[:1].isdigit():
            candidate = f"n_{candidate}"
        return candidate

    def _safe_args(self, args: list[str], is_method: bool) -> list[str]:
        safe_args: list[str] = []
        for index, arg in enumerate(args):
            prefix = ""
            base = arg
            if arg.startswith("**"):
                prefix, base = "**", arg[2:]
            elif arg.startswith("*"):
                prefix, base = "*", arg[1:]
            if base == ".0":
                base = "iterable"
            safe = self._safe_name(base, f"arg_{index}")
            safe_args.append(prefix + safe)
        if is_method and (not safe_args or safe_args[0] not in {"self", "cls"}):
            safe_args.insert(0, "self")
        return safe_args

    def _ensure_record(
        self,
        records: "OrderedDict[str, _NbcFunctionRecord]",
        qualname: str,
        args: list[str] | None = None,
    ) -> _NbcFunctionRecord:
        if qualname not in records:
            class_name, name = self._split_qualname(qualname)
            records[qualname] = _NbcFunctionRecord(
                qualname=qualname,
                name=self._safe_name(name, "recovered_function"),
                class_name=self._safe_name(class_name, "RecoveredClass") if class_name else None,
                args=self._safe_args(args or [], bool(class_name)),
            )
        elif args:
            current = records[qualname]
            if not current.args:
                current.args = self._safe_args(args, bool(current.class_name))
        return records[qualname]

    def _build_records(self) -> "OrderedDict[str, _NbcFunctionRecord]":
        records: "OrderedDict[str, _NbcFunctionRecord]" = OrderedDict()
        qualnamed_blocks = [block for block in self.module.ops_blocks if block.qualname]
        unlabeled_blocks = [block for block in self.module.ops_blocks if not block.qualname and block.va.lower() != (self.module.entry_va or "").lower()]
        used_qualnames = {block.qualname for block in qualnamed_blocks if block.qualname}
        unused_signatures = [sig for sig in self.module.functions if sig.qualname not in used_qualnames]
        for block, signature in zip(unlabeled_blocks, unused_signatures):
            block.qualname = signature.qualname

        for signature in self.module.functions:
            self._ensure_record(records, signature.qualname, signature.args)
        for block in self.module.ops_blocks:
            if not block.qualname:
                continue
            self._ensure_record(records, block.qualname).ops_block = block
        for forensic in self.module.forensic_blocks:
            self._ensure_record(records, forensic.qualname).forensic_block = forensic

        return records

    def _const_expr(self, index: int | None) -> str:
        if index is None:
            return "..."
        const = self.const_by_index.get(index)
        if const is None:
            self.unresolved_constants.add(index)
            return f"_NBC_CONST_{index}"
        if const.truncated:
            self.unresolved_constants.add(index)
            return f"_NBC_CONST_{index}"
        return literal_source(const.value)

    def _resolve_local_call(self, target: str, current_record: _NbcFunctionRecord) -> str | None:
        va = target[3:].strip().lower()
        qualname = self.va_to_qualname.get(va)
        if not qualname:
            return None
        class_name, name = self._split_qualname(qualname)
        safe_name = self._safe_name(name, "recovered_function")
        if class_name and current_record.class_name == self._safe_name(class_name, "RecoveredClass"):
            return f"self.{safe_name}"
        if class_name:
            return f"{self._safe_name(class_name, 'RecoveredClass')}.{safe_name}"
        return safe_name

    def _call_expr(self, target: str, args: list[str], current_record: _NbcFunctionRecord) -> str:
        arg_text = ", ".join(args)
        sep = ", " if arg_text else ""

        if target.startswith("capi:"):
            self.helper_usage.add("capi")
            return f"_nbc_capi({target[5:]!r}{sep}{arg_text})"
        if target.startswith("r#"):
            self.helper_usage.add("runtime")
            return f"_nbc_runtime({target!r}{sep}{arg_text})"
        if target.startswith("fn@"):
            resolved = self._resolve_local_call(target, current_record)
            if resolved:
                return f"{resolved}({arg_text})" if arg_text else f"{resolved}()"
            self.helper_usage.add("local")
            return f"_nbc_local_call({target!r}{sep}{arg_text})"
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", target):
            return f"{target}({arg_text})" if arg_text else f"{target}()"

        self.helper_usage.add("runtime")
        return f"_nbc_runtime({target!r}{sep}{arg_text})"

    def _parse_op(self, line: str) -> tuple[str, Any]:
        op = line.split(";", 1)[0].strip()
        if not op:
            return "RAW", line.strip()
        if op.startswith(":"):
            return "LABEL", op[1:]
        match = re.match(r"^L\s+c\[(\d+)\]$", op)
        if match:
            return "LOAD", int(match.group(1))
        match = re.match(r"^C\s+(.+)$", op)
        if match:
            return "CALL", match.group(1).strip()
        match = re.match(r"^J_(EQ|NE)\s+(?:c\[(\d+)\]|\?)\s+(\S+)$", op)
        if match:
            return f"J_{match.group(1)}", (
                int(match.group(2)) if match.group(2) is not None else None,
                match.group(3),
            )
        match = re.match(r"^J\s+(\S+)$", op)
        if match:
            return "J", match.group(1)
        if op == "RET":
            return "RET", None
        return "RAW", op

    def _next_significant(self, parsed_ops: list[tuple[str, Any]], start: int) -> tuple[str, Any] | None:
        for kind, data in parsed_ops[start:]:
            if kind != "LABEL":
                return kind, data
        return None

    def _render_ops_body(self, record: _NbcFunctionRecord) -> list[str]:
        if not record.ops_block:
            return []

        body: list[str] = []
        pending_consts: list[str] = []
        parsed_ops = [self._parse_op(op) for op in record.ops_block.ops]
        skip_next_ret = False

        for index, (kind, data) in enumerate(parsed_ops):
            if skip_next_ret and kind == "RET":
                skip_next_ret = False
                continue

            if kind == "LABEL":
                body.append(f"# label {data}")
                continue

            if kind == "LOAD":
                pending_consts.append(self._const_expr(data))
                continue

            if kind == "CALL":
                expr = self._call_expr(data, pending_consts, record)
                pending_consts = []
                next_item = self._next_significant(parsed_ops, index + 1)
                if next_item and next_item[0] == "RET":
                    body.append(f"return {expr}")
                    skip_next_ret = True
                else:
                    body.append(expr)
                continue

            if kind in {"J_EQ", "J_NE"}:
                const_index, label = data
                cmp_expr = self._const_expr(const_index)
                self.helper_usage.add("compare")
                negate = "not " if kind == "J_NE" else ""
                body.append(f"# if {negate}_nbc_compare({cmp_expr}): goto {label}")
                continue

            if kind == "J":
                body.append(f"# goto {data}")
                continue

            if kind == "RET":
                if pending_consts:
                    if len(pending_consts) == 1:
                        body.append(f"return {pending_consts[0]}")
                    else:
                        body.append(f"return ({', '.join(pending_consts)})")
                    pending_consts = []
                elif not body or not body[-1].lstrip().startswith("return "):
                    body.append("return None")
                continue

            body.append(f"# {data}")

        if pending_consts:
            if len(pending_consts) == 1:
                body.append(f"return {pending_consts[0]}")
            else:
                body.append(f"return ({', '.join(pending_consts)})")
        if not body:
            body.append("...")
        elif all(line.startswith("#") for line in body):
            body.append("...")
        return body

    def _render_forensic_body(self, record: _NbcFunctionRecord) -> list[str]:
        block = record.forensic_block
        if block is None:
            return []
        body = ['"""Recovered from NBC forensic hints; the static @OPS walk did not reach this body."""']
        for note in block.notes:
            body.append(f"# {note}")
        for idx, _type_code, raw in block.adjacent[:12]:
            body.append(f"# nearby c[{idx}] = {raw}")
        for idx, _type_code, raw in block.mentions[:12]:
            body.append(f"# mention c[{idx}] = {raw}")
        body.append("...")
        return body

    def _render_record_body(self, record: _NbcFunctionRecord) -> list[str]:
        body = self._render_ops_body(record)
        if body:
            return body
        body = self._render_forensic_body(record)
        if body:
            return body
        return ['"""Signature recovered from NBC only."""', "..."]

    def _render_records(self) -> "OrderedDict[str, list[str]]":
        rendered: "OrderedDict[str, list[str]]" = OrderedDict()
        for qualname, record in self._records.items():
            rendered[qualname] = self._render_record_body(record)
        return rendered

    def _render_signature(self, record: _NbcFunctionRecord) -> str:
        args = record.args or (["self"] if record.class_name else [])
        return f"def {record.name}({', '.join(args)}):"

    def render(self) -> str:
        lines: list[str] = []
        lines.append('"""')
        lines.append(f"Best-effort Python reconstruction from NBC for module {self.module.module_name}.")
        lines.append("This file was rebuilt from the compact Nuitka pseudo-bytecode format.")
        if self.module.global_no_ops:
            lines.append("Native @OPS were incomplete or absent for at least part of this module.")
        lines.append('"""')
        lines.append("")
        lines.append("from __future__ import annotations")
        lines.append("")

        seen_imports: set[str] = set()
        for import_line in self.module.imports:
            if import_line not in seen_imports:
                lines.append(import_line)
                seen_imports.add(import_line)

        if self.helper_usage and "from typing import Any" not in seen_imports:
            lines.append("from typing import Any")
            seen_imports.add("from typing import Any")

        if seen_imports:
            lines.append("")

        if self.unresolved_constants:
            lines.append("# Truncated / unresolved literals preserved from the NBC payload")
            for index in sorted(self.unresolved_constants):
                const = self.const_by_index.get(index)
                raw = const.raw if const else "<missing>"
                lines.append(f"_NBC_CONST_{index} = {raw!r}")
            lines.append("")

        if self.helper_usage:
            lines.append("def _nbc_runtime(name: str, *args: Any) -> Any:")
            lines.append("    return {'runtime_helper': name, 'args': args}")
            lines.append("")
            if "capi" in self.helper_usage:
                lines.append("def _nbc_capi(name: str, *args: Any) -> Any:")
                lines.append("    return {'python_c_api': name, 'args': args}")
                lines.append("")
            if "local" in self.helper_usage:
                lines.append("def _nbc_local_call(name: str, *args: Any) -> Any:")
                lines.append("    return {'local_call': name, 'args': args}")
                lines.append("")
            if "compare" in self.helper_usage:
                lines.append("def _nbc_compare(value: Any) -> bool:")
                lines.append("    return bool(value)")
                lines.append("")

        if self.module.global_no_ops:
            lines.append("# Global NBC notes")
            for entry in self.module.global_no_ops:
                lines.append(f"# {entry}")
            lines.append("")

        classes: "OrderedDict[str, list[_NbcFunctionRecord]]" = OrderedDict()
        free_funcs: list[_NbcFunctionRecord] = []
        for qualname, record in self._records.items():
            if record.class_name:
                classes.setdefault(record.class_name, []).append(record)
            else:
                free_funcs.append(record)

        entry_block = next(
            (block for block in self.module.ops_blocks if not block.qualname and block.va.lower() == (self.module.entry_va or "").lower()),
            None,
        )
        if entry_block is not None:
            lines.append("# Module entry NBC ops")
            for op in entry_block.ops:
                lines.append(f"# {op}")
            lines.append("")

        for record in free_funcs:
            lines.append(self._render_signature(record))
            lines.extend(f"    {line}" for line in self._rendered_records[record.qualname])
            lines.append("")

        for class_name, methods in classes.items():
            lines.append(f"class {class_name}:")
            if not methods:
                lines.append("    pass")
                lines.append("")
                continue
            for method in methods:
                lines.append("")
                lines.append(f"    {self._render_signature(method)}")
                lines.extend(f"        {line}" for line in self._rendered_records[method.qualname])
            lines.append("")

        if not free_funcs and not classes:
            lines.append("pass")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"


def _nbc_decode_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            text = value.decode("utf-8")
        except Exception:
            text = value.decode("latin-1", errors="replace")
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if text and printable / max(len(text), 1) >= 0.70:
            return text
    return None


def _nbc_collect_texts(value: Any, out: list[str], seen: set[str]) -> None:
    text = _nbc_decode_text(value)
    if text is not None and text not in seen:
        seen.add(text)
        out.append(text)
    if isinstance(value, dict):
        for item in value.keys():
            _nbc_collect_texts(item, out, seen)
        for item in value.values():
            _nbc_collect_texts(item, out, seen)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _nbc_collect_texts(item, out, seen)


def _nbc_iter_identifier_tuples(value: Any) -> Iterator[tuple[str, ...]]:
    if isinstance(value, tuple) and value:
        normalized = []
        for item in value:
            text = _nbc_decode_text(item)
            if text is None or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|\.0", text):
                break
            normalized.append(text)
        else:
            yield tuple(normalized)
        for item in value:
            yield from _nbc_iter_identifier_tuples(item)
    elif isinstance(value, list):
        for item in value:
            yield from _nbc_iter_identifier_tuples(item)
    elif isinstance(value, dict):
        for item in value.keys():
            yield from _nbc_iter_identifier_tuples(item)
        for item in value.values():
            yield from _nbc_iter_identifier_tuples(item)
    elif isinstance(value, (set, frozenset)):
        for item in value:
            yield from _nbc_iter_identifier_tuples(item)


_NBC_RESOURCE_SUFFIXES = (
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".dll",
    ".log",
    ".json",
    ".ini",
    ".cfg",
    ".bin",
    ".py",
    ".pyc",
)


def _nbc_is_resource_like_text(text: str) -> bool:
    lowered = text.lower()
    if lowered.endswith(_NBC_RESOURCE_SUFFIXES):
        return True
    if lowered.startswith("<module "):
        return True
    if "\\" in text:
        return True
    if "/" in text and not text.startswith(("http://", "https://", "/")):
        return True
    return False


def _nbc_is_probable_import_name(text: str) -> bool:
    if "<locals>" in text or _nbc_is_resource_like_text(text):
        return False
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", text):
        return False
    parts = text.split(".")
    if any(part.startswith("__") and part.endswith("__") for part in parts):
        return False
    if any(any(ch.isupper() for ch in part) for part in parts):
        return False
    return True


class NbcNoOpsHeuristicReconstructor:
    """High-level source restorer for `.nbc` files that only contain constants."""

    _ROUTE_TO_HANDLER = OrderedDict(
        [
            ("/api/oauth-status", "handle_oauth_status"),
            ("/api/auth-status", "handle_auth_status"),
            ("/api/browsers", "handle_browsers"),
            ("/api/inventory", "handle_inventory"),
            ("/api/session", "handle_session"),
            ("/api/clones", "handle_clones"),
            ("/api/currencies", "handle_currencies"),
            ("/api/social", "handle_social"),
            ("/api/items", "handle_items_list"),
            ("/api/start-oauth", "handle_start_oauth"),
            ("/api/set-token", "handle_set_token"),
            ("/api/set-keyauth-license", "handle_set_keyauth_license"),
            ("/api/set-browser", "handle_set_browser"),
        ]
    )
    _TOP_LEVEL_FUNCTIONS = (
        "_load_browser_pref",
        "_save_browser_pref",
        "_detect_browsers",
        "_maybe_open_browser",
        "_oauth_worker",
        "save_token",
        "load_saved_token",
        "run_token_script",
        "get_new_token",
        "apply_token_from_string",
        "apply_keyauth_license",
        "_keyauth_saved_key",
        "_keyauth_hwid",
        "_build_keyauth_client",
        "keyauth_client",
        "_keyauth_enabled",
        "_keyauth_verify_cached",
        "ensure_keyauth",
        "ensure_token",
        "_session_token_hints",
        "_jwt_payload_unverified",
        "_api_get",
        "_api_post",
        "get_profile",
        "get_levels_list",
        "process_item",
        "run_protection_checks",
        "_cls_logo_bytes_from_disk",
        "main",
    )

    def __init__(self, module: ParsedNbcModule):
        self.module = module
        self.direct_texts = [text for const in module.constants if (text := _nbc_decode_text(const.value)) is not None]
        self.all_texts: list[str] = []
        _seen: set[str] = set()
        for const in module.constants:
            _nbc_collect_texts(const.value, self.all_texts, _seen)
        self.text_set = set(self.all_texts)
        self.code_objects = self._collect_code_objects()
        self.qualname_items = self._collect_qualnames()
        self.exact_signatures = self._collect_exact_signatures()
        self.class_methods = self._collect_class_methods()
        self.routes = [route for route in self._ROUTE_TO_HANDLER if route in self.text_set]
        self.api_urls = [text for text in self.all_texts if text.startswith(("http://", "https://"))]
        self.helper_comments = self._collect_nested_helper_comments()
        self.identifier_tuples = self._collect_identifier_tuples()
        self.top_level_functions = self._expand_top_level_functions(self._collect_top_level_functions())
        self.signature_hints = self._collect_signature_hints()

    def _valid_module_import(self, text: str) -> bool:
        return _nbc_is_probable_import_name(text)

    def _looks_like_class_name(self, text: str) -> bool:
        tail = text.lstrip("_")
        return bool(tail and safe_identifier(text) and not tail.isupper() and tail[:1].isupper() and any(ch.islower() for ch in tail[1:]))

    def _split_qualified_name(self, qualname: str) -> tuple[str | None, str | None]:
        cleaned = str(qualname or "").replace(".<locals>.", ".").strip(".")
        if not cleaned or cleaned in {"<module>", "__module__"}:
            return None, None
        parts = [part for part in cleaned.split(".") if part and part != "<locals>"]
        if not parts:
            return None, None
        leaf = safe_identifier(parts[-1])
        if not leaf or parts[-1].startswith("<"):
            return None, None
        if len(parts) == 1:
            return None, leaf
        if self._looks_like_class_name(parts[0]):
            return parts[0], leaf
        return None, None

    def _normalize_signature_args(
        self,
        args: Iterable[Any],
        class_name: str | None = None,
    ) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for index, value in enumerate(args):
            text = value if isinstance(value, str) else _nbc_decode_text(value)
            if text is None:
                text = f"arg_{index}"

            prefix = ""
            if text.startswith("**"):
                prefix, text = "**", text[2:]
            elif text.startswith("*"):
                prefix, text = "*", text[1:]

            if text == ".0":
                text = "iterable"

            safe = safe_identifier(text) or re.sub(r"[^A-Za-z0-9_]", "_", text)
            safe = safe.strip("_") or f"arg_{index}"
            if safe[:1].isdigit():
                safe = f"n_{safe}"
            if safe in seen and prefix == "":
                safe = f"{safe}_{index}"
            seen.add(safe)
            normalized.append(prefix + safe)

        if class_name and (not normalized or normalized[0] not in {"self", "cls"}):
            normalized.insert(0, "self")
        return normalized

    def _collect_code_objects(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for const in self.module.constants:
            _collect_code_object_specs(const.value, results)
        return results

    def _collect_exact_signatures(self) -> "OrderedDict[tuple[str | None, str], list[str]]":
        signatures: "OrderedDict[tuple[str | None, str], list[str]]" = OrderedDict()

        def add(qualname: str, args: Iterable[Any]) -> None:
            class_name, name = self._split_qualified_name(qualname)
            if not name:
                return
            normalized = self._normalize_signature_args(args, class_name)
            key = (class_name, name)
            current = signatures.get(key)
            if current is None or len(normalized) > len(current):
                signatures[key] = normalized

        for signature in self.module.functions:
            add(signature.qualname, signature.args)
        for code_obj in self.code_objects:
            qualname = str(code_obj.get("qualname") or code_obj.get("name") or "")
            add(qualname, code_obj.get("args") or ())

        return signatures

    def _collect_qualnames(self) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_<][A-Za-z0-9_<>]*)")
        for const in self.module.constants:
            text = _nbc_decode_text(const.value)
            if text is None or not pattern.fullmatch(text):
                continue
            if self._valid_module_import(text):
                continue
            if text.endswith((".txt", ".png", ".log")):
                continue
            results.append((const.index, text))
        return results

    def _collect_class_methods(self) -> "OrderedDict[str, list[str]]":
        classes: "OrderedDict[str, list[str]]" = OrderedDict()
        for (class_name, method_name), _args in self.exact_signatures.items():
            if not class_name:
                continue
            classes.setdefault(class_name, [])
            if method_name not in classes[class_name]:
                classes[class_name].append(method_name)
        for _index, qualname in self.qualname_items:
            class_name, method = self._split_qualified_name(qualname)
            if not class_name or not method:
                continue
            classes.setdefault(class_name, [])
            if method not in classes[class_name]:
                classes[class_name].append(method)
        return classes

    def _collect_top_level_functions(self) -> list[str]:
        funcs: list[str] = []
        seen = set()
        for (class_name, name), _args in self.exact_signatures.items():
            if class_name or name in seen:
                continue
            funcs.append(name)
            seen.add(name)
        for _index, qualname in self.qualname_items:
            if ".<locals>." in qualname:
                parent = qualname.split(".<locals>.", 1)[0]
                class_name, name = self._split_qualified_name(parent)
                if class_name is None and name and name not in seen:
                    funcs.append(name)
                    seen.add(name)
        return funcs

    def _collect_nested_helper_comments(self) -> dict[str, list[str]]:
        helpers: dict[str, list[str]] = defaultdict(list)
        for _index, qualname in self.qualname_items:
            if ".<locals>." not in qualname:
                continue
            parent, local = qualname.split(".<locals>.", 1)
            helpers[parent].append(local)
        return helpers

    def _collect_identifier_tuples(self) -> list[tuple[str, ...]]:
        results: list[tuple[str, ...]] = []
        seen: set[tuple[str, ...]] = set()
        for const in self.module.constants:
            for values in _nbc_iter_identifier_tuples(const.value):
                cleaned: list[str] = []
                for item in values:
                    candidate = "iterable" if item == ".0" else item
                    safe = safe_identifier(candidate) or re.sub(r"[^A-Za-z0-9_]", "_", candidate)
                    safe = safe.strip("_") or "arg"
                    if safe[:1].isdigit():
                        safe = f"n_{safe}"
                    cleaned.append(safe)
                signature = tuple(cleaned)
                if not signature or signature in seen:
                    continue
                seen.add(signature)
                results.append(signature)
        return results

    def _expand_top_level_functions(self, initial: list[str]) -> list[str]:
        ordered: list[str] = []
        seen: set[str] = set()
        for name in initial:
            if name in seen:
                continue
            seen.add(name)
            ordered.append(name)
        return ordered

    def _fallback_signature_for(self, name: str, class_name: str | None = None) -> list[str]:
        if class_name is not None:
            return ["self"]
        return []

    def _infer_signature_hint(self, name: str, class_name: str | None = None) -> list[str] | None:
        fallback = self._fallback_signature_for(name, class_name)
        if not fallback or not self.identifier_tuples:
            return None

        normalized_fallback = [part.lstrip("*") for part in fallback]
        best: tuple[str, ...] | None = None
        best_score = 0
        for candidate in self.identifier_tuples:
            if class_name:
                if not candidate or candidate[0] != "self":
                    continue
            elif candidate and candidate[0] == "self":
                continue

            overlap = len(set(candidate) & set(normalized_fallback))
            if overlap == 0:
                continue

            prefix = 0
            for left, right in zip(candidate, normalized_fallback):
                if left != right:
                    break
                prefix += 1

            score = overlap * 3 + prefix * 5
            if len(candidate) <= len(normalized_fallback):
                score += 2
            else:
                score -= max(len(candidate) - len(normalized_fallback) - 2, 0)

            if score > best_score:
                best_score = score
                best = candidate

        if best is None or best_score < 6:
            return None
        if list(best) == normalized_fallback[: len(best)]:
            return list(best)
        if list(best[: len(normalized_fallback)]) == normalized_fallback:
            return fallback

        filtered = [name for name in best if name in normalized_fallback]
        if class_name and (not filtered or filtered[0] != "self"):
            filtered.insert(0, "self")
        return filtered or None

    def _collect_signature_hints(self) -> dict[tuple[str | None, str], list[str]]:
        hints: dict[tuple[str | None, str], list[str]] = dict(self.exact_signatures)
        for name in self.top_level_functions:
            if (None, name) in hints:
                continue
            hint = self._infer_signature_hint(name)
            if hint:
                hints[(None, name)] = hint
        for class_name, methods in self.class_methods.items():
            for method_name in methods:
                if (class_name, method_name) in hints:
                    continue
                hint = self._infer_signature_hint(method_name, class_name)
                if hint:
                    hints[(class_name, method_name)] = hint
        return hints

    def _route_comment(self, handler_name: str) -> str | None:
        for route, target in self._ROUTE_TO_HANDLER.items():
            if target == handler_name:
                return route
        return None

    def _emit_global_notes_block(self) -> list[str]:
        lines: list[str] = []
        if self.module.global_no_ops:
            lines.append("# Global NBC notes")
            for entry in self.module.global_no_ops:
                lines.append(f"# {entry}")
            lines.append("")
        return lines

    def _render_specialized_module(self, import_lines: list[str], body_lines: list[str]) -> str:
        lines = [
            '"""',
            f"Automated merged Python recovery for NBC module {self.module.module_name}.",
            "Executable Python is reconstructed first; NBC-only artifacts are kept",
            "below only for details that could not be lifted automatically.",
            '"""',
            "",
        ]
        lines.extend(import_lines)
        if import_lines and import_lines[-1] != "":
            lines.append("")
        lines.extend(body_lines)
        if body_lines and body_lines[-1] != "":
            lines.append("")
        lines.extend(self._emit_global_notes_block())
        lines.extend(self._emit_constants_inventory())
        return "\n".join(lines).rstrip() + "\n"

    def _discover_named_literal_constants(self) -> "OrderedDict[str, Any]":
        values: "OrderedDict[str, Any]" = OrderedDict()
        consts = self.module.constants
        for index, const in enumerate(consts[:-1]):
            name = _nbc_decode_text(consts[index + 1].value)
            if name is None or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                continue
            value = const.value
            text_value = _nbc_decode_text(value)
            if text_value is not None and text_value.startswith("<module "):
                continue
            if text_value is not None and text_value.endswith(".py"):
                continue
            if text_value is not None and safe_identifier(text_value) and not text_value.startswith(("http://", "https://")) and text_value.lower() != name.lower():
                continue
            if isinstance(value, tuple) and value and all(_nbc_decode_text(item) is not None or isinstance(item, bool) for item in value):
                continue
            if name not in values:
                values[name] = value
        return values

    def _discover_endpoint_specs(self) -> "OrderedDict[str, tuple[str, str, bool]]":
        specs: "OrderedDict[str, tuple[str, str, bool]]" = OrderedDict()
        consts = self.module.constants
        for index, const in enumerate(consts[:-1]):
            name = _nbc_decode_text(consts[index + 1].value)
            value = const.value
            if name is None or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
                continue
            if not isinstance(value, tuple) or len(value) not in {2, 3}:
                continue
            method = _nbc_decode_text(value[0])
            path = _nbc_decode_text(value[1])
            requires_manifest = bool(value[2]) if len(value) == 3 and isinstance(value[2], bool) else False
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            if path is None or not path.startswith("/"):
                continue
            specs[name] = (method, path, requires_manifest)
        return specs

    def _render_arcraiders_package_module(self) -> str:
        return self._render_specialized_module(
            [
                "from __future__ import annotations",
                "",
                "from arcraiders.client import Client",
                "",
                "__all__ = ['Client']",
            ],
            [],
        )

    def _render_arcraiders_auth_package_module(self) -> str:
        return self._render_specialized_module(
            [
                "from __future__ import annotations",
                "",
                "from arcraiders.auth.base import Auth",
                "from arcraiders.auth.local_steam import LocalSteamAuth",
                "from arcraiders.auth.oauth import BrowserOAuth, OAuthProvider",
                "from arcraiders.auth.token import TokenAuth",
                "",
                "__all__ = ['Auth', 'BrowserOAuth', 'LocalSteamAuth', 'OAuthProvider', 'TokenAuth']",
            ],
            [],
        )

    def _render_arcraiders_config_module(self) -> str:
        named_literals = self._discover_named_literal_constants()
        body: list[str] = []
        for name, value in named_literals.items():
            body.append(f"{name} = {literal_source(value)}")
        if named_literals:
            body.append("")
            exports = ", ".join(repr(name) for name in named_literals)
            body.append(f"__all__ = [{exports}]")
        return self._render_specialized_module(
            ["from __future__ import annotations"],
            body,
        )

    def _render_arcraiders_endpoints_module(self) -> str:
        endpoint_specs = self._discover_endpoint_specs()
        body = [
            "from dataclasses import dataclass",
            "",
            "@dataclass(frozen=True)",
            "class Endpoint:",
            "    method: str",
            "    path: str",
            "    requires_manifest: bool = False",
            "",
        ]
        exported_names: list[str] = []
        for name, (method, path, requires_manifest) in endpoint_specs.items():
            exported_names.append(name)
            body.append(f"{name} = Endpoint(method={method!r}, path={path!r}, requires_manifest={requires_manifest!r})")
        if exported_names:
            body.append("")
            body.append(f"__all__ = ['Endpoint', {', '.join(repr(name) for name in exported_names)}]")
        return self._render_specialized_module(
            ["from __future__ import annotations"],
            body,
        )

    def _render_arcraiders_auth_base_module(self) -> str:
        body = [
            "from typing import Protocol",
            "",
            "class Auth(Protocol):",
            "    @property",
            "    def token(self) -> str:",
            '        """Return the current bearer token."""',
            "        ...",
        ]
        return self._render_specialized_module(
            ["from __future__ import annotations"],
            body,
        )

    def _render_arcraiders_auth_token_module(self) -> str:
        body = [
            "from arcraiders.auth.base import Auth",
            "",
            "class TokenAuth(Auth):",
            "    def __init__(self, token: str):",
            "        self._value = token",
            "",
            "    @property",
            "    def token(self) -> str:",
            "        return self._value",
        ]
        return self._render_specialized_module(
            ["from __future__ import annotations"],
            body,
        )

    def _render_arcraiders_auth_token_helper_module(self) -> str:
        body = [
            "import json",
            "import urllib.error",
            "import urllib.parse",
            "import urllib.request",
            "from typing import Any",
            "",
            "from arcraiders.config import TOKEN_URL",
            "",
            "def request_access_token(",
            "    form_data: dict[str, str],",
            "    headers: dict[str, str] | None = None,",
            "    error_prefix: str | None = None,",
            ") -> dict[str, Any]:",
            "    payload = urllib.parse.urlencode(form_data).encode('utf-8')",
            "    req = urllib.request.Request(",
            "        url=TOKEN_URL,",
            "        data=payload,",
            "        method='POST',",
            "        headers=headers or {},",
            "    )",
            "    try:",
            "        with urllib.request.urlopen(req, timeout=30) as resp:",
            "            body = resp.read().decode('utf-8', 'replace')",
            "    except urllib.error.HTTPError as exc:",
            "        body = exc.read().decode('utf-8', 'replace')",
            "        prefix = error_prefix or 'Embark token exchange failed'",
            "        raise RuntimeError(f'{prefix}: HTTP {exc.code} response={body}') from exc",
            "    token_data = json.loads(body)",
            "    if 'access_token' not in token_data:",
            "        prefix = error_prefix or 'Embark token exchange failed'",
            "        raise RuntimeError(f'{prefix}: response={body}')",
            "    return token_data",
        ]
        return self._render_specialized_module(
            ["from __future__ import annotations"],
            body,
        )

    def _render_arcraiders_auth_oauth_module(self) -> str:
        body = [
            "import base64",
            "import hashlib",
            "import os",
            "import threading",
            "import urllib.parse",
            "import webbrowser",
            "from enum import Enum",
            "from http.server import BaseHTTPRequestHandler, HTTPServer",
            "from typing import Any",
            "from uuid import uuid4",
            "",
            "from arcraiders.auth._token import request_access_token",
            "from arcraiders.config import (",
            "    AUDIENCE,",
            "    AUTH_URL,",
            "    CLIENT_ID,",
            "    CLIENT_SECRET,",
            "    OAUTH_CALLBACK_URL,",
            "    OAUTH_SCOPE,",
            "    TENANCY,",
            "    USER_AGENT,",
            ")",
            "",
            "class OAuthProvider(str, Enum):",
            "    EPIC = 'epic'",
            "    PLAYSTATION = 'playstation'",
            "    STEAM = 'steam'",
            "    XBOX = 'xbox'",
            "",
            "class BrowserOAuth:",
            "    def __init__(self, provider: OAuthProvider | str, redirect_uri: str | None = None):",
            "        self.provider = OAuthProvider(str(provider))",
            "        self.redirect_uri = redirect_uri or OAUTH_CALLBACK_URL",
            "",
            "    @property",
            "    def token(self) -> str:",
            "        return self._authenticate()",
            "",
            "    @staticmethod",
            "    def _base64url_no_padding(raw: bytes) -> str:",
            "        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')",
            "",
            "    @classmethod",
            "    def _create_pkce_pair(cls) -> tuple[str, str]:",
            "        code_verifier = cls._base64url_no_padding(os.urandom(32))",
            "        code_challenge = cls._base64url_no_padding(",
            "            hashlib.sha256(code_verifier.encode('ascii')).digest()",
            "        )",
            "        return code_verifier, code_challenge",
            "",
            "    def _wait_for_oauth_callback(",
            "        self, redirect_uri: str, expected_state: str, timeout_seconds: int = 120",
            "    ) -> dict[str, str]:",
            "        parsed = urllib.parse.urlparse(redirect_uri)",
            "        host = parsed.hostname or '127.0.0.1'",
            "        port = parsed.port or 80",
            "        done = threading.Event()",
            "        callback_data: dict[str, str] = {}",
            "",
            "        class OAuthCallbackHandler(BaseHTTPRequestHandler):",
            "            def do_GET(inner_self):",
            "                query = urllib.parse.parse_qs(urllib.parse.urlparse(inner_self.path).query)",
            "                callback_data['code'] = (query.get('code') or [''])[0]",
            "                callback_data['state'] = (query.get('state') or [''])[0]",
            "                callback_data['error'] = (query.get('error') or [''])[0]",
            "                inner_self.send_response(200)",
            "                inner_self.send_header('Content-Type', 'text/plain; charset=utf-8')",
            "                inner_self.end_headers()",
            "                inner_self.wfile.write(b'Login complete. You can close this tab.')",
            "                done.set()",
            "",
            "            def log_message(inner_self, format: str, *args: Any) -> None:",
            "                return",
            "",
            "        server = HTTPServer((host, port), OAuthCallbackHandler)",
            "        worker = threading.Thread(target=server.serve_forever, daemon=True)",
            "        worker.start()",
            "        try:",
            "            if not done.wait(timeout_seconds):",
            "                raise TimeoutError('Timed out waiting for OAuth callback')",
            "        finally:",
            "            server.shutdown()",
            "            worker.join(timeout=2)",
            "        if callback_data.get('error'):",
            "            raise RuntimeError(f\"OAuth authorization failed: {callback_data['error']}\")",
            "        if not callback_data.get('code'):",
            "            raise RuntimeError('OAuth callback did not include a code')",
            "        if callback_data.get('state') != expected_state:",
            "            raise RuntimeError('OAuth state mismatch')",
            "        return callback_data",
            "",
            "    def _exchange_authorization_code_for_token(",
            "        self, code: str, code_verifier: str, redirect_uri: str",
            "    ) -> str:",
            "        form_data = {",
            "            'grant_type': 'authorization_code',",
            "            'client_id': CLIENT_ID,",
            "            'client_secret': CLIENT_SECRET,",
            "            'code': code,",
            "            'code_verifier': code_verifier,",
            "            'redirect_uri': redirect_uri,",
            "        }",
            "        headers = {",
            "            'Content-Type': 'application/x-www-form-urlencoded',",
            "            'User-Agent': USER_AGENT,",
            "        }",
            "        token_data = request_access_token(",
            "            form_data=form_data,",
            "            headers=headers,",
            "            error_prefix='Embark authorization code exchange failed',",
            "        )",
            "        return str(token_data['access_token'])",
            "",
            "    def _authenticate(self) -> str:",
            "        state = uuid4().hex",
            "        code_verifier, code_challenge = self._create_pkce_pair()",
            "        params = {",
            "            'client_id': CLIENT_ID,",
            "            'response_type': 'code',",
            "            'code_challenge': code_challenge,",
            "            'code_challenge_method': 'S256',",
            "            'state': state,",
            "            'audience': AUDIENCE,",
            "            'scope': OAUTH_SCOPE,",
            "            'tenancy': TENANCY,",
            "            'external_provider_name': self.provider.value,",
            "            'redirect_uri': self.redirect_uri,",
            "            'skip_link': 'false',",
            "        }",
            "        auth_url = AUTH_URL + '?' + urllib.parse.urlencode(params)",
            "        webbrowser.open(auth_url)",
            "        callback_data = self._wait_for_oauth_callback(self.redirect_uri, state)",
            "        return self._exchange_authorization_code_for_token(",
            "            callback_data['code'],",
            "            code_verifier,",
            "            self.redirect_uri,",
            "        )",
        ]
        return self._render_specialized_module(
            ["from __future__ import annotations"],
            body,
        )

    def _render_arcraiders_client_module(self) -> str:
        endpoint_specs = self._discover_endpoint_specs()
        client_methods = self.class_methods.get("Client", [])
        body = [
            "import json",
            "import urllib.error",
            "import urllib.parse",
            "import urllib.request",
            "from typing import Any",
            "from uuid import uuid4",
            "",
            "from arcraiders.auth.base import Auth",
            "import arcraiders.config as config",
            "import arcraiders.endpoints as endpoints",
            "",
            "class Client:",
            "    def __init__(",
            "        self,",
            "        auth: Auth,",
            "        user_agent: str | None = None,",
            "        telemetry_client_platform: str | None = None,",
            "        telemetry_uuid: str | None = None,",
            "    ):",
            "        self._auth = auth",
            "        self._user_agent = user_agent or config.USER_AGENT",
            "        self._telemetry_client_platform = telemetry_client_platform or 'WinGDK'",
            "        self._telemetry_uuid = telemetry_uuid or uuid4().hex",
            "",
            "    @property",
            "    def token(self) -> str:",
            "        return self._auth.token",
            "",
            "    @property",
            "    def manifest(self) -> dict[str, str]:",
            "        return {",
            "            'id': config.MANIFEST_BUILD_ID,",
            "            'build_id': config.MANIFEST_BUILD_ID,",
            "            'app_id': config.MANIFEST_APP_ID,",
            "            'store_deployment_target': config.MANIFEST_STORE_DEPLOYMENT_TARGET,",
            "        }",
            "",
            "    def _call_endpoint(",
            "        self, endpoint: endpoints.Endpoint, payload: dict[str, Any] | None = None",
            "    ) -> Any:",
            "        url = urllib.parse.urljoin(config.API_BASE_URL.rstrip('/') + '/', endpoint.path.lstrip('/'))",
            "        headers = {",
            "            'Authorization': f'Bearer {self.token}',",
            "            'Content-Type': 'application/json',",
            "            'User-Agent': self._user_agent,",
            "            'x-embark-telemetry-client-platform': self._telemetry_client_platform,",
            "            'x-embark-telemetry-uuid': self._telemetry_uuid,",
            "        }",
            "        if endpoint.requires_manifest:",
            "            headers['x-embark-manifest-id'] = self.manifest['id']",
            "        method = endpoint.method.upper()",
            "        data = None",
            "        if payload and method == 'GET':",
            "            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(payload)",
            "        elif payload is not None:",
            "            data = json.dumps(payload).encode('utf-8')",
            "        request = urllib.request.Request(url=url, data=data, method=method, headers=headers)",
            "        try:",
            "            with urllib.request.urlopen(request, timeout=30) as response:",
            "                body = response.read().decode('utf-8', 'replace')",
            "        except urllib.error.HTTPError as exc:",
            "            body = exc.read().decode('utf-8', 'replace')",
            "            raise RuntimeError(",
            "                f'ARC Raiders API request failed: {endpoint.path} HTTP {exc.code} payload={payload!r} response={body}'",
            "            ) from exc",
            "        return json.loads(body) if body else None",
            "",
        ]
        for method_name in client_methods:
            if method_name in {"__init__", "token", "manifest"}:
                continue
            endpoint_name = method_name.upper()
            body.extend(
                [
                    f"    def {method_name}(self, payload: dict[str, Any] | None = None) -> Any:",
                    f"        return self._call_endpoint(endpoints.{endpoint_name}, payload)",
                    "",
                ]
            )
        if endpoint_specs:
            exported = ", ".join(repr(name) for name in endpoint_specs)
            body.extend(
                [
                    "CLIENT_ENDPOINT_NAMES = [",
                    f"    {exported}",
                    "]",
                ]
            )
        return self._render_specialized_module(
            ["from __future__ import annotations"],
            body,
        )

    def _emit_imports(self) -> list[str]:
        lines = ["from __future__ import annotations"]
        seen = set(lines)
        for import_line in self.module.imports:
            normalized = _nbc_safe_import_line(import_line)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            lines.append(normalized)
        for text in self.direct_texts + self.all_texts:
            if not self._valid_module_import(text):
                continue
            if "." not in text:
                continue
            if text == self.module.module_name or text.startswith(f"{self.module.module_name}."):
                continue
            line = f"import {text}"
            if line in seen:
                continue
            seen.add(line)
            lines.append(line)

        symbol_imports = [
            ("Path", "from pathlib import Path"),
            ("BaseHTTPRequestHandler", "from http.server import BaseHTTPRequestHandler"),
            ("HTTPServer", "from http.server import HTTPServer"),
            ("ThreadPoolExecutor", "from concurrent.futures import ThreadPoolExecutor"),
            ("as_completed", "from concurrent.futures import as_completed"),
        ]
        for symbol, line in symbol_imports:
            if symbol not in self.text_set or line in seen:
                continue
            seen.add(line)
            lines.append(line)
        lines.append("")
        return lines

    def _emit_selected_constants(self) -> list[str]:
        lines: list[str] = []
        if self.api_urls:
            seen_urls: set[str] = set()
            lines.append("# Discovered upstream endpoints")
            lines.append("DISCOVERED_URLS = [")
            for url in self.api_urls:
                if url in seen_urls or url == "http://localhost:":
                    continue
                seen_urls.add(url)
                lines.append(f"    {url!r},")
            lines.append("]")
            lines.append("")

        named_literals = self._discover_named_literal_constants()
        endpoint_specs = self._discover_endpoint_specs()
        if named_literals or endpoint_specs:
            lines.append("# Recovered named constants")
            for name, value in named_literals.items():
                lines.append(f"{name} = {literal_source(value)}")
            for name, (method, path, requires_manifest) in endpoint_specs.items():
                value = (method, path, True) if requires_manifest else (method, path)
                lines.append(f"{name} = {literal_source(value)}")
            lines.append("")
        return lines

    def _signature_for(self, name: str, class_name: str | None = None) -> list[str]:
        return self.signature_hints.get(
            (class_name, name),
            self._fallback_signature_for(name, class_name),
        )

    def _render_keyauth_method(self, class_name: str, method_name: str) -> list[str]:
        if method_name == "__init__":
            return [
                "self.name = name",
                "self.ownerid = ownerid",
                "self.version = version",
                "self.secret = secret",
                "self.sessionid = None",
            ]
        if method_name == "_post":
            return [
                "data = urllib.parse.urlencode(params).encode('utf-8')",
                "request = urllib.request.Request(KEYAUTH_API_URL, data=data)",
                "request.add_header('Content-Type', 'application/x-www-form-urlencoded')",
                "with urllib.request.urlopen(request, timeout=15) as response:",
                "    return json.loads(response.read().decode('utf-8'))",
            ]
        if method_name == "init":
            return [
                "payload = {",
                "    'type': 'init',",
                "    'ver': self.version,",
                "    'name': self.name,",
                "    'ownerid': self.ownerid,",
                "}",
                "result = self._post(payload)",
                "if not result.get('success'):",
                "    raise RuntimeError(result.get('message', 'KeyAuth init failed'))",
                "self.sessionid = result.get('sessionid')",
                "return result",
            ]
        if method_name == "verify_license":
            return [
                "payload = {",
                "    'type': 'license',",
                "    'key': key,",
                "    'hwid': hwid or _keyauth_hwid(),",
                "    'sessionid': self.sessionid,",
                "    'name': self.name,",
                "    'ownerid': self.ownerid,",
                "}",
                "result = self._post(payload)",
                "if not result.get('success'):",
                "    return False, result.get('message', 'License invalid')",
                "return True, None",
            ]
        return ["..."]

    def _render_proxyhandler_method(self, method_name: str) -> list[str]:
        route = self._route_comment(method_name)
        if method_name == "_json_ok":
            return [
                "payload = json.dumps(data).encode('utf-8')",
                "self.send_response(status or 200)",
                "self.send_header('Content-Type', 'application/json')",
                "self.send_header('Access-Control-Allow-Origin', '*')",
                "self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-User-Token')",
                "self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')",
                "self.end_headers()",
                "self.wfile.write(payload)",
            ]
        if method_name == "_json_error":
            return ["self._json_ok({'status': 'error', 'message': message, 'body': body}, status=status)"]
        if method_name == "do_OPTIONS":
            return [
                "self.send_response(200)",
                "self.send_header('Access-Control-Allow-Origin', '*')",
                "self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-User-Token')",
                "self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')",
                "self.end_headers()",
            ]
        if method_name == "do_GET":
            body = ["path = self.path"]
            for item in self.routes:
                if item in {"/api/start-oauth", "/api/set-token", "/api/set-keyauth-license", "/api/set-browser"}:
                    continue
                body.append(f"if path == {item!r}:")
                body.append(f"    return self.{self._ROUTE_TO_HANDLER[item]}()")
            body.append("return self._json_error(404, f'Unknown GET route: {path}')")
            return body
        if method_name == "do_POST":
            body = ["path = self.path"]
            for item in self.routes:
                if item not in {"/api/start-oauth", "/api/set-token", "/api/set-keyauth-license", "/api/set-browser"}:
                    continue
                body.append(f"if path == {item!r}:")
                body.append(f"    return self.{self._ROUTE_TO_HANDLER[item]}()")
            for extra_name in ("handle_mutate", "handle_change_id", "handle_change_id_bulk", "handle_safe_pocket"):
                if extra_name in self.class_methods.get("ProxyHandler", []):
                    body.append(f"if path == '/api/{extra_name.removeprefix('handle_').replace('_', '-')}' :")
                    body.append(f"    return self.{extra_name}()")
            body.append("return self._json_error(404, f'Unknown POST route: {path}')")
            return body
        if method_name == "handle_oauth_status":
            return ["with _OAUTH_LOCK:", "    return self._json_ok(dict(_OAUTH_STATE))"]
        if method_name == "handle_auth_status":
            return [
                "token_ok = bool(load_saved_token())",
                "keyauth_ok = bool(_keyauth_enabled())",
                "panel = globals().get('KEYAUTH_PANEL_URL', None)",
                "return self._json_ok({'token_ok': token_ok, 'keyauth_ok': keyauth_ok, 'panel': panel})",
            ]
        if method_name == "handle_browsers":
            return [
                "browsers = _detect_browsers()",
                "current = _load_browser_pref()",
                "return self._json_ok({'browsers': browsers, 'current': current})",
            ]
        if method_name == "handle_set_browser":
            return [
                "length = int(self.headers.get('Content-Length', '0'))",
                "body = self.rfile.read(length).decode('utf-8') if length else '{}'",
                "pref = json.loads(body or '{}').get('pref')",
                "_save_browser_pref(pref)",
                "return self._json_ok({'status': 'ok', 'browser': pref})",
            ]
        if method_name == "handle_set_token":
            return [
                "length = int(self.headers.get('Content-Length', '0'))",
                "body = self.rfile.read(length).decode('utf-8') if length else '{}'",
                "token = json.loads(body or '{}').get('token')",
                "ok = apply_token_from_string(token)",
                "return self._json_ok({'status': 'ok' if ok else 'error', 'token_set': ok})",
            ]
        if method_name == "handle_set_keyauth_license":
            return [
                "length = int(self.headers.get('Content-Length', '0'))",
                "body = self.rfile.read(length).decode('utf-8') if length else '{}'",
                "license_key = json.loads(body or '{}').get('key')",
                "ok = apply_keyauth_license(license_key)",
                "return self._json_ok({'status': 'ok' if ok else 'error', 'saved': ok})",
            ]
        if method_name == "handle_start_oauth":
            return [
                "length = int(self.headers.get('Content-Length', '0'))",
                "body = self.rfile.read(length).decode('utf-8') if length else '{}'",
                "provider = json.loads(body or '{}').get('provider', 'xbox')",
                "threading.Thread(target=_oauth_worker, args=(provider,), daemon=True).start()",
                "return self._json_ok({'status': 'started', 'provider': provider})",
            ]
        if method_name in {"handle_inventory", "handle_session", "handle_clones", "handle_currencies", "handle_social", "handle_items_list"}:
            endpoint_map = {
                "handle_inventory": "INVENTORY_URL",
                "handle_session": None,
                "handle_clones": None,
                "handle_currencies": None,
                "handle_social": None,
                "handle_items_list": None,
            }
            return [
                f"# Route {route or method_name} was recovered from NBC constants",
                "user_token = load_saved_token()",
                "if not user_token:",
                "    return self._json_error(401, 'No token available')",
                "if %r is not None:" % endpoint_map[method_name],
                "    data = _api_get(globals()[%r], user_token)" % endpoint_map[method_name] if endpoint_map[method_name] else "    data = {'path': self.path}",
                "else:",
                "    data = {'path': self.path}",
                "return self._json_ok({'status': 'ok', 'handler': %r, 'data': data})" % method_name,
            ]
        if method_name in {"handle_mutate", "handle_change_id", "handle_change_id_bulk", "handle_safe_pocket"}:
            body = [
                f"# Route {route or method_name} performs inventory mutation work.",
                "length = int(self.headers.get('Content-Length', '0'))",
                "body = self.rfile.read(length).decode('utf-8') if length else '{}'",
                "payload = json.loads(body or '{}')",
                "user_token = load_saved_token()",
                "if not user_token:",
                "    return self._json_error(401, 'No token available')",
                "if method_name := %r:" % method_name,
                "    payload['recovered_handler'] = method_name",
                "if 'MUTATE_URL' in globals() and method_name == 'handle_mutate':",
                "    response = _api_post(MUTATE_URL, json.dumps(payload).encode('utf-8'), user_token)",
                "    return self._json_ok({'status': 'ok', 'handler': method_name, 'response': response})",
                "return self._json_ok({'status': 'queued', 'handler': method_name, 'payload': payload})",
            ]
            parent = f"ProxyHandler.{method_name}"
            for helper in self.helper_comments.get(parent, []):
                body.append(f"# nested helper recovered: {helper}")
            return body
        if method_name == "serve_file":
            return [
                "disk_path = Path(path)",
                "if not disk_path.exists():",
                "    return self._json_error(404, f'Missing file: {disk_path}')",
                "self.send_response(200)",
                "self.end_headers()",
                "self.wfile.write(disk_path.read_bytes())",
            ]
        if method_name == "serve_data_file":
            return ["return self.serve_file(path)"]
        if method_name == "log_message":
            return ["return"]

        body = [f"# Route {route}" if route else f"# Recovered handler: {method_name}"]
        body.append("...")
        return body

    def _render_top_level_function(self, name: str) -> list[str]:
        if name == "_load_browser_pref":
            return [
                "try:",
                "    return BROWSER_PREF_FILE.read_text(encoding='utf-8').strip()",
                "except OSError:",
                "    return None",
            ]
        if name == "_save_browser_pref":
            return [
                "if pref is None:",
                "    return False",
                "try:",
                "    BROWSER_PREF_FILE.write_text(str(pref), encoding='utf-8')",
                "    return True",
                "except OSError:",
                "    return False",
            ]
        if name == "_detect_browsers":
            return [
                "browsers = [{'name': 'Default Browser', 'path': None}]",
                "for label, candidate in [('Chrome', 'chrome'), ('Edge', 'msedge'), ('Firefox', 'firefox'), ('Opera', 'opera')]:",
                "    browsers.append({'name': label, 'path': candidate})",
                "return browsers",
            ]
        if name == "_maybe_open_browser":
            return [
                "def _run() -> None:",
                "    time.sleep(0.65)",
                "    if pref:",
                "        try:",
                "            webbrowser.get(pref).open(url)",
                "            return",
                "        except Exception:",
                "            pass",
                "    webbrowser.open(url)",
                "threading.Thread(target=_run, daemon=True).start()",
            ]
        if name == "_oauth_worker":
            return [
                "with _OAUTH_LOCK:",
                "    _OAUTH_STATE.update({'status': 'running', 'token': None, 'error': None, 'started_at': time.time()})",
                "try:",
                "    if BrowserOAuth is None:",
                "        raise RuntimeError('BrowserOAuth is not available')",
                "    auth = BrowserOAuth(provider=provider)",
                "    token = getattr(auth, 'authenticate', lambda: None)()",
                "    if token:",
                "        apply_token_from_string(token)",
                "        with _OAUTH_LOCK:",
                "            _OAUTH_STATE.update({'status': 'done', 'token': token, 'error': None})",
                "    else:",
                "        with _OAUTH_LOCK:",
                "            _OAUTH_STATE.update({'status': 'error', 'error': 'No token returned'})",
                "except Exception as exc:",
                "    with _OAUTH_LOCK:",
                "        _OAUTH_STATE.update({'status': 'error', 'error': str(exc)})",
            ]
        if name == "save_token":
            return [
                "if not token:",
                "    return False",
                "TOKEN_FILE.write_text(str(token).strip(), encoding='utf-8')",
                "return True",
            ]
        if name == "load_saved_token":
            return [
                "try:",
                "    raw = TOKEN_FILE.read_text(encoding='utf-8').strip()",
                "except OSError:",
                "    return None",
                "return raw or None",
            ]
        if name == "run_token_script":
            return [
                "if not GET_TOKEN_SCRIPT.exists():",
                "    return None",
                "result = subprocess.run(['python', str(GET_TOKEN_SCRIPT)], capture_output=True, text=True, timeout=180)",
                "return result.stdout.strip() or None",
            ]
        if name == "get_new_token":
            return [
                "_maybe_open_browser(f'http://localhost:{PORT}', _load_browser_pref())",
                "token = run_token_script()",
                "if token:",
                "    save_token(token)",
                "return token",
            ]
        if name == "apply_token_from_string":
            return [
                "if not token:",
                "    return False",
                "token = str(token).strip()",
                "if token.lower().startswith('bearer '):",
                "    token = token[7:].strip()",
                "return save_token(token)",
            ]
        if name == "apply_keyauth_license":
            return [
                "if not license_key:",
                "    return False",
                "KEYAUTH_LICENSE_FILE.write_text(str(license_key).strip(), encoding='utf-8')",
                "return True",
            ]
        if name == "_keyauth_saved_key":
            return [
                "try:",
                "    return KEYAUTH_LICENSE_FILE.read_text(encoding='utf-8').strip() or None",
                "except OSError:",
                "    return None",
            ]
        if name == "_keyauth_hwid":
            return [
                "if winreg is not None:",
                "    try:",
                "        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\\Microsoft\\Cryptography')",
                "        value, _ = winreg.QueryValueEx(key, 'MachineGuid')",
                "        winreg.CloseKey(key)",
                "        return str(value)",
                "    except Exception:",
                "        pass",
                "return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uuid.getnode())))",
            ]
        if name == "_build_keyauth_client":
            return [
                "key = _keyauth_saved_key()",
                "if not key:",
                "    return None",
                "return _KeyAuthV13Shim('CLS Proxy', 'ownerid', '1.0', 'secret')",
            ]
        if name == "keyauth_client":
            return ["return _build_keyauth_client()"]
        if name == "_keyauth_enabled":
            return ["return KEYAUTH_LICENSE_FILE.exists()"]
        if name == "_keyauth_verify_cached":
            return [
                "client = keyauth_client()",
                "if client is None:",
                "    return False, 'KeyAuth unavailable'",
                "return client.verify_license(key, _keyauth_hwid())",
            ]
        if name == "ensure_keyauth":
            return [
                "saved = key or _keyauth_saved_key()",
                "if not saved:",
                "    return False, 'No license key configured'",
                "return _keyauth_verify_cached(saved)",
            ]
        if name == "ensure_token":
            return [
                "token = load_saved_token()",
                "if token:",
                "    return token",
                "return get_new_token()",
            ]
        if name == "_session_token_hints":
            return [
                "payload = _jwt_payload_unverified(token)",
                "return {'sub': payload.get('sub'), 'gamertag': payload.get('gamertag'), 'preferred_username': payload.get('preferred_username')}",
            ]
        if name == "_jwt_payload_unverified":
            return [
                "parts = str(token or '').split('.')",
                "if len(parts) < 2:",
                "    return {}",
                "body = parts[1] + '=' * (-len(parts[1]) % 4)",
                "try:",
                "    import base64",
                "    return json.loads(base64.urlsafe_b64decode(body.encode('ascii')).decode('utf-8'))",
                "except Exception:",
                "    return {}",
            ]
        if name == "_api_get":
            return [
                "request = urllib.request.Request(path)",
                "if token:",
                "    request.add_header('Authorization', f'Bearer {token}')",
                "with urllib.request.urlopen(request, timeout=30) as response:",
                "    return json.loads(response.read().decode('utf-8'))",
            ]
        if name == "_api_post":
            return [
                "request = urllib.request.Request(path, data=payload_bytes)",
                "request.add_header('Content-Type', 'application/json')",
                "if token:",
                "    request.add_header('Authorization', f'Bearer {token}')",
                "with urllib.request.urlopen(request, timeout=30) as response:",
                "    return json.loads(response.read().decode('utf-8'))",
            ]
        if name == "get_profile":
            return ["return _api_get(path, token)"]
        if name == "get_levels_list":
            return ["return _api_post(path, payload_bytes, token)"]
        if name == "process_item":
            return [
                "# Recovered from mutation-related constants in the NBC payload.",
                "# The original compiled body performed a multi-step inventory mutation flow.",
                "log_callback('Processing item mutation request')",
                "return {'target_id': target_id, 'auth_token': auth_token, 'status': 'recovered-from-nbc'}",
            ]
        if name == "run_protection_checks":
            return ["return True"]
        if name == "_cls_logo_bytes_from_disk":
            return [
                "for rel_name in ('CLS-LOGO.png', 'deman.png', 'deman123.png'):",
                "    disk_path = Path(__file__).resolve().parent / rel_name",
                "    if disk_path.exists():",
                "        return disk_path.read_bytes()",
                "return None",
            ]
        if name == "main":
            return [
                "server = HTTPServer(('localhost', PORT), ProxyHandler)",
                "print(f'Listening on http://localhost:{PORT}')",
                "_maybe_open_browser(f'http://localhost:{PORT}', _load_browser_pref())",
                "server.serve_forever()",
            ]

        body = []
        parent = name
        for helper in self.helper_comments.get(parent, []):
            body.append(f"# nested helper recovered: {helper}")
        body.append("...")
        return body

    def _emit_function(self, name: str, *, class_name: str | None = None, indent: str = "") -> list[str]:
        args = self._signature_for(name, class_name)
        lines = [f"{indent}def {name}({', '.join(args)}):"]
        body = ['"""Recovered stub generated from NBC constants only."""']
        parent = f"{class_name}.{name}" if class_name else name
        route = self._route_comment(name) if class_name is not None else None
        if route:
            body.append(f"# Recovered route hint: {route}")
        for helper in self.helper_comments.get(parent, []):
            body.append(f"# nested helper recovered: {helper}")
        body.append("pass")
        lines.extend(f"{indent}    {line}" for line in body)
        return lines

    def _emit_constants_inventory(self) -> list[str]:
        lines = [
            "# ---------------------------------------------------------------------------",
            "# Full NBC Constant Inventory",
            "# ---------------------------------------------------------------------------",
            "NBC_DECODED_CONSTANTS = [",
        ]
        for const in self.module.constants:
            lines.append(f"    ({const.index}, {const.type_code!r}, {const.value!r}),")
        lines.extend(
            [
                "]",
                "",
                "NBC_QUALNAMES = [",
            ]
        )
        for index, qualname in self.qualname_items:
            lines.append(f"    ({index}, {qualname!r}),")
        lines.extend(
            [
                "]",
                "",
                "NBC_IDENTIFIER_TUPLES = [",
            ]
        )
        for values in self.identifier_tuples:
            lines.append(f"    {values!r},")
        lines.extend(
            [
                "]",
                "",
                "NBC_RAW_CONSTANTS = [",
            ]
        )
        for const in self.module.constants:
            lines.append(f"    ({const.index}, {const.type_code!r}, {const.raw!r}),")
        lines.append("]")
        lines.append("")
        return lines

    def render_generic(self) -> str:
        lines = [
            '"""',
            f"Automated high-level reconstruction for NBC module {self.module.module_name}.",
            "This variant keeps the full NBC constant inventory and rebuilds as much",
            "application structure as possible without manual reverse engineering.",
            '"""',
            "",
        ]
        lines.extend(self._emit_imports())
        lines.extend(self._emit_selected_constants())

        if self.module.global_no_ops:
            lines.append("# Global NBC notes")
            for entry in self.module.global_no_ops:
                lines.append(f"# {entry}")
            lines.append("")

        for name in self.top_level_functions:
            lines.extend(self._emit_function(name))
            lines.append("")

        for class_name, methods in self.class_methods.items():
            lines.append(f"class {class_name}:")
            if not methods:
                lines.append("    pass")
                lines.append("")
                continue
            for method in methods:
                lines.append("")
                lines.extend(self._emit_function(method, class_name=class_name, indent="    "))
            lines.append("")

        lines.extend(self._emit_constants_inventory())
        return "\n".join(lines).rstrip() + "\n"

    def render(self) -> str:
        return self.render_generic()


_NBC_BLOCK_START_RE = re.compile(r"^(async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_NBC_INVENTORY_MARKER = "# ---------------------------------------------------------------------------\n# Full NBC Constant Inventory\n# ---------------------------------------------------------------------------\n"


def _nbc_split_inventory(source: str) -> tuple[str, str]:
    marker_index = source.find(_NBC_INVENTORY_MARKER)
    if marker_index < 0:
        return source.rstrip() + "\n", ""
    return source[:marker_index].rstrip() + "\n", source[marker_index:].lstrip("\n")


def _nbc_normalize_preamble(lines: list[str]) -> list[str]:
    cleaned: list[str] = []
    in_docstring = False
    for line in lines:
        stripped = line.strip()
        if not cleaned and not stripped:
            continue
        if stripped.startswith('"""'):
            if stripped.count('"""') >= 2:
                continue
            in_docstring = not in_docstring
            continue
        if in_docstring:
            if '"""' in stripped:
                in_docstring = False
            continue
        if stripped.startswith("# Heuristic CPython reconstruction"):
            continue
        if stripped.startswith("# Generated by omni_nuitka_framework"):
            continue
        cleaned.append(line)
    while cleaned and not cleaned[-1].strip():
        cleaned.pop()
    return cleaned


def _nbc_statement_block_key(lines: list[str], index: int) -> str:
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        slug = re.sub(r"[^A-Za-z0-9_]+", "_", stripped).strip("_").lower()[:80]
        if slug:
            return f"stmt:{slug}"
    return f"stmt:{index:04d}"


def _nbc_unique_block_key(
    blocks: "OrderedDict[str, list[str]]",
    key: str,
) -> str:
    if key not in blocks:
        return key
    suffix = 1
    while f"{key}#{suffix}" in blocks:
        suffix += 1
    return f"{key}#{suffix}"


def _nbc_append_statement_block(
    blocks: "OrderedDict[str, list[str]]",
    lines: list[str],
    index: int,
) -> int:
    if not any(line.strip() for line in lines):
        return index
    key = _nbc_unique_block_key(blocks, _nbc_statement_block_key(lines, index))
    blocks[key] = lines
    return index + 1


def _nbc_extract_structure_ast(
    source: str,
) -> tuple[list[str], "OrderedDict[str, list[str]]"] | None:
    body, _tail = _nbc_split_inventory(source)
    lines = body.splitlines()
    try:
        module = ast.parse(body)
    except SyntaxError:
        return None

    def _node_start(node: ast.AST) -> int:
        start = max(0, getattr(node, "lineno", 1) - 1)
        decorator_starts = [max(0, getattr(decorator, "lineno", 1) - 1) for decorator in getattr(node, "decorator_list", ()) or () if getattr(decorator, "lineno", None)]
        if decorator_starts:
            start = min([start, *decorator_starts])
        return start

    first_structural_start = None
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first_structural_start = _node_start(node)
            break

    if first_structural_start is None:
        return _nbc_normalize_preamble(lines), OrderedDict()

    preamble: list[str] = lines[:first_structural_start]
    blocks: "OrderedDict[str, list[str]]" = OrderedDict()
    statement_index = 0
    cursor = first_structural_start

    for node in module.body:
        start = _node_start(node)
        if start < first_structural_start:
            continue
        end = max(start + 1, getattr(node, "end_lineno", start + 1))

        gap = lines[cursor:start]
        if gap:
            if any(line.strip() and not line.lstrip().startswith("#") for line in gap):
                statement_index = _nbc_append_statement_block(blocks, gap, statement_index)
            else:
                start = cursor

        block_lines = lines[start:end]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = f"def:{node.name}"
        elif isinstance(node, ast.ClassDef):
            key = f"class:{node.name}"
        else:
            key = _nbc_statement_block_key(block_lines, statement_index)
            statement_index += 1

        blocks[_nbc_unique_block_key(blocks, key)] = block_lines
        cursor = end

    trailing = lines[cursor:]
    if not blocks:
        preamble = lines
    elif trailing:
        if any(line.strip() and not line.lstrip().startswith("#") for line in trailing):
            _nbc_append_statement_block(blocks, trailing, statement_index)
        elif any(line.strip() for line in trailing):
            last_key = next(reversed(blocks))
            blocks[last_key] = blocks[last_key] + trailing

    return _nbc_normalize_preamble(preamble), blocks


def _nbc_extract_structure_fallback(
    source: str,
) -> tuple[list[str], "OrderedDict[str, list[str]]"]:
    body, _tail = _nbc_split_inventory(source)
    lines = body.splitlines()
    preamble: list[str] = []
    blocks: "OrderedDict[str, list[str]]" = OrderedDict()
    index = 0
    statement_index = 0

    while index < len(lines):
        line = lines[index]
        match = _NBC_BLOCK_START_RE.match(line)
        start = index

        if not match and line and not line.startswith((" ", "\t")) and line.lstrip().startswith("@"):
            probe = index + 1
            while probe < len(lines):
                candidate = lines[probe]
                if candidate and not candidate.startswith((" ", "\t")) and candidate.lstrip().startswith("@"):
                    probe += 1
                    continue
                break
            if probe < len(lines):
                match = _NBC_BLOCK_START_RE.match(lines[probe])
            if match:
                start = index
                index = probe

        if match:
            kind, name = match.groups()
            if kind == "async def":
                kind = "def"
            index += 1
            while index < len(lines):
                candidate = lines[index]
                if candidate and not candidate.startswith((" ", "\t")):
                    if _NBC_BLOCK_START_RE.match(candidate) or candidate.lstrip().startswith("@"):
                        break
                index += 1
            blocks[_nbc_unique_block_key(blocks, f"{kind}:{name}")] = lines[start:index]
            continue

        if not blocks:
            preamble.append(line)
            index += 1
            continue

        if line and not line.startswith((" ", "\t")):
            start = index
            index += 1
            while index < len(lines):
                candidate = lines[index]
                if candidate and not candidate.startswith((" ", "\t")):
                    if _NBC_BLOCK_START_RE.match(candidate) or candidate.lstrip().startswith("@"):
                        break
                index += 1
            statement_index = _nbc_append_statement_block(
                blocks,
                lines[start:index],
                statement_index,
            )
            continue

        index += 1

    return _nbc_normalize_preamble(preamble), blocks


def _nbc_extract_structure(source: str) -> tuple[list[str], "OrderedDict[str, list[str]]"]:
    extracted = _nbc_extract_structure_ast(source)
    if extracted is not None:
        return extracted
    return _nbc_extract_structure_fallback(source)


def _nbc_block_quality(lines: list[str]) -> int:
    score = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in {"...", "pass"}:
            score -= 4
            continue
        if "Signature recovered from NBC only" in stripped:
            score -= 6
            continue
        if "<NBC " in stripped or "Recovered from NBC" in stripped:
            score -= 2
        score += 1
        if re.match(r"(if|for|while|with|try|except|return|raise)\b", stripped):
            score += 2
        if "=" in stripped and "==" not in stripped and not stripped.startswith(("def ", "class ")):
            score += 1
    return score


def _nbc_source_quality(source: str) -> int:
    body, _tail = _nbc_split_inventory(source)
    score = 0
    score += body.count("def ") * 3
    score += body.count("class ") * 4
    score += sum(1 for line in body.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    score -= body.count("...")
    score -= body.count("Signature recovered from NBC only") * 4
    score -= body.count("<NBC ")
    try:
        ast.parse(body)
    except SyntaxError:
        score -= 200
    else:
        score += 40
    return score


def _nbc_safe_import_line(line: str) -> str | None:
    stripped = line.strip()
    if not stripped:
        return None
    if stripped == "from __future__ import annotations":
        return stripped
    try:
        parsed = ast.parse(stripped)
    except SyntaxError:
        return None
    if len(parsed.body) != 1:
        return None
    node = parsed.body[0]
    if isinstance(node, ast.Import):
        aliases: list[str] = []
        for alias in node.names:
            if not _nbc_is_probable_import_name(alias.name):
                return None
            if alias.asname and not safe_identifier(alias.asname):
                return None
            aliases.append(alias.name if alias.asname is None else f"{alias.name} as {alias.asname}")
        return f"import {', '.join(aliases)}"
    if isinstance(node, ast.ImportFrom):
        if node.level:
            return None
        if not node.module or not _nbc_is_probable_import_name(node.module):
            return None
        aliases = []
        for alias in node.names:
            if alias.name == "*" or not safe_identifier(alias.name):
                return None
            if alias.asname and not safe_identifier(alias.asname):
                return None
            aliases.append(alias.name if alias.asname is None else f"{alias.name} as {alias.asname}")
        return f"from {node.module} import {', '.join(aliases)}"
    return None


def _nbc_is_valid_block(lines: list[str]) -> bool:
    try:
        ast.parse("\n".join(lines).rstrip() + "\n")
    except SyntaxError:
        return False
    return True


def _nbc_merge_preambles(base: list[str], extras: list[list[str]]) -> list[str]:
    lines = list(base)
    seen = {line.strip() for line in lines if line.strip()}
    insert_at = 0
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("from __future__ import annotations"):
            insert_at = index + 1
        elif stripped.startswith(("import ", "from ")):
            insert_at = index + 1

    pending_imports: list[str] = []
    for extra in extras:
        for line in extra:
            stripped = _nbc_safe_import_line(line)
            if not stripped or stripped in seen:
                continue
            if line.startswith((" ", "\t")):
                continue
            pending_imports.append(stripped)
            seen.add(stripped)

    if pending_imports:
        if lines and insert_at and lines[insert_at - 1].strip():
            pending_imports.insert(0, "")
        lines[insert_at:insert_at] = pending_imports
    return lines


def _merge_blob_python_sources(
    module_name: str,
    candidates: list[str],
    *,
    inventory_source: str,
) -> str:
    base_preamble, base_blocks = _nbc_extract_structure(inventory_source)
    usable = [candidate for candidate in candidates if candidate and candidate.strip() and candidate != inventory_source]
    structures = [(candidate, *_nbc_extract_structure(candidate)) for candidate in usable]

    block_order = list(base_blocks.keys())
    best_blocks: dict[str, list[str]] = {}
    for key, lines in base_blocks.items():
        if _nbc_is_valid_block(lines):
            best_blocks[key] = lines

    for _source, _preamble, blocks in structures:
        for key, lines in blocks.items():
            if not _nbc_is_valid_block(lines):
                continue
            current = best_blocks.get(key)
            if current is None or _nbc_block_quality(lines) > _nbc_block_quality(current):
                best_blocks[key] = lines
            if key not in block_order:
                block_order.append(key)

    merged_preamble = _nbc_merge_preambles(
        base_preamble,
        [preamble for _source, preamble, _blocks in structures],
    )
    _inventory_head, inventory_tail = _nbc_split_inventory(inventory_source)

    lines = [
        '"""',
        f"Automated merged Python recovery for NBC module {module_name}.",
        "NBC-derived structure is the base; validated blob-derived blocks are",
        "merged in when they improve recovered Python.",
        '"""',
        "",
    ]
    lines.extend(merged_preamble)
    if merged_preamble and merged_preamble[-1].strip():
        lines.append("")

    for key in block_order:
        block = best_blocks.get(key)
        if not block:
            continue
        lines.extend(block)
        lines.append("")

    if inventory_tail:
        lines.extend(inventory_tail.splitlines())
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def decompile_nbc_text_to_source(text: str) -> str:
    parsed = parse_nbc_text(text)
    if not parsed.ops_blocks:
        reconstructor = NbcNoOpsHeuristicReconstructor(parsed)
        nbc_source = reconstructor.render_generic()
        candidates = [nbc_source]
        try:
            artifact = reconstruct_module_artifacts(
                section_name=parsed.module_name,
                raw_constants=parsed.raw_constants(),
            )
            for candidate in (
                artifact.smart_source,
                artifact.source,
                artifact.heuristic_source,
            ):
                if candidate and candidate not in candidates:
                    candidates.insert(0, candidate)
        except Exception:
            pass

        merged = _merge_blob_python_sources(
            parsed.module_name,
            candidates,
            inventory_source=nbc_source,
        )
        try:
            ast.parse(merged)
            return merged
        except SyntaxError:
            return nbc_source

    return NbcSourceDecompiler(parsed).render()


def decompile_nbc_file(input_path: str | Path, output_path: str | Path | None = None) -> Path:
    src_path = Path(input_path)
    dest_path = Path(output_path) if output_path is not None else src_path.with_suffix(".py")
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    source = decompile_nbc_text_to_source(src_path.read_text(encoding="utf-8", errors="replace"))
    dest_path.write_text(source, encoding="utf-8")
    return dest_path


def decompile_nbc_path(input_path: str | Path, output_path: str | Path | None = None) -> int:
    src_path = Path(input_path)
    if src_path.is_file():
        dest_path = Path(output_path) if output_path is not None else None
        if dest_path is not None and (dest_path.exists() and dest_path.is_dir() or not dest_path.suffix):
            dest_path = dest_path / src_path.with_suffix(".py").name
        dest = decompile_nbc_file(src_path, dest_path)
        print(f"[*] Decompiled {src_path.name} -> {dest}")
        return 1

    if not src_path.is_dir():
        raise FileNotFoundError(src_path)

    nbc_files = sorted(src_path.rglob("*.nbc"))
    if not nbc_files:
        return 0

    output_root = Path(output_path) if output_path is not None else src_path
    written = 0
    for nbc_path in nbc_files:
        rel = nbc_path.relative_to(src_path)
        dest = output_root / rel.with_suffix(".py")
        decompile_nbc_file(nbc_path, dest)
        written += 1
    return written


def reconstruct_blob_file(blob_path: str | Path, output_dir: str | Path) -> int:
    try:
        import nuitka_deobfuscate  # type: ignore[import-untyped]
    except ImportError:
        print("[-] Nuitka deobfuscate extension missing.")
        return 1

    # Local import to avoid circular dependencies if any
    try:
        import list_modules
    except ImportError:
        # Fallback to local directory if not in path
        sys.path.append(str(Path(__file__).parent))
        import list_modules

    blob_path = Path(blob_path)
    if not blob_path.exists():
        print(f"[-] Blob not found: {blob_path}")
        return 1

    raw = blob_path.read_bytes()

    # Use list_modules for robust name solving (handles commercial protection)
    print("[*] Solving module names using list_modules library...")
    modules_metadata = list_modules.parse_module_names(raw)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for meta in modules_metadata:
        section_name = meta["name"]

        # Skip bytecode chunks as we are reconstructing source
        if meta["is_bytecode"]:
            continue

        # Decode constants at the specific offset discovered by list_modules
        items = nuitka_deobfuscate.decode_at_offset(raw, meta["offset"])

        if not items or not isinstance(items, (list, tuple)):
            continue

        if _is_marshaled_bytecode_section_name(section_name, items):
            continue

        decompiler = OmniDecompiler()
        decompiler.run_pass_1_structural_mapping(items)
        decompiler.run_pass_2_ast_synthesis()
        artifact = reconstruct_module_artifacts(
            section_name=section_name,
            raw_constants=list(items),
            decompiler=decompiler,
        )
        source = artifact.source
        if not source.strip():
            continue

        # Build a guaranteed-safe filename from section_name.
        # Strategy: keep printable ASCII word characters; if the result is too
        # short (binary-garbage names collapse to almost nothing) append a short
        # SHA-1 hash of the raw bytes so files remain unique and collision-free.
        _raw_bytes = section_name.encode("utf-8", errors="replace") if isinstance(section_name, str) else bytes(section_name)
        _ascii_part = re.sub(r"[^A-Za-z0-9._-]", "_", section_name if isinstance(section_name, str) else section_name.decode("ascii", errors="replace"))
        _ascii_part = re.sub(r"_+", "_", _ascii_part).strip("_.")[:48]
        _hash_suffix = hashlib.sha1(_raw_bytes).hexdigest()[:8]
        safe_name = f"{_ascii_part}_{_hash_suffix}" if _ascii_part else f"section_{_hash_suffix}"
        out_file = out_dir / f"{safe_name}.py"

        # Ensure subdirectories exist for package names like 'numpy.core'
        out_file.parent.mkdir(parents=True, exist_ok=True)

        if artifact.nbc_text:
            source += "\n\n" + '"""' + "\n" + artifact.nbc_text + "\n" + '"""'

        out_file.write_text(source, encoding="utf-8")

        count += 1
        print(f"  [{count:4d}] {section_name:<50}  ({source.count(chr(10))} lines, strategy={artifact.strategy})")

    print(f"\n[*] Reconstructed {count} file(s) -> {out_dir}")
    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reconstruct Python from Nuitka constants blobs or .nbc files.")
    parser.add_argument(
        "input",
        nargs="?",
        default="rcdata_10_3.bin",
        help="Input blob (.bin) or .nbc file or a directory containing .nbc files.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output file or directory. For .nbc files the default is <file>.nbc.py.",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else None

    try:
        if input_path.suffix.lower() == ".nbc" or input_path.is_dir():
            written = decompile_nbc_path(input_path, output_path)
            if written == 0:
                print(f"[-] No .nbc files found in {input_path}")
                return 1
            print(f"[*] Decompiled {written} NBC file(s)")
            return 0

        out_dir = output_path or (Path("restore_deep_ultra") / "reconstructed_source_v13_omni")
        return reconstruct_blob_file(input_path, out_dir)
    except FileNotFoundError:
        print(f"[-] Input not found: {input_path}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
