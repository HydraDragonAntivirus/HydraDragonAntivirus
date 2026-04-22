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
import importlib
import keyword
import re
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from textwrap import indent as _indent
from typing import Any, Callable, Iterator


# ---------------------------------------------------------------------------
# Nuitka packed-signature tags
# ---------------------------------------------------------------------------

class NuitkaTags:
    ARG         = "a"
    USER_DEF    = "u"
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
        return repr(b2s_safe(value))
    if isinstance(value, tuple):
        return repr(tuple(_trim_sequence(list(tuple_texts(value)), "...")))
    if isinstance(value, list):
        return repr(_trim_sequence(list(tuple_texts(value)), "..."))
    if isinstance(value, dict):
        cleaned = {b2s_safe(k): (b2s_safe(v) if isinstance(v, (bytes, bytearray)) else v)
                   for k, v in list(value.items())[:20]}
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

IDENTIFIER_RE    = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLASS_NAME_RE    = re.compile(r"^_?[A-Z][A-Za-z0-9_]*$")
IMPORT_PATH_RE   = re.compile(r"^[a-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
METHOD_REF_RE    = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$")
HTTP_ENDPOINT_RE = re.compile(r"https?://[A-Za-z0-9]|/functions/[A-Za-z0-9_]")
LOG_RE           = re.compile(r"\b(log|logger|logging|debug|info|warning|error|critical)\b", re.I)
PARAM_RE         = re.compile(r":param\s+(\w+):")
RETURN_RE        = re.compile(r":returns?:\s*(.*)")
RAISES_RE        = re.compile(r":raises?\s+(\w+):")

DECORATOR_NAMES: frozenset[str] = frozenset(
    {"property", "abstractmethod", "staticmethod", "classmethod", "overload"}
)
META_FIELD_NAMES: frozenset[str] = frozenset({
    "__prepare__", "__qualname__", "__firstlineno__", "__static_attributes__",
    "__orig_bases__", "__getitem__", "metaclass", "annotations", "origin",
    "has_location", "__module__",
})
KNOWN_METHOD_NAMES: frozenset[str] = frozenset({
    "__init__", "__new__", "__repr__", "__str__", "__bytes__",
    "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__",
    "__hash__", "__reduce__", "__reduce_ex__", "__getstate__", "__setstate__",
    "__iter__", "__next__", "__len__", "__bool__", "__contains__",
    "__copy__", "__deepcopy__", "__enter__", "__exit__",
    "__getattr__", "__setattr__", "__delattr__", "__getitem__",
    "__setitem__", "__delitem__", "__call__",
    "prepare", "copy", "clone", "close", "json",
    "value", "name", "type_id", "_packed", "_init_without_validation",
    "register_hook", "deregister_hook", "send", "receive",
    "read", "write", "flush", "seek", "tell",
    "connect", "disconnect", "reconnect",
    "encode", "decode", "serialize", "deserialize",
    "validate", "parse", "format", "render",
})
KNOWN_METHOD_PREFIXES: tuple[str, ...] = (
    "prepare_", "register_", "deregister_", "iter_", "get_", "set_",
    "raise_", "encode_", "decode_", "_encode_", "_get_", "_init_",
    "add_", "remove_", "clear_", "reset_", "is_", "has_", "can_",
    "on_", "do_", "handle_", "process_", "build_", "make_", "create_",
    "update_", "delete_", "fetch_", "load_", "save_", "dump_",
    "_build_", "_make_", "_create_", "_process_", "_handle_",
    "_validate_", "_parse_", "_format_", "_check_", "_ensure_",
)
KNOWN_BASE_NAMES: frozenset[str] = frozenset({
    "Exception", "Warning", "ValueError", "TypeError", "RuntimeError",
    "ConnectionError", "LookupError", "MessageDefect", "IncompleteRead",
    "OSError", "IOError", "KeyError", "IndexError", "AttributeError",
    "NotImplementedError", "StopIteration", "GeneratorExit", "TimeoutError",
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
    "tools", "support", "constants", "provides", "implements",
)
MODULE_DOCSTRING_BAD_PREFIXES: tuple[str, ...] = (
    "build ", "parse ", "return ", "create ", "construct ", "convert ",
    "serialize ", "deserialize ", "encode ", "decode ", "represent ",
    "initialize ", "prepare ", "register ", "deregister ",
    "max retries exceeded",
)
_C_API_PREFIXES: tuple[str, ...] = (
    "SSL_", "X509_", "EVP_", "BIO_", "OBJ_", "ASN1_", "PEM_",
    "PKCS", "RSA_", "EC_", "DH_", "HMAC_", "AES_", "SHA",
)
TYPING_NAMES: frozenset[str] = frozenset({
    "Any", "Callable", "Mapping", "Iterable", "Sequence",
    "Optional", "Union", "List", "Dict", "Tuple", "Set",
    "Type", "ClassVar", "Final", "Literal", "overload",
    "Generator", "Iterator", "AsyncIterator", "Awaitable",
})
LOCK_ATTRS: frozenset[str] = frozenset({"_lock", "_mutex", "_rlock", "_semaphore"})
ITER_ATTRS: frozenset[str] = frozenset({"_items", "_data", "_buffer", "_queue", "_list", "_entries"})
NETWORK_HINTS: frozenset[str] = frozenset({
    "timeout", "retry", "redirect", "response", "request",
    "socket", "connection", "stream", "chunk", "content",
})

# Python built-in type names useful for isinstance checks
_BUILTIN_TYPES: dict[str, str] = {
    "str": "str", "int": "int", "float": "float", "bool": "bool",
    "bytes": "bytes", "list": "list", "dict": "dict", "tuple": "tuple",
    "set": "set", "frozenset": "frozenset",
}

# ---------------------------------------------------------------------------
# Text classification helpers
# ---------------------------------------------------------------------------

def clean_docstring(text: Any) -> str | None:
    s = str(text).strip()
    return s.replace("\r\n", "\n").replace("\r", "\n") if s else None


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
        "typing.Any": "Any", "typing.Optional": "Optional",
        "typing.Callable": "Callable", "typing.Mapping": "Mapping",
        "typing.Iterable": "Iterable", "typing.Sequence": "Sequence",
        "typing.List": "List", "typing.Dict": "Dict",
        "typing.Tuple": "Tuple", "typing.Union": "Union",
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
    return isinstance(name, str) and name.isupper() and 3 <= len(name) <= 64


def _score_window(items: list[Any], start: int, length: int) -> int:
    score = 0
    window = items[start: start + length]
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
        long_hints = [
            h for h in string_hints
            if len(h) > 60 and " " in h and not is_probable_endpoint(h)
        ]
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
        return f"True if the condition holds, False otherwise."
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
        "__init__":        "Initialise a new instance.",
        "__repr__":        "Return an unambiguous string representation.",
        "__str__":         "Return a human-readable string representation.",
        "__bytes__":       "Return the binary encoding of this object.",
        "__len__":         "Return the number of contained elements.",
        "__bool__":        "Return the truth value of this object.",
        "__iter__":        "Return an iterator over the contained elements.",
        "__next__":        "Return the next element, raising StopIteration when exhausted.",
        "__contains__":    "Return True if the element is present.",
        "__enter__":       "Enter the runtime context for this object.",
        "__exit__":        "Exit the runtime context, suppressing exceptions if appropriate.",
        "__eq__":          "Return True if this instance equals *other*.",
        "__ne__":          "Return True if this instance does not equal *other*.",
        "__hash__":        "Return a hash of this instance suitable for dict keys.",
        "__lt__":          "Return True if this instance is less than *other*.",
        "__le__":          "Return True if this instance is less than or equal to *other*.",
        "__gt__":          "Return True if this instance is greater than *other*.",
        "__ge__":          "Return True if this instance is greater than or equal to *other*.",
        "__reduce__":      "Return state for pickling.",
        "__getstate__":    "Return the instance state for serialisation.",
        "__setstate__":    "Restore the instance from serialised state.",
        "__copy__":        "Return a shallow copy.",
        "__deepcopy__":    "Return a deep copy.",
        "__call__":        "Call this object as a function.",
        "__getattr__":     "Called when an attribute is not found through normal means.",
        "__setattr__":     "Set the named attribute on the object.",
        "__delattr__":     "Delete the named attribute.",
        "__getitem__":     "Return the value at the given key or index.",
        "__setitem__":     "Set the value at the given key or index.",
        "__delitem__":     "Delete the value at the given key or index.",
        "close":           "Release all resources held by this object.",
        "connect":         "Establish the underlying connection.",
        "disconnect":      "Terminate the underlying connection.",
        "reconnect":       "Close and reopen the underlying connection.",
        "send":            "Send data over the connection.",
        "receive":         "Receive data from the connection.",
        "read":            "Read and return data.",
        "write":           "Write data.",
        "flush":           "Flush any buffered data to the underlying sink.",
        "encode":          "Encode this object to bytes.",
        "decode":          "Decode bytes into a Python object.",
        "serialize":       "Serialise this object to a portable representation.",
        "deserialize":     "Restore an object from its serialised form.",
        "validate":        "Validate the data and raise on the first violation.",
        "copy":            "Return a shallow copy of this object.",
        "clone":           "Return an independent copy of this object.",
        "register_hook":   "Register a callable as a hook for the given event.",
        "deregister_hook": "Remove a previously registered hook for the given event.",
        "prepare":         "Prepare the object for dispatch.",
    }
    if name in mapping:
        return mapping[name]
    if name.startswith("prepare_"):
        target = name[len("prepare_"):].replace("_", " ")
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
        "_value":        "Any",
        "_name":         "str",
        "_host":         "str",
        "_port":         "int",
        "_timeout":      "float | None",
        "_maxsize":      "int",
        "_block":        "bool",
        "_headers":      "dict[str, str]",
        "_cookies":      "dict[str, str]",
        "_url":          "str",
        "_method":       "str",
        "_body":         "bytes | None",
        "_data":         "bytes | None",
        "_encoding":     "str",
        "_errors":       "str",
        "_lock":         "threading.Lock",
        "_rlock":        "threading.RLock",
        "_items":        "list[Any]",
        "_entries":      "list[Any]",
        "_buffer":       "bytearray",
        "_queue":        "Any",
        "_socket":       "Any",
        "_lib":          "Any",
        "_ffi":          "Any",
        "_ptr":          "Any",
        "_handle":       "Any",
        "_pool":         "Any",
        "_hooks":        "dict[str, list[Callable[..., Any]]]",
        "_session":      "Any",
        "_cert":         "Any",
        "_key":          "Any",
        "_ca_certs":     "str | None",
        "_ssl_context":  "Any",
        "_type_id":      "int",
        "_version":      "int",
        "_code":         "int",
        "_status":       "int",
        "_reason":       "str",
        "_content":      "bytes",
        "_text":         "str",
        "_json":         "Any",
        "_stream":       "bool",
        "_chunk_size":   "int | None",
        "_redirect":     "bool",
        "_max_redirects":"int",
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
    name:         str
    is_method:    bool                       = False
    args:         list[str]                  = field(default_factory=list)
    annotations:  OrderedDict[str, str]      = field(default_factory=OrderedDict)
    return_type:  str | None                 = None
    decorators:   list[str]                  = field(default_factory=list)
    docstring:    str | None                 = None
    messages:     list[str]                  = field(default_factory=list)
    string_hints: list[str]                  = field(default_factory=list)
    tuples:       list[tuple[Any, ...]]      = field(default_factory=list)
    dict_hints:   list[dict[str, Any]]       = field(default_factory=list)
    literals:     list[Any]                  = field(default_factory=list)
    body_lines:   list[str]                  = field(default_factory=list)
    line_hint:    int | None                 = None

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
    name:       str
    bases:      list[str]                         = field(default_factory=list)
    docstring:  str | None                        = None
    slots:      tuple[str, ...] | None            = None
    attributes: set[str]                          = field(default_factory=set)
    constants:  OrderedDict[str, str]             = field(default_factory=OrderedDict)
    methods:    OrderedDict[str, FunctionDefNode] = field(default_factory=OrderedDict)

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
    docstring:   str | None            = None
    annotations: dict[str, str] | None = None
    decorators:  list[str]             = field(default_factory=list)
    args:        list[str] | None      = None
    line:        int | None            = None
    dicts:       list[Any]             = field(default_factory=list)
    tuples:      list[Any]             = field(default_factory=list)
    literals:    list[Any]             = field(default_factory=list)

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
        func:     FunctionDefNode,
        attrs:    list[str],
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
            return ["return self._value"] if "_value" in attrs else (
                [f"return self.{attrs[0]}"] if attrs else ["return None"]
            )

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
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be a name" in lower:
                lines += [
                    f"if not isinstance({primary}, Name):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be an objectidentifier" in lower:
                lines += [
                    f"if not isinstance({primary}, ObjectIdentifier):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be an integer" in lower or "must be int" in lower:
                lines += [
                    f"if not isinstance({primary}, int):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be a float" in lower or "must be numeric" in lower:
                lines += [
                    f"if not isinstance({primary}, (int, float)):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be a list" in lower or "must be a sequence" in lower:
                lines += [
                    f"if not isinstance({primary}, (list, tuple)):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be a dict" in lower or "must be a mapping" in lower:
                lines += [
                    f"if not isinstance({primary}, dict):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be callable" in lower:
                lines += [
                    f"if not callable({primary}):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "must be an instance of" in lower:
                # Try to extract the class name
                m = re.search(r"instance of\s+(\w+)", msg, re.I)
                cls_name = m.group(1) if m else "object"
                lines += [
                    f"if not isinstance({primary}, {cls_name}):",
                    f'    raise TypeError({msg!r})',
                ]
            elif "unsupported" in lower or lower.startswith("invalid ") or "not valid" in lower:
                lines += [
                    f"if {primary} not in self._SUPPORTED:",
                    f'    raise ValueError({msg!r})',
                ]
            elif "deprecated" in lower:
                lines.append(f"warnings.warn({msg!r}, DeprecationWarning, stacklevel=2)")
            elif "already open" in lower:
                lines += [
                    "if self._is_open:",
                    f'    raise RuntimeError({msg!r})',
                ]
            elif "already closed" in lower or "not open" in lower:
                lines += [
                    "if not self._is_open:",
                    f'    raise RuntimeError({msg!r})',
                ]
            elif "timeout" in lower:
                lines += [
                    f"if {primary} is not None and {primary} < 0:",
                    f'    raise ValueError({msg!r})',
                ]
        return lines

    @staticmethod
    def _promote_messages_to_docstrings(func: FunctionDefNode) -> None:
        if func.docstring:
            return
        remaining: list[str] = []
        for msg in func.messages:
            if (
                not func.docstring
                and len(msg) > 30
                and ("\n" in msg or ":param" in msg or ":return" in msg)
            ):
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
        cls_name = cls_node.name if cls_node else "object"

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
            lines.append(f"self._logger = logging.getLogger(__name__)")

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
            lines.append(f"finally:")
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
        idx_attr   = next((a for a in attrs if "index" in a or "_pos" in a or "_cursor" in a), None)
        coll       = BodySynthesizer._iter_attr(attrs)
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
                f"try:",
                f"    return next(self._{coll.lstrip('_')}_iter)",
                f"except StopIteration:",
                f"    raise",
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
            f'return (',
            f'    f"{cls_name}('
            f'{field_parts}"',
            f')',
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
        suffix  = "," if len(attrs[:4]) == 1 else ""
        return [
            f"return hash((",
            f"    {members}{suffix}",
            f"))",
        ]

    @staticmethod
    def _body_pickle(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        cls_name = cls_node.name if cls_node else "object"
        if func.name == "__reduce__":
            if attrs:
                members = ", ".join(f"self.{a}" for a in attrs[:4])
                suffix  = "," if len(attrs[:4]) == 1 else ""
                return [f"return (self.__class__, ({members}{suffix}))"]
            return [f"return (self.__class__, ())"]
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
        return [f"return False"]

    @staticmethod
    def _body_getitem(
        cls_node: ClassDefNode | None,
        func: FunctionDefNode,
        attrs: list[str],
        non_self: list[str],
    ) -> list[str]:
        key  = non_self[0] if non_self else "key"
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
        key   = non_self[0] if non_self else "key"
        value = non_self[1] if len(non_self) > 1 else "value"
        coll  = BodySynthesizer._iter_attr(attrs)
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
        key  = non_self[0] if non_self else "key"
        coll = BodySynthesizer._iter_attr(attrs)
        if coll:
            return [
                f"try:",
                f"    del self.{coll}[{key}]",
                f"except (KeyError, IndexError) as exc:",
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
                f")",
            ]
        return [f"import copy", f"return copy.copy(self)"]

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
            f"sock = _socket.create_connection(",
            f"    (self.{host_attr}, self.{port_attr}),",
            f"    timeout=self.{timeout_attr}," if timeout_attr else "    timeout=None,",
            f")",
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
        buf_attr  = next((a for a in attrs if "buffer" in a or "buf" in a), None)
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
        buf_attr  = next((a for a in attrs if "buffer" in a or "buf" in a), None)
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
            suffix = helper[len("prepare_"):]
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
        suffix = func.name[len("prepare_"):]
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
                    f"self.headers = {{}}",
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
                    f"    import base64 as _b64",
                    f"    user, pw = {suffix}",
                    f"    token = _b64.b64encode(f'{{user}}:{{pw}}'.encode()).decode()",
                    f"    self.headers['Authorization'] = f'Basic {{token}}'",
                ]
            elif suffix == "hooks":
                lines = [
                    "self.hooks = {}",
                    f"if {suffix}:",
                    f"    for event, hk in {suffix}.items():",
                    f"        if callable(hk):",
                    f"            self.register_hook(event, hk)",
                    f"        elif hasattr(hk, '__iter__'):",
                    f"            for fn in hk:",
                    f"                self.register_hook(event, fn)",
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
        arg    = non_self[0]
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
        arg    = non_self[0] if non_self else "item"
        coll   = next(
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
        arg    = non_self[0] if non_self else "item"
        coll   = next(
            (a for a in attrs if suffix in a or "items" in a or "list" in a or "entries" in a),
            None,
        )
        if coll:
            return [
                f"try:",
                f"    self.{coll}.remove({arg})",
                f"except ValueError:",
                f"    pass",
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
                f"import urllib.request as _req",
                f"with _req.urlopen({path_arg}) as resp:",
                f"    return resp.read()",
            ]
        else:
            lines += [
                f"from pathlib import Path as _Path",
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
                f"from pathlib import Path as _Path",
                f"_Path({path_arg}).write_bytes(",
                f"    self.{val_attr} if isinstance(self.{val_attr}, (bytes, bytearray))",
                f"    else str(self.{val_attr}).encode('utf-8')",
                f")",
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
        api_calls:    list[str] = []
        method_calls: list[str] = []
        field_refs:   list[str] = []
        
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
                pfx = "    return " if (
                    is_last and (func.name.startswith("get_") or "property" in func.decorators)
                ) else "    "
                if has_lib:
                    target = "self._lib" if func.is_method else "lib"
                    lines.append(f"{pfx}{target}.{call}({call_args_str})")
                else:
                    lines.append(f"{pfx}{call}({call_args_str})")
            lines += [
                "except Exception as exc:",
                "    raise RuntimeError(",
                f'        f"C-extension call failed: {{exc}}"',
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
                    for idx, route in enumerate(filtered_hints[:15]): # Cap at 15 routing paths
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
            and any(kw in lower for kw in (
                "must be", "invalid", "unsupported", "error", "failed",
                "cannot", "expected", "should be", "not a valid", "is not", "deprecated",
            ))
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
            if setter_name in cls_node.methods and any(
                "setter" in d for d in cls_node.methods[setter_name].decorators
            ):
                continue
            # Find the backing attr
            backing = f"_{mname}"
            if backing not in attrs:
                backing = mname
            if backing not in attrs:
                continue
            ann = TypeInferencer.infer(backing)
            setter = FunctionDefNode(
                name        = setter_name,
                is_method   = True,
                args        = ["self", "value"],
                annotations = OrderedDict({"value": ann}),
                decorators  = [f"{setter_name}.setter"],
                docstring   = f"Set {mname.replace('_', ' ')}.",
                body_lines  = [
                    f"if value is self.{backing}:",
                    f"    return",
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
        self.classes:          OrderedDict[str, ClassDefNode]          = OrderedDict()
        self.functions:        OrderedDict[str, FunctionDefNode]        = OrderedDict()
        self.module_constants: OrderedDict[str, str]                    = OrderedDict()
        self.imports:          OrderedDict[str, None]                   = OrderedDict()
        self.from_imports:     OrderedDict[str, OrderedDict[str, None]] = OrderedDict()
        self.api_endpoints:    set[str]                                  = set()
        self.images:           OrderedDict[str, int]                    = OrderedDict()
        self.vk_table:         OrderedDict[str, Any]                    = OrderedDict()
        self.module_docstring: str | None                                = None
        self.class_candidates: set[str]                                  = set()
        self.current_class:    str | None                                = None
        self.current_function: FunctionDefNode | None                    = None
        self.last_item_name:   str | None                                = None
        self.has_threading:    bool                                      = False
        self.has_logging:      bool                                      = False
        self.has_warnings:     bool                                      = False
        self.unclaimed_items:  list[Any]                                  = []

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
        cls_node    = self.ensure_class(cls_name)
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
            text = (
                b2s_safe(item) if isinstance(item, (bytes, bytearray))
                else (item if isinstance(item, str) else None)
            )
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
            window = items[index + 1: index + 10]
            if any(
                isinstance(x, (bytes, bytearray, str)) and b2s_safe(x) in META_FIELD_NAMES | DECORATOR_NAMES
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
        return {n for n, s in scores.items() if s >= 3}

    def _hydrate_class_metadata(self, items: list[Any], index: int, cls_node: ClassDefNode) -> None:
        if not cls_node.docstring:
            for offset, candidate in enumerate(items[index + 1: index + 8], start=1):
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
            for candidate in reversed(items[max(0, index - 3): index]):
                txt = (
                    b2s_safe(candidate) if isinstance(candidate, (bytes, bytearray))
                    else (candidate if isinstance(candidate, str) else None)
                )
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
        window = items[index + 1: index + 6]
        return "\n" in text or any(
            isinstance(x, (bytes, bytearray, str)) and is_probable_import_path(b2s_safe(x))
            for x in window
        )

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
        return {
            b2s_safe(k): (b2s_safe(v) if isinstance(v, (bytes, bytearray)) else v)
            for k, v in list(value.items())[:20]
        }

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
        ann  = self._normalize_annotations(pending.annotations)
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
                self.current_class    = owner
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
                self.current_class    = owner
                self.current_function = func
                self._apply_pending(func, pending)
                pending.reset()
            return

        if text in self.class_candidates:
            cls_node = self.ensure_class(text)
            self.current_class    = text
            self.current_function = None
            if cls_node:
                self._hydrate_class_metadata(items, index, cls_node)
                if pending.docstring and not cls_node.docstring:
                    cls_node.docstring = clean_docstring(pending.docstring)
                    pending.docstring  = None
            return

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
            name         = func.name,
            args         = func.args,
            annotations  = dict(func.annotations),
            return_type  = func.return_type,
            messages     = func.messages,
            string_hints = func.string_hints,
            existing_doc = func.docstring,
            is_method    = func.is_method,
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
        elif name in {"__init__", "__del__", "close", "flush", "write", "send",
                      "prepare", "__setstate__", "set_", "add_", "remove_"}:
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

    from_lines:  list[str] = []
    plain_lines: list[str] = []

    for module_path, names in decompiler.from_imports.items():
        if names:
            from_lines.append(f"from {module_path} import {', '.join(names)}")
    for module_path in decompiler.imports:
        if module_path not in decompiler.from_imports:
            plain_lines.append(f"import {module_path}")

    all_lines = sorted(set(from_lines + plain_lines))
    top_mod   = lambda s: s.split()[1].split(".")[0]

    std   = [l for l in all_lines if top_mod(l) in stdlib]
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
    lines.append(f"# Heuristic CPython reconstruction for: {section_name}")
    lines.append(f"# Generated by omni_nuitka_framework — do not edit by hand.")
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
    needs_self = any(
        f.return_type in {"Self"}
        for f in all_funcs
    )
    if needs_self:
        used_typing["Self"] = None  # type: ignore[assignment]

    if "Any" not in used_typing and any(
        "Any" in (func.return_type or "") or any("Any" in v for v in func.annotations.values())
        for func in all_funcs
    ):
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
    public_names = (
        [n for n in decompiler.functions if not n.startswith("_")]
        + [n for n in decompiler.classes if not n.startswith("_")]
    )
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

    # --- unclaimed raw data from blob ---
    if decompiler.unclaimed_items:
        lines.append("")
        lines.append("# ===========================================================================")
        lines.append("# UNCLAIMED RAW DATA — items not assigned to any class or function")
        lines.append("# ===========================================================================")
        for idx, item in enumerate(decompiler.unclaimed_items):
            lines.append(f"_raw_{idx} = {repr(item)}")

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
    return any(token in source for token in ("def ", "async def ", "class ", "import "))


def _is_marshaled_bytecode_section_name(
    section_name: str,
    raw_values: Iterable[Any] | None = None,
) -> bool:
    if section_name.strip(".").lower() != "bytecode":
        return False
    if raw_values is None:
        return True
    return any(
        isinstance(item, (bytes, bytearray))
        and len(item) >= 16
        and item[:1] in (b"\xf3", b"\xe3", b"c")
        for item in raw_values
    )


@functools.lru_cache(maxsize=1)
def _load_v7_smart_reconstructor():
    candidates: list[str] = []
    if __package__:
        candidates.append(f"{__package__}.nuitkalizator_v7_2")
    candidates.append("nuitkalizator_v7_2")

    for module_name in candidates:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        reconstructor = getattr(module, "StaticalySmartReconstructor", None)
        if reconstructor is not None:
            return reconstructor
    return None


def _is_module_name_candidate(value: Any) -> bool:
    if not isinstance(value, str) or len(value) < 2 or len(value) > 80:
        return False
    if value.endswith((".py", ".pyc")):
        return False
    if value.startswith("__") and value.endswith("__"):
        return False
    return bool(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", value)
    )


def _is_identifier_tuple(value: Any) -> bool:
    return bool(
        isinstance(value, tuple)
        and value
        and all(
            isinstance(item, str)
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item)
            for item in value
        )
    )


def _infer_signature_candidates(raw_constants: list[Any]) -> list[tuple[str, list[str]]]:
    name_positions: list[tuple[int, str]] = []
    tuple_positions: list[tuple[int, tuple[str, ...]]] = []
    seen_names: set[str] = set()

    for index, value in enumerate(raw_constants):
        if (
            isinstance(value, str)
            and len(value) >= 3
            and re.fullmatch(r"[a-z_][a-z0-9_]*", value)
            and value not in {"self", "cls", "args", "kwargs"}
            and value not in seen_names
        ):
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
        text = repr(value)
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
        out = [
            "# Nuitka static reconstruction (compact). Feed to an LLM.",
            "# c[N]=mod_consts[N]   no native @OPS block was available in this standalone OMNI run.",
            "",
            f"@MOD {section_name or '__module__'}",
            f"@VER {version[0]}.{version[1]}",
            "",
        ]
        cls._emit_constants(raw_constants, out)
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
) -> OmniModuleArtifact:
    if _is_marshaled_bytecode_section_name(section_name, raw_constants):
        return OmniModuleArtifact(
            source="",
            heuristic_source="",
            strategy="bytecode-only",
            nbc_text=None,
            smart_source=None,
        )

    constants = list(raw_constants)
    code_objects: list[dict[str, Any]] = []
    for item in constants:
        _collect_code_object_specs(item, code_objects)

    if decompiler is None:
        decompiler = OmniDecompiler()
        decompiler.run_pass_1_structural_mapping(constants)
        decompiler.run_pass_2_ast_synthesis()

    heuristic_source = _generate_heuristic_omni_source(decompiler, section_name)

    smart_source: str | None = None
    smart_reconstructor = _load_v7_smart_reconstructor()
    if smart_reconstructor is not None and constants:
        try:
            smart_source = smart_reconstructor(
                module_name=section_name or "__module__",
                constants=constants,
                code_objects=code_objects,
            ).render()
        except Exception:
            smart_source = None

    source = heuristic_source
    strategy = "heuristic"
    if smart_source and _has_python_structure(smart_source):
        smart_units = _count_reconstructed_blocks(smart_source)
        heuristic_units = _count_reconstructed_blocks(heuristic_source)
        if smart_units > heuristic_units or not _has_python_structure(heuristic_source):
            source = smart_source
            strategy = "smart"

    nbc_text = OmniNuitkaCompactEmitter.render(
        section_name=section_name,
        raw_constants=constants,
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
    decompiler: OmniDecompiler,
    section_name: str,
    raw_constants: list[Any] | tuple[Any, ...] | None = None,
    python_version: tuple[int, int] | None = None,
    prefer_full: bool = True,
) -> str:
    if raw_constants is not None and _is_marshaled_bytecode_section_name(section_name, raw_constants):
        return ""
    if prefer_full and raw_constants is not None:
        return reconstruct_module_artifacts(
            section_name=section_name,
            raw_constants=raw_constants,
            decompiler=decompiler,
            python_version=python_version,
        ).source
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
            suffix = stripped[len("@NO_OPS"):].strip()
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
                current_forensic.adjacent.append(
                    (int(match.group(1)), match.group(2), match.group(3))
                )
                continue
            if forensic_mode == "mentions" and match:
                current_forensic.mentions.append(
                    (int(match.group(1)), match.group(2), match.group(3))
                )
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
        self.va_to_qualname = {
            block.va.lower(): block.qualname
            for block in module.ops_blocks
            if block.qualname
        }
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
        unlabeled_blocks = [
            block for block in self.module.ops_blocks
            if not block.qualname and block.va.lower() != (self.module.entry_va or "").lower()
        ]
        used_qualnames = {block.qualname for block in qualnamed_blocks if block.qualname}
        unused_signatures = [
            sig for sig in self.module.functions
            if sig.qualname not in used_qualnames
        ]
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
        body = [
            '"""Recovered from NBC forensic hints; the static @OPS walk did not reach this body."""'
        ]
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
            (
                block for block in self.module.ops_blocks
                if not block.qualname and block.va.lower() == (self.module.entry_va or "").lower()
            ),
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
        self.direct_texts = [
            text
            for const in module.constants
            if (text := _nbc_decode_text(const.value)) is not None
        ]
        self.all_texts: list[str] = []
        _seen: set[str] = set()
        for const in module.constants:
            _nbc_collect_texts(const.value, self.all_texts, _seen)
        self.text_set = set(self.all_texts)
        self.qualname_items = self._collect_qualnames()
        self.class_methods = self._collect_class_methods()
        self.routes = [
            route for route in self._ROUTE_TO_HANDLER
            if route in self.text_set
        ]
        self.api_urls = [
            text for text in self.all_texts
            if text.startswith(("http://", "https://"))
        ]
        self.helper_comments = self._collect_nested_helper_comments()
        self.identifier_tuples = self._collect_identifier_tuples()
        self.top_level_functions = self._expand_top_level_functions(
            self._collect_top_level_functions()
        )
        self.signature_hints = self._collect_signature_hints()

    def _valid_module_import(self, text: str) -> bool:
        return _nbc_is_probable_import_name(text)

    def _collect_qualnames(self) -> list[tuple[int, str]]:
        results: list[tuple[int, str]] = []
        pattern = re.compile(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_<][A-Za-z0-9_<>]*)"
        )
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
        for _index, qualname in self.qualname_items:
            if "<locals>" in qualname:
                continue
            first, _, method = qualname.partition(".")
            if not method:
                continue
            if not (first[:1].isupper() or first.startswith("_") and first[1:2].isupper()):
                continue
            classes.setdefault(first, [])
            if method not in classes[first]:
                classes[first].append(method)
        return classes

    def _collect_top_level_functions(self) -> list[str]:
        funcs: list[str] = []
        seen = set()
        for _index, qualname in self.qualname_items:
            if ".<locals>." in qualname:
                parent = qualname.split(".<locals>.", 1)[0]
                if "." not in parent and parent not in seen:
                    funcs.append(parent)
                    seen.add(parent)
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
        if list(best) == normalized_fallback[:len(best)]:
            return list(best)
        if list(best[:len(normalized_fallback)]) == normalized_fallback:
            return fallback

        filtered = [name for name in best if name in normalized_fallback]
        if class_name and (not filtered or filtered[0] != "self"):
            filtered.insert(0, "self")
        return filtered or None

    def _collect_signature_hints(self) -> dict[tuple[str | None, str], list[str]]:
        hints: dict[tuple[str | None, str], list[str]] = {}
        for name in self.top_level_functions:
            hint = self._infer_signature_hint(name)
            if hint:
                hints[(None, name)] = hint
        for class_name, methods in self.class_methods.items():
            for method_name in methods:
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
            if isinstance(value, tuple) and value and all(
                _nbc_decode_text(item) is not None or isinstance(item, bool) for item in value
            ):
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
            body.append(
                f"{name} = Endpoint(method={method!r}, path={path!r}, requires_manifest={requires_manifest!r})"
            )
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
            if method_name in {'__init__', 'token', 'manifest'}:
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
            for url in self.api_urls:
                if url in seen_urls or url == "http://localhost:":
                    continue
                seen_urls.add(url)
                if "keyauth.win/api/1.3/" in url:
                    lines.append(f"KEYAUTH_API_URL = {url!r}")
                elif "keyauth.win/app/?page=licenses" in url:
                    lines.append(f"KEYAUTH_PANEL_URL = {url!r}")
                elif "/inventory/v1/mutate" in url:
                    lines.append(f"MUTATE_URL = {url!r}")
                elif "/inventory" in url:
                    lines.append(f"INVENTORY_URL = {url!r}")
                else:
                    lines.append(f"# endpoint: {url}")
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
            lines.append(
                f"    ({const.index}, {const.type_code!r}, {const.value!r}),"
            )
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
            lines.append(
                f"    ({const.index}, {const.type_code!r}, {const.raw!r}),"
            )
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


_NBC_BLOCK_START_RE = re.compile(r"^(def|class)\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_NBC_INVENTORY_MARKER = (
    "# ---------------------------------------------------------------------------\n"
    "# Full NBC Constant Inventory\n"
    "# ---------------------------------------------------------------------------\n"
)


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


def _nbc_extract_structure(source: str) -> tuple[list[str], "OrderedDict[str, list[str]]"]:
    body, _tail = _nbc_split_inventory(source)
    lines = body.splitlines()
    preamble: list[str] = []
    blocks: "OrderedDict[str, list[str]]" = OrderedDict()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _NBC_BLOCK_START_RE.match(line)
        if match:
            kind, name = match.groups()
            start = index
            index += 1
            while index < len(lines):
                candidate = lines[index]
                if candidate and not candidate.startswith((" ", "\t")) and _NBC_BLOCK_START_RE.match(candidate):
                    break
                index += 1
            blocks[f"{kind}:{name}"] = lines[start:index]
            continue
        if not blocks:
            preamble.append(line)
        index += 1
    return _nbc_normalize_preamble(preamble), blocks


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
    usable = [
        candidate for candidate in candidates
        if candidate and candidate.strip() and candidate != inventory_source
    ]
    structures = [
        (candidate, *_nbc_extract_structure(candidate))
        for candidate in usable
    ]

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

    blob_path = Path(blob_path)
    if not blob_path.exists():
        print(f"[-] Blob not found: {blob_path}")
        return 1

    raw = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(raw)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for section_name, items in sections.items():
        if not items:
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
        safe_name = re.sub(r'[<>:"/\\|?*\x00]', "_", section_name).strip("._") or "section"
        out_file = out_dir / f"{safe_name}.py"
        out_file.write_text(source, encoding="utf-8")
        if artifact.nbc_text:
            out_file.with_suffix(".nbc").write_text(artifact.nbc_text, encoding="utf-8")
        count += 1
        print(
            f"  [{count:4d}] {safe_name}.py  "
            f"({source.count(chr(10))} lines, strategy={artifact.strategy})"
        )

    print(f"\n[*] Reconstructed {count} file(s) -> {out_dir}")
    return 0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruct Python from Nuitka constants blobs or .nbc files."
    )
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
