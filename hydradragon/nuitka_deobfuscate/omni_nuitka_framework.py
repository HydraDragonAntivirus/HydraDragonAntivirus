"""
omni_nuitka_framework.py

High-fidelity heuristic CPython source reconstruction from Nuitka section metadata.
Targets 3 000+ line output per blob via rich body synthesis, docstring recovery,
property-setter generation, context-manager / iterator recovery, and full
exception-hierarchy reconstruction.
"""

from __future__ import annotations

import functools
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


def generate_omni_source(decompiler: OmniDecompiler, section_name: str) -> str:
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
    out_dir  = Path("restore_deep_ultra") / "reconstructed_source_v13_omni"
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
        print(f"  [{count:4d}] {safe_name}.py  ({source.count(chr(10))} lines)")

    print(f"\n[*] Reconstructed {count} file(s) -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
