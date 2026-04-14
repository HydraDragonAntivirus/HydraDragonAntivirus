"""
omni_nuitka_framework.py

Heuristic CPython source reconstruction from Nuitka section metadata.
The goal here is not pyc decompilation. This module stays on the
metadata/CPython-structure side and tries to rebuild readable class and
function source directly from Nuitka blob sections.
"""

from __future__ import annotations

import keyword
import re
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


class NuitkaTags:
    ARG = 'a'
    USER_DEF = 'u'
    PRIVATE_DEF = 'p'
    OBJECT_TYPE = 'O'


def b2s_safe(val):
    if val is None:
        return "None"
    if isinstance(val, str):
        return val
    if isinstance(val, (int, float, bool)):
        return str(val)
    if isinstance(val, (tuple, list, dict, set, frozenset)):
        return str(val)
    if hasattr(val, 'decode'):
        try:
            return val.decode('utf-8')
        except Exception:
            return val.decode('latin-1', errors='replace')
    return repr(val)


def is_b64_image(val):
    s = b2s_safe(val) if isinstance(val, (bytes, bytearray)) else str(val)
    return 'iVBORw0KGgo' in s or 'JFIF' in s


def is_annotation_dict(d):
    if not isinstance(d, dict) or not d or len(d) > 25:
        return False
    for key in d.keys():
        text = b2s_safe(key)
        if not text.isidentifier() and text != 'return':
            return False
    return True


def decode_annotation_blob(d):
    annotations = OrderedDict()
    if not isinstance(d, dict):
        return annotations
    for key, value in d.items():
        name = b2s_safe(key)
        if value is None:
            annotations[name] = 'Any'
        elif value is True or value is False:
            annotations[name] = 'bool'
        elif isinstance(value, int):
            annotations[name] = 'int'
        elif isinstance(value, float):
            annotations[name] = 'float'
        elif isinstance(value, str):
            annotations[name] = value if value[:1].isupper() else 'str'
        elif isinstance(value, (bytes, bytearray)):
            text = b2s_safe(value)
            annotations[name] = text if text[:1].isupper() else 'str'
        else:
            annotations[name] = type(value).__name__
    return annotations


def parse_nuitka_packed_signature(raw_bytes):
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode('utf-8', errors='replace')

    method_refs = []
    args = []
    types = {}
    for segment in raw_bytes.split(b'\x00'):
        if not segment:
            continue
        text = segment.decode('utf-8', errors='replace')
        if not text:
            continue
        tag = text[0]
        name = text[1:]
        if tag == NuitkaTags.ARG:
            args.append(name)
        elif tag == NuitkaTags.USER_DEF:
            if '.' in name and name.split('.', 1)[0].isidentifier():
                method_refs.append(name)
        elif tag == NuitkaTags.OBJECT_TYPE:
            if args:
                types[args[-1]] = name
        elif tag == NuitkaTags.PRIVATE_DEF:
            if '.' in name and name.split('.', 1)[0]:
                method_refs.append(name)
    return method_refs, args, types


IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLASS_NAME_RE = re.compile(r"^_?[A-Z][A-Za-z0-9_]*$")
IMPORT_PATH_RE = re.compile(r"^[a-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")
METHOD_REF_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$")

DECORATOR_NAMES = {'property', 'abstractmethod', 'staticmethod', 'classmethod'}
META_FIELD_NAMES = {
    '__prepare__', '__qualname__', '__firstlineno__', '__static_attributes__',
    '__orig_bases__', '__getitem__', 'metaclass', 'annotations', 'origin',
    'has_location', '__module__'
}
KNOWN_METHOD_NAMES = {
    '__init__', '__new__', '__repr__', '__eq__', '__hash__', '__reduce__',
    '__iter__', '__len__', '__bool__', 'prepare', 'copy', 'close', 'json',
    'value', 'type_id', '_packed', '_init_without_validation',
}
KNOWN_METHOD_PREFIXES = (
    'prepare_', 'register_', 'deregister_', 'iter_', 'get_', 'set_',
    'raise_', 'encode_', 'decode_', '_encode_', '_get_', '_init_',
)
KNOWN_BASE_NAMES = {
    'Exception', 'Warning', 'ValueError', 'TypeError', 'RuntimeError',
    'ConnectionError', 'LookupError', 'MessageDefect', 'IncompleteRead',
}


def clean_docstring(text):
    text = str(text).strip()
    if not text:
        return None
    return text.replace('\r\n', '\n').replace('\r', '\n')


def safe_identifier(name):
    if name is None:
        return None
    text = str(name).strip().replace('-', '_').replace(' ', '_')
    text = re.sub(r'[^0-9A-Za-z_]', '_', text)
    if not text:
        return None
    if text[0].isdigit():
        text = '_' + text
    if keyword.iskeyword(text):
        text += '_'
    if not IDENTIFIER_RE.fullmatch(text):
        return None
    return text


def normalize_annotation_text(value):
    text = b2s_safe(value).strip()
    if not text:
        return None
    replacements = {
        'typing.Any': 'Any',
        'typing.Callable': 'Callable',
        'typing.Mapping': 'Mapping',
        'typing.Iterable': 'Iterable',
        'typing.Sequence': 'Sequence',
    }
    return replacements.get(text, text)


def is_probable_docstring(text):
    if not isinstance(text, str):
        return False
    text = text.strip()
    if len(text) < 12 or ' ' not in text:
        return False
    if IMPORT_PATH_RE.fullmatch(text) or METHOD_REF_RE.fullmatch(text):
        return False
    return True


def is_probable_import_path(text):
    return isinstance(text, str) and IMPORT_PATH_RE.fullmatch(text) and text.lower() == text


def is_probable_class_name(text):
    return isinstance(text, str) and CLASS_NAME_RE.fullmatch(text) and text not in DECORATOR_NAMES


def is_probable_method_name(text):
    if not isinstance(text, str):
        return False
    if text in DECORATOR_NAMES or text in META_FIELD_NAMES:
        return False
    if text in KNOWN_METHOD_NAMES:
        return True
    if text.startswith(KNOWN_METHOD_PREFIXES):
        return True
    if text.startswith('__') and text.endswith('__') and len(text) > 4:
        return True
    return bool(IDENTIFIER_RE.fullmatch(text) and text[:1].islower())


def tuple_texts(value):
    if not isinstance(value, (tuple, list)):
        return ()
    result = []
    for item in value:
        if isinstance(item, (bytes, bytearray, str)):
            result.append(b2s_safe(item))
        else:
            result.append(item)
    return tuple(result)


def literal_source(value):
    if isinstance(value, bytes):
        return repr(b2s_safe(value))
    if isinstance(value, tuple):
        return repr(tuple(tuple_texts(value)))
    if isinstance(value, list):
        return repr(list(tuple_texts(value)))
    if isinstance(value, dict):
        cleaned = OrderedDict()
        for key, item in list(value.items())[:20]:
            cleaned[b2s_safe(key)] = b2s_safe(item) if isinstance(item, (bytes, bytearray)) else item
        return repr(dict(cleaned))
    return repr(value)


def should_render_constant(name):
    return isinstance(name, str) and name.isupper() and 3 <= len(name) <= 64


@dataclass
class FunctionDefNode:
    name: str
    is_method: bool = False
    args: list[str] = field(default_factory=list)
    annotations: OrderedDict = field(default_factory=OrderedDict)
    return_type: str | None = None
    decorators: list[str] = field(default_factory=list)
    docstring: str | None = None
    messages: list[str] = field(default_factory=list)
    string_hints: list[str] = field(default_factory=list)
    tuples: list[tuple] = field(default_factory=list)
    dict_hints: list[dict] = field(default_factory=list)
    literals: list[object] = field(default_factory=list)
    body_lines: list[str] = field(default_factory=list)
    line_hint: int | None = None

    def render(self, indent=0):
        pad = " " * (indent * 4)
        out = []
        for decorator in self.decorators:
            out.append(f"{pad}@{decorator}")

        args = self.args[:] or (['self'] if self.is_method else [])
        if 'classmethod' in self.decorators and args and args[0] == 'self':
            args[0] = 'cls'
        if 'property' in self.decorators:
            args = ['self']

        signature = []
        for arg in args:
            annotation = self.annotations.get(arg)
            signature.append(f"{arg}: {annotation}" if annotation else arg)

        ret = f" -> {self.return_type}" if self.return_type else ""
        out.append(f"{pad}def {self.name}({', '.join(signature)}){ret}:")

        body = []
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
            body = ['pass']

        body_pad = " " * ((indent + 1) * 4)
        for line in body:
            if line:
                out.append(f"{body_pad}{line}")
            else:
                out.append("")
        return "\n".join(out) + "\n"


@dataclass
class ClassDefNode:
    name: str
    bases: list[str] = field(default_factory=list)
    docstring: str | None = None
    slots: tuple | None = None
    attributes: set = field(default_factory=set)
    constants: OrderedDict = field(default_factory=OrderedDict)
    methods: OrderedDict = field(default_factory=OrderedDict)

    def render(self, indent=0):
        pad = " " * (indent * 4)
        header = f"{pad}class {self.name}"
        if self.bases:
            header += f"({', '.join(self.bases)})"
        header += ":"
        out = [header]

        body_lines = []
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
            body_lines.append(f"__slots__ = {repr(tuple(self.slots))}")
        for name, value in self.constants.items():
            body_lines.append(f"{name} = {value}")
        if self.attributes:
            body_lines.append("# Recovered instance attributes")
            for attr in sorted(self.attributes):
                body_lines.append(f"# self.{attr}")
        for method in self.methods.values():
            if body_lines:
                body_lines.append("")
            body_lines.extend(method.render(indent + 1).rstrip().splitlines())
        if not body_lines:
            body_lines = ['pass']

        body_pad = " " * ((indent + 1) * 4)
        for line in body_lines:
            if line:
                if line.startswith(body_pad):
                    out.append(line)
                else:
                    out.append(f"{body_pad}{line}")
            else:
                out.append("")
        return "\n".join(out) + "\n"


class OmniDecompiler:
    def __init__(self):
        self.classes = OrderedDict()
        self.functions = OrderedDict()
        self.module_constants = OrderedDict()
        self.imports = OrderedDict()
        self.from_imports = OrderedDict()
        self.api_endpoints = set()
        self.images = OrderedDict()
        self.vk_table = OrderedDict()
        self.module_docstring = None
        self.class_candidates = set()
        self.current_class = None
        self.current_function = None
        self.last_item_name = None

    def ensure_class(self, cls_name):
        cls_name = safe_identifier(cls_name)
        if not cls_name:
            return None
        if cls_name not in self.classes:
            self.classes[cls_name] = ClassDefNode(cls_name)
        return self.classes[cls_name]

    def ensure_function(self, func_name):
        func_name = safe_identifier(func_name)
        if not func_name:
            return None
        if func_name not in self.functions:
            self.functions[func_name] = FunctionDefNode(func_name, is_method=False)
        return self.functions[func_name]

    def ensure_method(self, cls_name, method_name):
        cls_node = self.ensure_class(cls_name)
        method_name = safe_identifier(method_name)
        if cls_node is None or not method_name:
            return None
        if method_name not in cls_node.methods:
            cls_node.methods[method_name] = FunctionDefNode(method_name, is_method=True, args=['self'])
        return cls_node.methods[method_name]

    def record_import(self, module_path, names=None):
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

    def _trim_dict(self, value):
        cleaned = OrderedDict()
        for key, item in list(value.items())[:20]:
            cleaned[b2s_safe(key)] = b2s_safe(item) if isinstance(item, (bytes, bytearray)) else item
        return cleaned

    def _collect_class_candidates(self, items):
        scores = defaultdict(int)
        for index, item in enumerate(items):
            text = b2s_safe(item) if isinstance(item, (bytes, bytearray)) else item if isinstance(item, str) else None
            if not isinstance(text, str):
                continue
            match = METHOD_REF_RE.fullmatch(text)
            if match:
                scores[match.group(1)] += 5
                continue
            if not is_probable_class_name(text):
                continue
            window = items[index + 1:index + 10]
            score = 0
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
            if any(isinstance(x, dict) and is_annotation_dict(x) for x in window):
                score += 1
            if any(isinstance(x, int) and 0 < x < 10000 for x in window):
                score += 1
            if score >= 3:
                scores[text] += score
        return {name for name, score in scores.items() if score >= 3}

    def _normalize_args(self, values, method=False):
        args = []
        for value in values or ():
            ident = safe_identifier(value)
            if ident and ident not in {'return', 'None'}:
                args.append(ident)
        if method:
            if not args or args[0] != 'self':
                args = ['self'] + [arg for arg in args if arg != 'self']
        return args

    def _normalize_annotations(self, annotation_dict):
        annotations = OrderedDict()
        for key, value in (annotation_dict or {}).items():
            ident = safe_identifier(key)
            if ident:
                text = normalize_annotation_text(value)
                if text:
                    annotations[ident] = text
        return annotations

    def _apply_pending(self, func, *, args=None, annotations=None, docstring=None, decorators=None, line_hint=None):
        if func is None:
            return
        ann = self._normalize_annotations(annotations)
        explicit_args = self._normalize_args(args, method=func.is_method)
        if not explicit_args and ann:
            explicit_args = self._normalize_args([name for name in ann if name != 'return'], method=func.is_method)
        if explicit_args:
            func.args = explicit_args
        if ann:
            func.annotations.update({k: v for k, v in ann.items() if k != 'return'})
            if ann.get('return'):
                func.return_type = ann['return']
        for decorator in decorators or ():
            if decorator not in func.decorators:
                func.decorators.append(decorator)
        if docstring and not func.docstring:
            func.docstring = clean_docstring(docstring)
        if line_hint and not func.line_hint:
            func.line_hint = line_hint

    def _record_target_hint(self, target, kind, value):
        if target is None:
            return
        if kind == 'dict':
            target.dict_hints.append(self._trim_dict(value))
        elif kind == 'tuple':
            target.tuples.append(tuple_texts(value))
        elif kind == 'literal':
            target.literals.append(value)
        elif kind == 'message':
            text = clean_docstring(value)
            if text and text not in target.messages:
                target.messages.append(text)
        elif kind == 'string':
            text = b2s_safe(value)
            if text and text not in target.string_hints:
                target.string_hints.append(text)

    def _looks_like_method_block(self, items, index, text):
        if not is_probable_method_name(text):
            return False
        window = items[index + 1:index + 5]
        if any(isinstance(x, dict) and is_annotation_dict(x) for x in window):
            return True
        if any(isinstance(x, tuple) and len(x) <= 12 for x in window):
            return True
        if any(isinstance(x, str) and is_probable_docstring(x) for x in window):
            return True
        if text in KNOWN_METHOD_NAMES or text.startswith(KNOWN_METHOD_PREFIXES):
            return True
        return False

    def _hydrate_class_metadata(self, items, index, cls_node):
        if cls_node is None:
            return
        if not cls_node.docstring:
            for candidate in items[index + 1:index + 8]:
                if isinstance(candidate, str) and is_probable_docstring(candidate):
                    cls_node.docstring = clean_docstring(candidate)
                    break
        if not cls_node.bases:
            for candidate in reversed(items[max(0, index - 3):index]):
                text = b2s_safe(candidate) if isinstance(candidate, (bytes, bytearray)) else candidate if isinstance(candidate, str) else None
                if not isinstance(text, str):
                    continue
                if text in {'ABCMeta', 'Callable', 'Mapping'}:
                    continue
                if text in KNOWN_BASE_NAMES or (is_probable_class_name(text) and text not in self.class_candidates and text != cls_node.name):
                    cls_node.bases.append(text)
                    break

    def run_pass_1_structural_mapping(self, blob_items):
        items = list(blob_items)
        self.class_candidates = self._collect_class_candidates(items)

        pending_docstring = None
        pending_annotations = None
        pending_decorators = []
        pending_args = None
        pending_line = None

        for index, item in enumerate(items):
            if item is None:
                continue

            if isinstance(item, (bytes, bytearray)):
                text = b2s_safe(item)
                item_type = 'packed' if b'\x00' in item and len(item) > 4 else 'bytes'
            elif isinstance(item, str):
                text = item
                item_type = 'str'
            elif isinstance(item, dict):
                text = None
                item_type = 'dict'
            elif isinstance(item, tuple):
                text = None
                item_type = 'tuple'
            elif isinstance(item, list):
                text = None
                item_type = 'list'
            elif isinstance(item, (int, float, bool)):
                text = None
                item_type = 'literal'
            else:
                text = None
                item_type = 'other'

            if item_type == 'bytes' and text.endswith('_B64') and index + 1 < len(items):
                nxt = items[index + 1]
                if isinstance(nxt, (bytes, bytearray, str)) and is_b64_image(nxt):
                    self.images[text] = len(b2s_safe(nxt))
                    continue

            if item_type == 'bytes' and text.startswith('VK_') and index + 1 < len(items) and isinstance(items[index + 1], int):
                self.vk_table[text] = items[index + 1]
                continue

            if item_type == 'packed':
                refs, args, hints = parse_nuitka_packed_signature(item)
                if refs:
                    for ref in refs:
                        match = METHOD_REF_RE.fullmatch(ref)
                        if not match:
                            continue
                        func = self.ensure_method(match.group(1), match.group(2))
                        self.current_class = match.group(1)
                        self.current_function = func
                        self._apply_pending(
                            func,
                            args=args,
                            annotations=hints,
                            docstring=pending_docstring,
                            decorators=pending_decorators,
                            line_hint=pending_line,
                        )
                        pending_docstring = None
                        pending_annotations = None
                        pending_decorators = []
                        pending_args = None
                        pending_line = None
                elif args:
                    pending_args = args
                    if hints:
                        pending_annotations = hints
                continue

            if item_type == 'dict':
                if is_annotation_dict(item):
                    pending_annotations = decode_annotation_blob(item)
                else:
                    self._record_target_hint(self.current_function, 'dict', item)
                continue

            if item_type == 'tuple':
                decoded = tuple_texts(item)
                if self.last_item_name == '__slots__' and self.current_class:
                    cls_node = self.classes.get(self.current_class)
                    if cls_node:
                        cls_node.slots = tuple(x for x in decoded if isinstance(x, str) and safe_identifier(x))
                elif all(isinstance(x, str) and safe_identifier(x) for x in decoded) and 0 < len(decoded) <= 12:
                    pending_args = decoded
                self._record_target_hint(self.current_function, 'tuple', item)
                continue

            if item_type == 'literal':
                if isinstance(item, int) and 0 < item < 10000:
                    pending_line = item
                self._record_target_hint(self.current_function, 'literal', item)
                continue

            if not isinstance(text, str) or not text:
                continue

            self.last_item_name = text

            if 'http' in text.lower() or '/functions/' in text:
                self.api_endpoints.add(text)

            if text in DECORATOR_NAMES:
                pending_decorators.append(text)
                continue

            method_ref = METHOD_REF_RE.fullmatch(text)
            if method_ref:
                func = self.ensure_method(method_ref.group(1), method_ref.group(2))
                self.current_class = method_ref.group(1)
                self.current_function = func
                self._apply_pending(
                    func,
                    args=pending_args,
                    annotations=pending_annotations,
                    docstring=pending_docstring,
                    decorators=pending_decorators,
                    line_hint=pending_line,
                )
                pending_docstring = None
                pending_annotations = None
                pending_decorators = []
                pending_args = None
                pending_line = None
                continue

            if text in self.class_candidates:
                cls_node = self.ensure_class(text)
                self.current_class = text
                self.current_function = None
                self._hydrate_class_metadata(items, index, cls_node)
                if pending_docstring and cls_node and not cls_node.docstring:
                    cls_node.docstring = clean_docstring(pending_docstring)
                    pending_docstring = None
                continue

            if is_probable_import_path(text):
                names = None
                if index + 1 < len(items) and isinstance(items[index + 1], tuple):
                    names = [name for name in tuple_texts(items[index + 1]) if isinstance(name, str) and safe_identifier(name)]
                self.record_import(text, names)
                continue

            if should_render_constant(text) and index + 1 < len(items):
                nxt = items[index + 1]
                if isinstance(nxt, (str, bytes, bytearray, int, float, bool, tuple, list, dict)):
                    self.module_constants[text] = literal_source(nxt)
                continue

            if self.current_class and text.startswith('_') and not text.startswith('__') and len(text) > 1:
                cls_node = self.classes.get(self.current_class)
                if cls_node:
                    cls_node.attributes.add(text)

            if self.current_class and self._looks_like_method_block(items, index, text):
                func = self.ensure_method(self.current_class, text)
                self.current_function = func
                self._apply_pending(
                    func,
                    args=pending_args,
                    annotations=pending_annotations,
                    docstring=pending_docstring,
                    decorators=pending_decorators,
                    line_hint=pending_line,
                )
                pending_docstring = None
                pending_annotations = None
                pending_decorators = []
                pending_args = None
                pending_line = None
                continue

            if not self.current_class and is_probable_method_name(text):
                window = items[index + 1:index + 4]
                if any(isinstance(x, (tuple, dict)) for x in window) or any(isinstance(x, str) and is_probable_docstring(x) for x in window):
                    func = self.ensure_function(text)
                    self.current_function = func
                    self._apply_pending(
                        func,
                        args=pending_args,
                        annotations=pending_annotations,
                        docstring=pending_docstring,
                        decorators=pending_decorators,
                        line_hint=pending_line,
                    )
                    pending_docstring = None
                    pending_annotations = None
                    pending_decorators = []
                    pending_args = None
                    pending_line = None
                    continue

            if is_probable_docstring(text):
                if not self.module_docstring and index < 8:
                    self.module_docstring = clean_docstring(text)
                elif self.current_function:
                    self._record_target_hint(self.current_function, 'message', text)
                else:
                    pending_docstring = text
                continue

            if self.current_function and text not in DECORATOR_NAMES:
                self._record_target_hint(self.current_function, 'string', text)

    def _candidate_attributes(self, cls_node, func):
        attrs = []
        if cls_node.slots:
            attrs.extend([attr for attr in cls_node.slots if isinstance(attr, str)])
        attrs.extend(sorted(cls_node.attributes))
        for tuple_hint in func.tuples:
            for item in tuple_hint:
                if isinstance(item, str) and item.startswith('_') and item not in attrs:
                    attrs.append(item)
        return attrs

    def _validation_lines(self, func):
        lines = []
        args = [arg for arg in func.args if arg not in {'self', 'cls'}]
        primary = args[0] if args else 'value'
        for message in func.messages[:3]:
            lower = message.lower()
            if 'must be string' in lower:
                lines.extend([
                    f"if not isinstance({primary}, str):",
                    f"    raise TypeError({message!r})",
                ])
            elif 'must be a name' in lower:
                lines.extend([
                    f"if not isinstance({primary}, Name):",
                    f"    raise TypeError({message!r})",
                ])
            elif 'must be an objectidentifier' in lower:
                lines.extend([
                    f"if not isinstance({primary}, ObjectIdentifier):",
                    f"    raise TypeError({message!r})",
                ])
            elif 'unsupported' in lower or lower.startswith('invalid '):
                lines.append(f"raise ValueError({message!r})")
                break
            elif 'must be an instance of' in lower:
                lines.append(f"# Validation hint: {message}")
        return lines

    def _build_prepare_body(self, cls_node, func):
        lines = []
        helper_methods = [name for name in cls_node.methods if name.startswith('prepare_')]
        if func.name == 'prepare' and helper_methods:
            arg_set = set(func.args)
            for helper in helper_methods:
                suffix = helper[len('prepare_'):]
                call_args = []
                if suffix in arg_set:
                    call_args.append(suffix)
                elif suffix == 'body':
                    for candidate in ('data', 'files', 'json', 'params'):
                        if candidate in arg_set:
                            call_args.append(candidate)
                elif suffix == 'auth' and 'auth' in arg_set:
                    call_args.append('auth')
                elif suffix == 'hooks' and 'hooks' in arg_set:
                    call_args.append('hooks')
                lines.append(f"self.{helper}({', '.join(call_args)})")
            return lines

        if func.name.startswith('prepare_'):
            suffix = func.name[len('prepare_'):]
            args = [arg for arg in func.args if arg not in {'self', 'cls'}]
            if suffix in args:
                lines.append(f"self.{suffix} = {suffix}")
            elif suffix == 'headers' and 'headers' in args:
                lines.append("self.headers = headers or {}")
            elif suffix == 'url' and 'url' in args:
                lines.append("self.url = url")
            elif suffix == 'method' and 'method' in args:
                lines.append("self.method = method.upper()")
            elif suffix == 'cookies' and 'cookies' in args:
                lines.append("self._cookies = cookies")
            elif suffix == 'body':
                if 'data' in args:
                    lines.append("self.body = data")
                if 'json' in args:
                    lines.append("self.json = json")
            elif suffix == 'hooks' and 'hooks' in args:
                lines.append("self.hooks = hooks")
        return lines

    def _build_body(self, cls_node, func):
        attrs = self._candidate_attributes(cls_node, func)
        lines = []

        if 'abstractmethod' in func.decorators:
            return ['raise NotImplementedError']

        if func.name in {'__init__', '_init_without_validation'}:
            arg_names = [arg for arg in func.args if arg not in {'self', 'cls'}]
            used = set()
            for arg in arg_names:
                preferred = None
                if f"_{arg}" in attrs:
                    preferred = f"_{arg}"
                elif arg in attrs:
                    preferred = arg
                elif len(arg_names) == 1 and '_value' in attrs:
                    preferred = '_value'
                else:
                    for candidate in attrs:
                        if candidate not in used and candidate.lstrip('_') == arg:
                            preferred = candidate
                            break
                if preferred:
                    used.add(preferred)
                    lines.append(f"self.{preferred} = {arg}")
            lines.extend(self._validation_lines(func))
            return lines

        if func.name == 'value' and 'property' in func.decorators:
            if '_value' in attrs:
                return ["return self._value"]
            if attrs:
                return [f"return self.{attrs[0]}"]

        if func.name == 'type_id' and 'property' in func.decorators and '_type_id' in attrs:
            return ["return self._type_id"]

        if func.name == '_packed' and '_value' in attrs:
            return ["return self._value.packed"]

        if func.name.startswith('get') and len(func.name) > 3:
            candidate = func.name[3:4].lower() + func.name[4:]
            for attr in attrs:
                if attr.lstrip('_') == candidate:
                    return [f"return self.{attr}"]

        if func.name == '__repr__':
            if attrs:
                pieces = ", ".join([f"{attr.lstrip('_')}={{self.{attr}!r}}" for attr in attrs[:4]])
                return [f'return f"<{cls_node.name}({pieces})>"']
            return [f'return f"<{cls_node.name}>"']

        if func.name == '__eq__' and attrs:
            left = ", ".join([f"self.{attr}" for attr in attrs[:4]])
            right = ", ".join([f"other.{attr}" for attr in attrs[:4]])
            if len(attrs[:4]) == 1:
                return [
                    f"if not isinstance(other, {cls_node.name}):",
                    "    return NotImplemented",
                    f"return ({left},) == ({right},)",
                ]
            return [
                f"if not isinstance(other, {cls_node.name}):",
                "    return NotImplemented",
                f"return ({left}) == ({right})",
            ]

        if func.name == '__hash__' and attrs:
            members = ", ".join([f"self.{attr}" for attr in attrs[:4]])
            if len(attrs[:4]) == 1:
                return [f"return hash(({members},))"]
            return [f"return hash(({members}))"]

        if func.name == '__reduce__' and attrs:
            members = ", ".join([f"self.{attr}" for attr in attrs[:4]])
            tuple_expr = f"({members},)" if len(attrs[:4]) == 1 else f"({members})"
            return [f"return (self.__class__, {tuple_expr})"]

        if func.name == 'register_hook':
            return [
                "self.hooks.setdefault(event, []).append(hook)",
                "return hook",
            ]

        if func.name == 'deregister_hook':
            return [
                "hooks = self.hooks.get(event, [])",
                "if hook in hooks:",
                "    hooks.remove(hook)",
                "    return True",
                "return False",
            ]

        prepare_lines = self._build_prepare_body(cls_node, func)
        if prepare_lines:
            return prepare_lines

        validation = self._validation_lines(func)
        if validation:
            return validation

        if func.dict_hints:
            lines.append(f"config = {literal_source(func.dict_hints[0])}")
        elif func.tuples:
            lines.append(f"state = {literal_source(func.tuples[0])}")

        for text in func.string_hints[:5]:
            if is_probable_docstring(text):
                continue
            if 'http' in text.lower():
                lines.append(f"# External reference: {text}")
            elif len(text) > 20 and ' ' in text:
                lines.append(f"# {text}")
        return lines

    def run_pass_2_ast_synthesis(self):
        for cls_name, cls_node in self.classes.items():
            if cls_name.endswith('Warning') and not cls_node.bases:
                cls_node.bases = ['Warning']
            elif cls_name.endswith('Error') and not cls_node.bases:
                cls_node.bases = ['Exception']
            for func in cls_node.methods.values():
                func.body_lines = self._build_body(cls_node, func)

        for func in self.functions.values():
            if not func.body_lines:
                func.body_lines = self._validation_lines(func)
            if not func.body_lines and func.dict_hints:
                func.body_lines = [f"config = {literal_source(func.dict_hints[0])}"]


def generate_omni_source(decompiler, section_name):
    lines = []

    if decompiler.module_docstring:
        doc = clean_docstring(decompiler.module_docstring) or ""
        doc_lines = doc.splitlines()
        if len(doc_lines) <= 1:
            lines.append(f'"""{doc}"""')
        else:
            lines.append('"""')
            lines.extend(doc_lines)
            lines.append('"""')

    lines.append('from __future__ import annotations')
    lines.append('')
    lines.append(f"# Heuristic CPython reconstruction for: {section_name}")

    typing_names = OrderedDict()
    all_functions = list(decompiler.functions.values())
    for cls_node in decompiler.classes.values():
        all_functions.extend(cls_node.methods.values())
    for func in all_functions:
        for annotation in list(func.annotations.values()) + ([func.return_type] if func.return_type else []):
            if not annotation:
                continue
            for token in re.findall(r'\b[A-Z][A-Za-z0-9_]*\b', annotation):
                if token in {'Any', 'Callable', 'Mapping', 'Iterable', 'Sequence'}:
                    typing_names[token] = None
    if typing_names:
        lines.append(f"from typing import {', '.join(typing_names)}")

    import_lines = []
    for module_path, names in decompiler.from_imports.items():
        if names:
            import_lines.append(f"from {module_path} import {', '.join(names)}")
    for module_path in decompiler.imports:
        if module_path not in decompiler.from_imports:
            import_lines.append(f"import {module_path}")
    if import_lines:
        lines.append('')
        lines.extend(sorted(dict.fromkeys(import_lines)))

    if decompiler.api_endpoints:
        lines.append('')
        for url in sorted(decompiler.api_endpoints):
            lines.append(f"# endpoint: {url}")

    if decompiler.vk_table:
        lines.append('')
        for name, value in decompiler.vk_table.items():
            lines.append(f"{name} = {value!r}")

    if decompiler.module_constants:
        lines.append('')
        for name, value in decompiler.module_constants.items():
            if should_render_constant(name):
                lines.append(f"{name} = {value}")

    if decompiler.functions:
        lines.append('')
        for func in decompiler.functions.values():
            lines.extend(func.render(0).rstrip().splitlines())
            lines.append('')

    for cls_node in decompiler.classes.values():
        if not cls_node.methods and not cls_node.attributes and not cls_node.docstring:
            continue
        lines.append('')
        lines.extend(cls_node.render(0).rstrip().splitlines())
        lines.append('')

    return "\n".join(lines).rstrip() + "\n"


def main():
    try:
        import nuitka_deobfuscate
    except ImportError:
        print("[-] Nuitka deobfuscate extension missing.")
        return 1

    blob_path = Path('rcdata_10_3.bin')
    if not blob_path.exists():
        print("[-] Blob not found.")
        return 1

    raw = blob_path.read_bytes()
    sections = nuitka_deobfuscate.decode_blob(raw)
    out_dir = Path('restore_deep_ultra') / 'reconstructed_source_v12_omni'
    out_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for section_name, items in sections.items():
        if not items:
            continue
        decompiler = OmniDecompiler()
        decompiler.run_pass_1_structural_mapping(items)
        decompiler.run_pass_2_ast_synthesis()
        source = generate_omni_source(decompiler, section_name)
        if 'class ' not in source and 'def ' not in source:
            continue
        safe_name = re.sub(r'[<>:"/\\|?*\x00]', '_', section_name).strip('._') or 'section'
        (out_dir / f"{safe_name}.py").write_text(source, encoding='utf-8')
        count += 1

    print(f"[*] Processed {count} files to: {out_dir}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
