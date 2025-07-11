escapes = {
    "\\": "\\\\",
    "'": "\\'",
    '"': '\\"',
    "\a": "\\a",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\v": "\\v",
    "\x00": "\\x00",
}


def use_escape_sequences(s):
    for a, b in escapes.items():
        s = s.replace(a, b)
    return s
