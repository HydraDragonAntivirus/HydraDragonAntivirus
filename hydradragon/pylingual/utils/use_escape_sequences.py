def use_escape_sequences(s):
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
    for a, b in escapes.items():
        s = s.replace(a, b)
    return s
