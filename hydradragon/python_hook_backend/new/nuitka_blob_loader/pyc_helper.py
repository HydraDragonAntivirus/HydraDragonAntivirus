import importlib.util
import marshal
import os
import sys


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: pyc_helper.py <input.rawmarshal> <output.pyc>\n")
        return 2

    in_path, out_path = sys.argv[1], sys.argv[2]

    try:
        with open(in_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        sys.stderr.write(f"pyc_helper: read failed: {e}\n")
        return 1

    if not raw:
        sys.stderr.write("pyc_helper: no marshal bytes\n")
        return 1

    try:
        obj = marshal.loads(raw)
    except Exception as e:
        sys.stderr.write(f"pyc_helper: marshal.loads failed: {e}\n")
        return 1

    try:
        remarshal = marshal.dumps(obj)
    except Exception as e:
        sys.stderr.write(f"pyc_helper: marshal.dumps failed: {e}\n")
        return 1

    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)

    header = importlib.util.MAGIC_NUMBER + (0).to_bytes(4, "little") + (0).to_bytes(4, "little") + (0).to_bytes(4, "little")

    try:
        with open(out_path, "wb") as f:
            f.write(header)
            f.write(remarshal)
    except OSError as e:
        sys.stderr.write(f"pyc_helper: write failed: {e}\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
