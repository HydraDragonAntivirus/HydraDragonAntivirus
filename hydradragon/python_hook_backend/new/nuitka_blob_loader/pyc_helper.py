import sys
import marshal
import subprocess
from pathlib import Path

def convert_one_bytes(raw: bytes, raw_mode: bool) -> bytes:
    if not raw:
        raise ValueError("empty input")
    if raw_mode:
        return raw
    return marshal.dumps(marshal.loads(raw))

def convert_one_file(src: Path, dst: Path, raw_mode: bool) -> int:
    try:
        raw = src.read_bytes()
        out = convert_one_bytes(raw, raw_mode)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(out)
        print(f"[helper] {dst}")
        return 0
    except Exception as e:
        print(f"[helper] failed: {src} -> {e}", file=sys.stderr)
        return 1

def process_dir(stage_dir: Path, out_dir: Path) -> int:
    py = sys.executable
    me = Path(__file__).resolve()
    done = 0
    failed = 0

    for src in stage_dir.rglob("*.rawmarshal"):
        rel = src.relative_to(stage_dir)
        rel_str = str(rel)
        if rel_str.endswith(".rawmarshal"):
            rel_str = rel_str[:-11]
        dst = out_dir / rel_str

        rc = subprocess.run([py, str(me), "one", str(src), str(dst)]).returncode
        if rc != 0:
            print(f"[helper] retry raw: {src}", file=sys.stderr)
            rc = subprocess.run([py, str(me), "one", "--raw", str(src), str(dst)]).returncode

        if rc == 0:
            done += 1
        else:
            failed += 1

    print(f"[helper] done={done} failed={failed}")
    return 0 if failed == 0 else 1

def main() -> int:
    args = sys.argv[1:]

    if args and args[0] == "one":
        args = args[1:]
        raw_mode = False
        if args and args[0] == "--raw":
            raw_mode = True
            args = args[1:]
        if len(args) != 2:
            print("usage: pyc_helper.py one [--raw] <input-file> <output-file>", file=sys.stderr)
            return 2
        return convert_one_file(Path(args[0]), Path(args[1]), raw_mode)

    raw_mode = False
    if args and args[0] == "--raw":
        raw_mode = True
        args = args[1:]

    if len(args) != 2:
        print("usage: pyc_helper.py [--raw] <input-file-or-dir> <output-file-or-dir>", file=sys.stderr)
        return 2

    src = Path(args[0])
    dst = Path(args[1])

    if src.is_dir():
        if raw_mode:
            print("[helper] --raw is only valid for single-file mode", file=sys.stderr)
            return 2
        return process_dir(src, dst)

    return convert_one_file(src, dst, raw_mode)

if __name__ == "__main__":
    raise SystemExit(main())
