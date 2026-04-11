import io
import sys
from pathlib import Path

from xdis.magics import by_version, int2magic
from xdis.unmarshal import VersionIndependentUnmarshaller


def header_from_magic_int(magic_int: int) -> bytes:
    magic = int2magic(magic_int)
    flags = (0).to_bytes(4, "little")
    mtime = (0).to_bytes(4, "little")
    src_size = (0).to_bytes(4, "little")
    return magic + flags + mtime + src_size


def candidate_magic_ints(preferred_version: str | None = None) -> list[int]:
    out: list[int] = []

    if preferred_version:
        magic = by_version.get(preferred_version)
        if magic is None:
            raise RuntimeError(f"xdis has no magic for version {preferred_version}")
        if isinstance(magic, (bytes, bytearray)):
            # xdis.by_version maps version -> 4-byte magic
            # VersionIndependentUnmarshaller wants magic_int
            out.append(int.from_bytes(bytes(magic[:2]), "little"))
            return out

    # fallback: stable, recent CPython only
    for ver in ("3.13", "3.12", "3.11", "3.10", "3.9", "3.8"):
        magic = by_version.get(ver)
        if magic is not None:
            out.append(int.from_bytes(bytes(magic[:2]), "little"))

    return list(dict.fromkeys(out))


def unmarshal_with_xdis(raw: bytes, preferred_version: str | None = None):
    last_exc = None

    for magic_int in candidate_magic_ints(preferred_version):
        try:
            stream = io.BytesIO(raw)
            um = VersionIndependentUnmarshaller(stream, magic_int, bytes_for_s=True)
            obj = um.load()
            return obj, magic_int
        except Exception as e:
            last_exc = e

    raise RuntimeError(f"xdis VIU failed: {last_exc}")


def convert_one_file(src: Path, dst: Path, preferred_version: str | None = None) -> int:
    try:
        raw = src.read_bytes()
        if not raw:
            raise ValueError("empty marshal blob")

        obj, magic_int = unmarshal_with_xdis(raw, preferred_version)

        # If VIU could load it, keep original marshal payload and write real .pyc
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(header_from_magic_int(magic_int) + raw)
        print(f"[helper] {dst} magic_int={magic_int}", flush=True)
        return 0
    except Exception as e:
        print(f"[helper] failed: {src} -> {e}", file=sys.stderr, flush=True)
        return 1


def process_dir(stage_dir: Path, out_dir: Path, preferred_version: str | None = None) -> int:
    done = 0
    failed = 0

    for src in sorted(stage_dir.rglob("*.rawmarshal")):
        rel = src.relative_to(stage_dir)
        rel_str = str(rel)
        if rel_str.endswith(".rawmarshal"):
            rel_str = rel_str[:-11]
        dst = out_dir / rel_str

        rc = convert_one_file(src, dst, preferred_version)
        if rc == 0:
            done += 1
        else:
            failed += 1

    print(f"[helper] done={done} failed={failed}", flush=True)
    return 0 if failed == 0 else 1


def main() -> int:
    args = sys.argv[1:]
    preferred_version = None

    if args[:2] == ["--version", args[1] if len(args) > 1 else None]:
        preferred_version = args[1]
        args = args[2:]

    if len(args) != 2:
        print("usage: pyc_helper.py [--version 3.12] <input-file-or-dir> <output-file-or-dir>", file=sys.stderr)
        return 2

    src = Path(args[0])
    dst = Path(args[1])

    if src.is_dir():
        return process_dir(src, dst, preferred_version)

    return convert_one_file(src, dst, preferred_version)


if __name__ == "__main__":
    raise SystemExit(main())
