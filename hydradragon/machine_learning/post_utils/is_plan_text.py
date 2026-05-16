import os
import shutil
import math
import chardet
import subprocess
import logging
from tqdm import tqdm

# -------------------- LOGGING --------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# -------------------- PATH SETUP --------------------
script_dir = os.path.dirname(os.path.abspath(__file__))


# -------------------- TEXT HEURISTICS --------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    size = len(data)
    for c in freq:
        if c:
            p = c / size
            entropy -= p * math.log2(p)

    return entropy


def is_plain_text(
    data: bytes,
    null_byte_threshold: float = 0.01,
    max_control_ratio: float = 0.05,
    max_entropy: float = 7.9,
) -> bool:
    if not data:
        return True

    # 1) Null bytes
    if data.count(0) / len(data) > null_byte_threshold:
        return False

    # 2) Decode attempt
    guess = chardet.detect(data)
    enc = guess.get("encoding")

    decoded = None
    if enc:
        try:
            decoded = data.decode(enc)
        except Exception:
            pass

    if decoded is None:
        decoded = data.decode("latin-1")

    # 3) Control characters (excluding whitespace)
    control_chars = sum((ord(c) < 32 and c not in "\n\r\t\f\b") for c in decoded)

    if control_chars / len(decoded) > max_control_ratio:
        return False

    # 4) Entropy
    if shannon_entropy(data) > max_entropy:
        return False

    return True



# -------------------- MAIN SCAN --------------------
def scan_benign_dir(
    benign_dir: str = "data2",
    problematic_dir: str = "problematic_files",
):
    benign_dir = os.path.abspath(benign_dir)
    problematic_dir = os.path.abspath(problematic_dir)

    os.makedirs(problematic_dir, exist_ok=True)

    # Collect files
    files = []
    for root, _, names in os.walk(benign_dir):
        for name in names:
            files.append(os.path.join(root, name))

    for src_path in tqdm(files, desc="Scanning files", unit="file"):
        rel_path = os.path.relpath(src_path, benign_dir)
        dst_path = os.path.join(problematic_dir, rel_path)
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)

        try:
            with open(src_path, "rb") as f:
                data = f.read()

            # First: heuristic
            if is_plain_text(data):
                continue

            # Still not text → problematic
            shutil.copy2(src_path, dst_path)

        except Exception as ex:
            logger.error(f"Read error for {src_path}: {ex}")
            shutil.copy2(src_path, dst_path)


# -------------------- ENTRY POINT --------------------
if __name__ == "__main__":
    scan_benign_dir()
