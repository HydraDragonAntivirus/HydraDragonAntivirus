import os
import shutil
import math
import chardet
import subprocess
import inspect
import logging
from pathlib import Path
from tqdm import tqdm

# -------------------- LOGGING --------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# -------------------- PATH SETUP --------------------
script_dir = os.path.dirname(os.path.abspath(__file__))

detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")

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
    control_chars = sum(
        (ord(c) < 32 and c not in "\n\r\t\f\b")
        for c in decoded
    )

    if control_chars / len(decoded) > max_control_ratio:
        return False

    # 4) Entropy
    if shannon_entropy(data) > max_entropy:
        return False

    return True

# -------------------- DETECT IT EASY --------------------
def analyze_file_with_die(file_path: str) -> str | None:
    try:
        result = subprocess.run(
            [detectiteasy_console_path, "-p", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        if result.stdout.strip():
            return result.stdout

        if result.stderr:
            logger.error(f"DIE stderr for {file_path}: {result.stderr}")

    except subprocess.SubprocessError as ex:
        logger.error(f"DIE subprocess error for {file_path}: {ex}")
    except Exception as ex:
        logger.error(f"DIE general error for {file_path}: {ex}")

    return None

def is_plain_text_file_from_output(die_output):
    """
    Checks if the DIE output does indicate plain text, suggesting it is plain text data.
    """
    if die_output and "Format: plain text" in die_output():
        logger.info("DIE output does not contain plain text; identified as non-plain text data.")
        return True
    return False

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

            # Second: Detect It Easy fallback
            if os.path.isfile(detectiteasy_console_path):
                die_output = analyze_file_with_die(src_path)
                if is_plain_text_file_from_output(die_output):
                    continue

            # Still not text → problematic
            shutil.copy2(src_path, dst_path)

        except Exception as ex:
            logger.error(f"Read error for {src_path}: {ex}")
            shutil.copy2(src_path, dst_path)


# -------------------- ENTRY POINT --------------------
if __name__ == "__main__":
    scan_benign_dir()
