from pathlib import Path

SEARCH_TEXT = "HomekoWorld"
FOLDER_PATH = r"pylingual_bundle"  # change this


def search_in_folder(folder_path: str, search_text: str) -> None:
    folder = Path(folder_path)

    if not folder.exists():
        print(f"Folder does not exist: {folder}")
        return

    if not folder.is_dir():
        print(f"Not a folder: {folder}")
        return

    found_any = False

    for file_path in folder.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, start=1):
                    if search_text in line:
                        found_any = True
                        print(f"Found in: {file_path}")
                        print(f"  Line {line_number}: {line.strip()}")
        except Exception as e:
            print(f"Could not read {file_path}: {e}")

    if not found_any:
        print(f'"{search_text}" not found in any file under {folder}')


if __name__ == "__main__":
    search_in_folder(FOLDER_PATH, SEARCH_TEXT)