import json
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def hash_file(path: Path) -> str:
    """
    Compute the SHA256 hash of a file.

    Args:
        path (Path): Path to the file.

    Returns:
        str: SHA256 hash as hex string.
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.finalize().hex()


def generate_index(source_dir: Path, encrypted_dir: Path) -> Dict:
    """
    Walks through the source_dir and generates an index of all files with metadata.

    Args:
        source_dir (Path): The directory to index (original files).
        encrypted_dir (Path): The directory where encrypted files are stored.

    Returns:
        dict: The full index of all files.
    """
    source_dir = source_dir.resolve()
    encrypted_dir = encrypted_dir.resolve()
    index = {"root": str(source_dir), "files": []}

    for file_path in source_dir.rglob("*"):
        if file_path.is_file():
            relative_path = file_path.relative_to(source_dir)
            encrypted_path = encrypted_dir / (str(relative_path) + ".enc")

            index["files"].append(
                {
                    "relative_path": str(relative_path),
                    "encrypted_path": str(encrypted_path),
                    "size": file_path.stat().st_size,
                    "hash": hash_file(file_path),
                }
            )

    return index


def save_index(index: Dict, index_path: Path) -> None:
    """
    Save the index to a JSON file.

    Args:
        index (dict): The index dictionary to save.
        index_path (Path): Path to the output index file.
    """
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.open("w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)


def load_index(index_path: Path) -> Dict:
    """
    Load an index JSON file.

    Args:
        index_path (Path): Path to the index file.

    Returns:
        dict: Loaded index.
    """
    with index_path.open("r", encoding="utf-8") as f:
        return json.load(f)
