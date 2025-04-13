import os
from pathlib import Path

def secure_delete(path: Path, passes: int = 1) -> None:
    """
    Securely deletes a file by overwriting it with random bytes before unlinking.

    Args:
        path (Path): Path to the file to securely delete.
        passes (int): Number of overwrite passes (default: 1).
    """
    if not path.is_file():
        raise ValueError(f"Cannot secure-delete non-file path: {path}")
    
    size = path.stat().st_size
    with open(path, 'r+b') as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
    path.unlink()