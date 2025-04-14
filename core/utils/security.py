import os
from pathlib import Path

def secure_delete(path: Path, passes: int = 1) -> None:
    """
    Securely deletes a file by overwriting it with random bytes before unlinking.
    However, in SSD it's a different problem (wear leveling), only works properly for HDD

    Args:
        path (Path): Path to the file to securely delete.
        passes (int): Number of overwrite passes (default: 1).
    """
    size = path.stat().st_size
    with open(path, 'r+b') as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    path.unlink()

def is_rotational(path: Path) -> bool:
    try:
        device = os.path.realpath(path).split('/')[2]
        with open(f"/sys/block/{device}/queue/rotational") as f:
            return f.read().strip() == "1"
    except Exception:
        return False