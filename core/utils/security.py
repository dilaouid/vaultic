"""
Security Utilities - Functions related to secure file operations.
"""

import os
import platform

from rich import print
from pathlib import Path


def is_rotational(path: Path) -> bool:
    """
    Determine if a file is on a rotational (HDD) or solid-state (SSD) drive.

    This is important for secure deletion, as HDDs require multiple overwrites,
    while SSDs use wear leveling and can't be securely erased at the file level.

    Args:
        path: Path to check

    Returns:
        bool: True if the file is likely on a rotational drive
    """
    # On Linux, we can check directly
    if platform.system() == "Linux":
        try:
            # Get the mount point for the file
            device = os.stat(path).st_dev
            dev_path = os.path.realpath(
                f"/sys/dev/block/{os.major(device)}:{os.minor(device)}"
            )

            # Check if it's rotational
            rotational_path = os.path.join(dev_path, "queue/rotational")
            if os.path.exists(rotational_path):
                with open(rotational_path, "r") as f:
                    return f.read().strip() == "1"
        except Exception:
            pass

    # On macOS, we can check if it's an SSD via diskutil
    elif platform.system() == "Darwin":
        try:
            mount_point = _get_mount_point(path)
            import subprocess

            output = subprocess.check_output(["diskutil", "info", mount_point]).decode()
            return "Solid State: No" in output
        except Exception:
            pass

    # On Windows, we could check if it's an SSD, but it's complicated
    # For now, we assume rotational to be safe
    return True


def _get_mount_point(path: Path) -> str:
    """
    Get the mount point for a path.

    Args:
        path: Path to check

    Returns:
        str: Mount point path
    """
    path = path.resolve()

    # Start with the path and walk upwards until we find a different device
    while path != path.parent:
        parent_path = path.parent
        if os.stat(path).st_dev != os.stat(parent_path).st_dev:
            return str(path)
        path = parent_path

    return str(path)


def secure_delete(path: Path, passes: int = 3) -> None:
    """
    Securely delete a file by overwriting it multiple times before unlinking.
    Includes error handling and final verification.

    Args:
        path: Path to the file to delete
        passes: Number of overwrite passes (default: 3 for HDD, 1 for SSD)
    """
    if not path.exists():
        return

    try:
        # Get file size
        file_size = path.stat().st_size

        # Skip secure deletion for very large files (performance)
        # or zero-byte files (no data to overwrite)
        if file_size == 0 or file_size > 100 * 1024 * 1024:  # 100 MB
            path.unlink()
            return

        # Adjust number of passes based on drive type
        if not is_rotational(path):
            passes = 1  # Single pass for SSD
            print(f"[blue]Using single pass for SSD: {path}[/blue]")
        else:
            print(f"[blue]Using {passes} passes for HDD: {path}[/blue]")

        # Overwrite with random data
        with open(path, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                # Write random bytes
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

        # Verify the file is still accessible before deletion
        try:
            with open(path, "rb") as f:
                f.read(1)  # Try to read one byte
        except Exception as e:
            print(f"[red]Error verifying file before deletion: {e}[/red]")
            return

        # Delete the file
        path.unlink()

        # Verify deletion
        if path.exists():
            raise Exception("File still exists after deletion")

    except Exception as e:
        print(f"[red]Error during secure deletion: {e}[/red]")
        raise
