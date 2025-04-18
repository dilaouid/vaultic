from .base import StorageProvider
from pathlib import Path
import shutil


class MockLocalProvider(StorageProvider):
    """
    Mock provider that stores backups in a local ./mock_remote/ folder.
    Useful for dev/testing without touching any real cloud.
    """

    def __init__(self):
        self.remote_root = Path("./mock_remote/")
        self.remote_root.mkdir(parents=True, exist_ok=True)

    def upload_file(self, local_path: Path, remote_path: str) -> None:
        dest = self.remote_root / remote_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_path, dest)

    def download_file(self, remote_path: str, local_path: Path) -> None:
        src = self.remote_root / remote_path
        local_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, local_path)

    def list_files(self) -> list[str]:
        return [
            str(p.relative_to(self.remote_root))
            for p in self.remote_root.rglob("*")
            if p.is_file()
        ]
