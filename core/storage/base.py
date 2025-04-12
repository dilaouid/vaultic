from abc import ABC, abstractmethod
from pathlib import Path

class StorageProvider(ABC):
    """
    Abstract base class for a cloud storage provider.
    """

    @abstractmethod
    def upload_file(self, local_path: Path, remote_path: str) -> None:
        """
        Upload a file to the cloud.

        Args:
            local_path (Path): Path to the encrypted file on disk.
            remote_path (str): Path in the cloud (e.g. backups/filename.enc).
        """
        pass

    @abstractmethod
    def download_file(self, remote_path: str, local_path: Path) -> None:
        """
        Download a file from the cloud.

        Args:
            remote_path (str): Path in the cloud.
            local_path (Path): Destination path on disk.
        """
        pass

    @abstractmethod
    def list_files(self) -> list[str]:
        """
        List all files in the remote backup storage.

        Returns:
            list[str]: List of remote file paths.
        """
        pass
