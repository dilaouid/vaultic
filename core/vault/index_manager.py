"""
Index Manager - Handles secure vault index operations (encryption, decryption, and updates).
"""

import json
import time
import traceback

from rich import print
from pathlib import Path
from typing import Dict, Optional, List, Union

from core.encryption.service import (
    EncryptionService,
)


class VaultIndexManager:
    """
    Manages encrypted vault indexes, providing secure loading, updating, and saving.

    This class ensures that the index is only decrypted when needed, and is
    re-encrypted after updates are complete to minimize exposure of unencrypted data.
    """

    INDEX_FILENAME = "index.json"
    TEMP_INDEX_FILENAME = ".index_temp.json"

    def __init__(self, enc_service: EncryptionService, vault_dir: Path):
        """
        Initialize the vault index manager.

        Args:
            enc_service: The encryption service to use
            vault_dir: The vault root directory
        """
        self.enc_service = enc_service
        self.vault_dir = vault_dir
        self.encrypted_dir = self.vault_dir / "encrypted"

        # Ensure directories exist
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)
        (self.encrypted_dir / "index").mkdir(parents=True, exist_ok=True)

        # Track if index has been modified since last save
        self.modified = False

        # In-memory index cache
        self._index_cache = None

        # File paths
        self.index_path = self.encrypted_dir / "index" / self.INDEX_FILENAME
        self.encrypted_index_path = (
            self.encrypted_dir / "index" / f"{self.INDEX_FILENAME}.enc"
        )
        self.encrypted_hmac_path = (
            self.encrypted_dir / "index" / f"{self.INDEX_FILENAME}.enc.hmac"
        )
        self.temp_index_path = self.encrypted_dir / "index" / self.TEMP_INDEX_FILENAME

    def load(self) -> Dict:
        """
        Load and decrypt the vault index.

        Returns:
            Dict: The decrypted index data
        """
        if self._index_cache is not None:
            return self._index_cache

        # Try to load from encrypted index
        if self.encrypted_index_path.exists() and self.encrypted_hmac_path.exists():
            try:
                # Decrypt the index
                decrypted_data = self.enc_service.decrypt_bytes(
                    self.encrypted_index_path, self.encrypted_hmac_path
                )
                self._index_cache = json.loads(decrypted_data.decode())
                return self._index_cache
            except Exception as e:
                print(f"[red]❌ Error reading encrypted index: {e}[/red]")
                traceback.print_exc()

        # If no index found, create a new one
        self._index_cache = {}
        self.modified = True
        return self._index_cache

    def save(self, force: bool = False) -> None:
        """
        Encrypt and save the vault index.

        Args:
            force: Force save even if index hasn't been modified
        """
        if not force and not self.modified:
            return

        if self._index_cache is None:
            return

        # Convert index to JSON
        index_data = json.dumps(self._index_cache, indent=2).encode()

        # Encrypt and save the index
        try:
            # Create parent directories if they don't exist
            self.encrypted_index_path.parent.mkdir(parents=True, exist_ok=True)

            # Encrypt and save the index
            self.enc_service.encrypt_bytes(
                index_data, self.encrypted_index_path, self.encrypted_hmac_path
            )
            self.modified = False
            print(f"[green]✓ Index saved to {self.encrypted_index_path}[/green]")
        except Exception as e:
            print(f"[red]❌ Error saving encrypted index: {e}[/red]")
            traceback.print_exc()

    def add_file(self, rel_path: Path, encrypted_filename: str, size: int) -> None:
        """
        Add a file to the index.

        Args:
            rel_path: Path relative to the vault root
            encrypted_filename: Name of the encrypted file
            size: Size of the file in bytes
        """
        index = self.load()
        index[str(rel_path)] = {
            "encrypted_filename": encrypted_filename,
            "size": size,
            "added": time.time(),
        }
        self.modified = True

    def remove_file(self, rel_path: Path) -> None:
        """
        Remove a file from the index.

        Args:
            rel_path: Path relative to the vault root
        """
        index = self.load()
        if str(rel_path) in index:
            del index[str(rel_path)]
            self.modified = True

    def get_file_info(self, rel_path: Path) -> Optional[Dict]:
        """
        Get information about a file from the index.

        Args:
            rel_path: Path relative to the vault root

        Returns:
            Optional[Dict]: File information if found, None otherwise
        """
        index = self.load()
        return index.get(str(rel_path))

    def list_files(self) -> List[Dict[str, Union[str, int]]]:
        """
        List all files in the index.

        Returns:
            List[Dict[str, Union[str, int]]]: List of file information dictionaries
        """
        index = self.load()
        return [
            {
                "path": path,
                "size": info["size"],
                "added": info["added"],
            }
            for path, info in index.items()
        ]

    def clear_cache(self) -> None:
        """
        Clear the index cache from memory after ensuring it's saved.
        """
        if self.modified:
            self.save()

        self._index_cache = None
        print("[grey]Index cache cleared from memory[/grey]")

    def get_index_data(self) -> dict:
        """
        Get the current index data.

        Returns:
            dict: The current index data
        """
        if self._index_cache is None:
            self.load()
        return self._index_cache
