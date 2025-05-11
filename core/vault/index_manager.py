"""
Index Manager - Handles secure vault index operations (encryption, decryption, and updates).
"""

import json
import traceback

from rich import print
from pathlib import Path
from typing import Dict, Optional, List, Union, Any

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
        Encrypt and save the vault index with integrity verification.

        Args:
            force: Force save even if index hasn't been modified
        """
        if not force and not self.modified:
            return

        if self._index_cache is None:
            return

        try:
            # Convert index to JSON with sorted keys for consistent hashing
            index_data = json.dumps(self._index_cache, indent=2, sort_keys=True).encode()

            # Create parent directories if they don't exist
            self.encrypted_index_path.parent.mkdir(parents=True, exist_ok=True)

            # Create temporary files for atomic write
            temp_enc_path = self.encrypted_index_path.with_suffix('.enc.tmp')
            temp_hmac_path = self.encrypted_hmac_path.with_suffix('.hmac.tmp')

            # Encrypt and save the index
            self.enc_service.encrypt_bytes(
                index_data, temp_enc_path, temp_hmac_path
            )

            # Verify the encrypted data
            try:
                decrypted_data = self.enc_service.decrypt_bytes(
                    temp_enc_path, temp_hmac_path
                )
                if decrypted_data != index_data:
                    raise ValueError("Encryption verification failed")
            except Exception as e:
                print(f"[red]❌ Error verifying encrypted index: {e}[/red]")
                # Clean up temporary files
                temp_enc_path.unlink(missing_ok=True)
                temp_hmac_path.unlink(missing_ok=True)
                raise

            # Atomic rename of temporary files
            temp_enc_path.replace(self.encrypted_index_path)
            temp_hmac_path.replace(self.encrypted_hmac_path)

            self.modified = False
            print(f"[green]✓ Index saved and verified: {self.encrypted_index_path}[/green]")

        except Exception as e:
            print(f"[red]❌ Error saving encrypted index: {e}[/red]")
            traceback.print_exc()
            raise

    def add_file(self, rel_path: Union[Path, str], metadata: Dict[str, Any]) -> None:
        """
        Add a file to the index with its metadata.

        Args:
            rel_path: Path relative to the vault root
            metadata: File metadata including encrypted_filename, size, added timestamp, etc.
        """
        index = self.load()
        index[str(rel_path)] = metadata
        self.modified = True
        
        # Update vault metadata file count
        self._update_vault_file_count(1)

    def remove_file(self, rel_path: Union[Path, str]) -> None:
        """
        Remove a file from the index.

        Args:
            rel_path: Path relative to the vault root
        """
        index = self.load()
        path_str = str(rel_path)
        
        if path_str in index:
            del index[path_str]
            self.modified = True
            
            # Update vault metadata file count
            self._update_vault_file_count(-1)

    def get_file_info(self, rel_path: Union[Path, str]) -> Optional[Dict]:
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
                "size": info.get("size", 0),
                "added": info.get("added", 0),
                "encrypted_filename": info.get("encrypted_filename", ""),
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
        
    def _update_vault_file_count(self, delta: int) -> None:
        """
        Update the file count in the vault metadata.
        
        Args:
            delta: Change in file count (positive for additions, negative for removals)
        """
        try:
            meta_path = self.vault_dir / "keys" / "vault-meta.json"
            if meta_path.exists():
                with open(meta_path, "r") as f:
                    metadata = json.load(f)
                
                # Update file count, ensuring it doesn't go below 0
                current_count = metadata.get("file_count", 0)
                new_count = max(0, current_count + delta)
                metadata["file_count"] = new_count
                
                with open(meta_path, "w") as f:
                    json.dump(metadata, f, indent=2)
        except Exception as e:
            print(f"[yellow]⚠️ Could not update file count in metadata: {e}[/yellow]")