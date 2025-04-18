"""
Index Manager - Handles secure vault index operations (encryption, decryption, and updates).
"""

import json
import time
import os
import traceback

from rich import print
from pathlib import Path
from typing import Dict, Optional, List, Union

from core.encryption.service import EncryptionService


class VaultIndexManager:
    """
    Manages encrypted vault indexes, providing secure loading, updating, and saving.

    This class ensures that the index is only decrypted when needed, and is
    re-encrypted after updates are complete to minimize exposure of unencrypted data.
    """

    INDEX_FILENAME = "index.json.enc"
    INDEX_HMAC_FILENAME = "index.json.enc.hmac"
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

        # The encrypted directory is under the vault_dir
        self.encrypted_dir = self.vault_dir / "encrypted"
        self.content_dir = self.encrypted_dir / "content"
        self.hmac_dir = self.encrypted_dir / "hmac"

        # Ensure directories exist
        self.content_dir.mkdir(parents=True, exist_ok=True)
        self.hmac_dir.mkdir(parents=True, exist_ok=True)

        # Track if index has been modified since last save
        self.modified = False

        # In-memory index cache
        self._index_cache = None

        # File paths
        self.enc_index_path = self.content_dir / self.INDEX_FILENAME
        self.enc_hmac_path = self.hmac_dir / self.INDEX_HMAC_FILENAME
        self.temp_index_path = self.encrypted_dir / self.TEMP_INDEX_FILENAME

        # Legacy index path - we'll check it during migration but won't update it
        self.legacy_index_path = self.encrypted_dir / "index.json"

        # Delete any existing legacy index - we're removing it completely
        if self.legacy_index_path.exists():
            try:
                self.legacy_index_path.unlink()
                print("[green]✅ Removed legacy unencrypted index file[/green]")
            except Exception as e:
                print(f"[yellow]⚠️ Warning: Could not delete legacy index: {e}[/yellow]")

        # Check integrity of index and HMAC
        self._check_index_integrity()

    def _check_index_integrity(self):
        """
        Check if index exists but HMAC is missing, and fix if possible.
        """
        if self.enc_index_path.exists() and not self.enc_hmac_path.exists():
            print(
                "[yellow]⚠️ Index file exists but HMAC is missing. Trying to recover...[/yellow]"
            )

            # If HMAC is missing but index exists, we'll need to recreate the index
            try:
                # First, try to create an empty HMAC file to see if it's a permissions issue
                with open(self.enc_hmac_path, "wb") as f:
                    f.write(b"test")

                # If we got here, we can write to the HMAC directory
                # Delete the test file
                self.enc_hmac_path.unlink()

                # We'll recreate the index with a forced save
                self._index_cache = {}
                self.modified = True
                print("[blue]Will recreate index file on next save()[/blue]")

            except Exception as e:
                print(f"[red]❌ Cannot write to HMAC directory: {e}[/red]")
                print(f"[red]Please check permissions on {self.hmac_dir}[/red]")

    def load(self) -> Dict:
        """
        Load and decrypt the index if it exists, otherwise create a new one.

        Returns:
            Dict: The decrypted index
        """
        # Check if we already have the index in memory
        if self._index_cache is not None:
            return self._index_cache

        # For debugging
        if self.enc_index_path.exists():
            print(
                f"[blue]Index file exists: {self.enc_index_path.stat().st_size} bytes[/blue]"
            )
        else:
            print("[yellow]Index file does not exist[/yellow]")

        if self.enc_hmac_path.exists():
            print(
                f"[blue]HMAC file exists: {self.enc_hmac_path.stat().st_size} bytes[/blue]"
            )
        else:
            print("[yellow]HMAC file does not exist[/yellow]")

        # Check if encrypted index exists and is valid
        if self.enc_index_path.exists() and self.enc_hmac_path.exists():
            # Only try to decrypt if both index and HMAC exist
            try:
                # Decrypt to temporary file
                self.enc_service.decrypt_file(
                    str(self.enc_index_path), str(self.temp_index_path)
                )

                # Load JSON from temp file
                with open(self.temp_index_path, "r", encoding="utf-8") as f:
                    self._index_cache = json.load(f)
                    print(
                        f"[green]Successfully loaded encrypted index with {len(self._index_cache)} entries[/green]"
                    )

                # Clean up temp file
                if self.temp_index_path.exists():
                    self.temp_index_path.unlink()

                # Check for legacy index for one-time migration
                if self.legacy_index_path.exists():
                    try:
                        with open(self.legacy_index_path, "r", encoding="utf-8") as f:
                            legacy_data = json.load(f)

                        # Import any missing entries from legacy index
                        added = 0
                        for path, info in legacy_data.items():
                            if path not in self._index_cache:
                                self._index_cache[path] = info
                                added += 1
                                self.modified = True

                        if added > 0:
                            print(
                                f"[blue]Imported {added} entries from legacy index[/blue]"
                            )
                            # Delete legacy index after migration
                            self.legacy_index_path.unlink()
                            print(
                                "[green]✅ Legacy index deleted after migration[/green]"
                            )
                    except Exception as e:
                        print(
                            f"[yellow]Warning: Failed to import from legacy index: {e}[/yellow]"
                        )

                return self._index_cache

            except Exception as e:
                print(f"[red]Error decrypting index: {e}[/red]")
                print(f"[red]Traceback: {traceback.format_exc()}[/red]")

                # Clean up temp file
                if self.temp_index_path.exists():
                    self.temp_index_path.unlink()

                # If the error is about missing HMAC, but HMAC file exists,
                # there might be a file corruption or synchronization issue
                if "Missing HMAC" in str(e) and self.enc_hmac_path.exists():
                    print(
                        "[yellow]HMAC verification failed. The index or HMAC file may be corrupted.[/yellow]"
                    )

                    # Try to fix by forcing recreation of both files
                    print(
                        "[yellow]Attempting to fix by removing corrupted files...[/yellow]"
                    )
                    try:
                        if self.enc_index_path.exists():
                            self.enc_index_path.unlink()
                        if self.enc_hmac_path.exists():
                            self.enc_hmac_path.unlink()
                        print(
                            "[green]Removed corrupted index files. Will create new ones.[/green]"
                        )
                    except Exception as cleanup_error:
                        print(
                            f"[red]Failed to clean up corrupted files: {cleanup_error}[/red]"
                        )

        # Try legacy index file for one-time migration
        if self.legacy_index_path.exists():
            try:
                with open(self.legacy_index_path, "r", encoding="utf-8") as f:
                    self._index_cache = json.load(f)
                print(
                    f"[yellow]Using legacy unencrypted index with {len(self._index_cache)} entries[/yellow]"
                )
                self.modified = True  # Mark as modified so it will be encrypted

                # Delete legacy index after importing
                self.legacy_index_path.unlink()
                print("[green]✅ Legacy index deleted after import[/green]")

                return self._index_cache
            except Exception as e:
                print(f"[red]Error loading legacy index: {e}[/red]")

        # Create new empty index
        print("[yellow]Creating new empty index[/yellow]")
        self._index_cache = {}
        self.modified = True
        return self._index_cache

    def add_file(
        self, rel_path: Union[str, Path], hashed_name: str, file_size: int
    ) -> None:
        """
        Add or update a file in the index.

        Args:
            rel_path: Relative path of the file within the vault
            hashed_name: Hash-based encrypted filename
            file_size: Size of the original file in bytes
        """
        # Ensure index is loaded
        index = self.load()

        # Convert Path to string if necessary
        if isinstance(rel_path, Path):
            rel_path = str(rel_path)

        # Update index with file information
        index[rel_path] = {
            "hash": hashed_name,
            "size": file_size,
            "timestamp": time.time(),
        }

        self.modified = True
        print(f"[green]Added/updated file in index: {rel_path}[/green]")

    def remove_file(self, rel_path: Union[str, Path]) -> bool:
        """
        Remove a file from the index.

        Args:
            rel_path: Relative path of the file to remove

        Returns:
            bool: True if file was found and removed
        """
        # Ensure index is loaded
        index = self.load()

        # Convert Path to string if necessary
        if isinstance(rel_path, Path):
            rel_path = str(rel_path)

        # Remove file if it exists
        if rel_path in index:
            del index[rel_path]
            self.modified = True
            print(f"[yellow]Removed file from index: {rel_path}[/yellow]")
            return True

        return False

    def get_file_info(self, rel_path: Union[str, Path]) -> Optional[Dict]:
        """
        Get information about a file from the index.

        Args:
            rel_path: Relative path of the file

        Returns:
            Optional[Dict]: File metadata or None if not found
        """
        # Ensure index is loaded
        index = self.load()

        # Convert Path to string if necessary
        if isinstance(rel_path, Path):
            rel_path = str(rel_path)

        return index.get(rel_path)

    def list_files(self) -> List[str]:
        """
        List all files in the index.

        Returns:
            List[str]: List of file paths in the index
        """
        # Ensure index is loaded
        index = self.load()
        return list(index.keys())

    def save(self, force: bool = False) -> bool:
        """
        Encrypt and save the index if it has been modified.

        Args:
            force: Force saving even if not modified

        Returns:
            bool: True if index was saved
        """
        if not (self.modified or force):
            print("[grey]Index not modified, skipping save[/grey]")
            return False

        if self._index_cache is None:
            print("[yellow]No index loaded, nothing to save[/yellow]")
            return False

        # Remove any existing temporary file
        if self.temp_index_path.exists():
            try:
                self.temp_index_path.unlink()
            except Exception as e:
                print(
                    f"[yellow]Warning: Could not delete existing temporary file: {e}[/yellow]"
                )

        try:
            print(
                f"[blue]Saving encrypted index with {len(self._index_cache)} entries...[/blue]"
            )

            # Remove legacy index if it exists - we don't want it anymore
            if self.legacy_index_path.exists():
                try:
                    self.legacy_index_path.unlink()
                    print("[green]✅ Removed legacy unencrypted index file[/green]")
                except Exception as e:
                    print(
                        f"[yellow]⚠️ Warning: Could not delete legacy index: {e}[/yellow]"
                    )

            # Step 1: Write index to temporary file
            with open(self.temp_index_path, "w", encoding="utf-8") as f:
                json.dump(self._index_cache, f, indent=2)
                # Ensure data is flushed to disk
                f.flush()
                os.fsync(f.fileno())

            # Ensure the temp file exists and has content before continuing
            if not self.temp_index_path.exists():
                print("[red]Error: Temporary index file not created[/red]")
                return False

            if self.temp_index_path.stat().st_size == 0:
                print("[red]Error: Temporary index file is empty[/red]")
                return False

            print(
                f"[blue]Encrypting index ({self.temp_index_path.stat().st_size} bytes)...[/blue]"
            )

            # Step 2: Make sure old files are deleted before encryption
            # This helps prevent issues where the HMAC file might be missing
            if self.enc_index_path.exists():
                try:
                    self.enc_index_path.unlink()
                    print("[blue]Removed old index file before encryption[/blue]")
                except Exception as e:
                    print(
                        f"[yellow]Warning: Could not delete old index file: {e}[/yellow]"
                    )

            if self.enc_hmac_path.exists():
                try:
                    self.enc_hmac_path.unlink()
                    print("[blue]Removed old HMAC file before encryption[/blue]")
                except Exception as e:
                    print(
                        f"[yellow]Warning: Could not delete old HMAC file: {e}[/yellow]"
                    )

            # Step 3: Encrypt the temporary file
            self.enc_service.encrypt_file(
                str(self.temp_index_path),
                str(self.enc_index_path),
                str(self.enc_hmac_path),
            )

            # Step 4: Verify both files were created
            if not self.enc_index_path.exists():
                print("[red]Error: Encrypted index file was not created[/red]")
                return False

            if not self.enc_hmac_path.exists():
                print("[red]Error: HMAC file was not created[/red]")
                return False

            print(
                f"[green]Encrypted index saved ({self.enc_index_path.stat().st_size} bytes)[/green]"
            )
            print(
                f"[green]HMAC file saved ({self.enc_hmac_path.stat().st_size} bytes)[/green]"
            )

            # Clean up temp file
            if self.temp_index_path.exists():
                try:
                    self.temp_index_path.unlink()
                except Exception as e:
                    print(
                        f"[yellow]Warning: Could not delete temporary file: {e}[/yellow]"
                    )

            self.modified = False
            return True

        except Exception as e:
            print(f"[red]Error saving encrypted index: {e}[/red]")
            print(f"[red]Traceback: {traceback.format_exc()}[/red]")
            return False

    def clear_cache(self) -> None:
        """
        Clear the index cache from memory after ensuring it's saved.
        """
        if self.modified:
            self.save()

        self._index_cache = None
        print("[grey]Index cache cleared from memory[/grey]")
