"""
Vault Watcher - Monitors vault directories for changes and automatically processes files.
"""

import time
from pathlib import Path
from typing import Optional
from rich import print
import traceback
from threading import Timer
import os

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core.encryption.service import (
    EncryptionService,
    ARCHIVE_FILENAME,
    ARCHIVE_HMAC_FILENAME,
)
from core.config import Config
from core.storage.factory import get_provider
from core.vault.file_handler import encrypt_and_store_file
from core.vault.index_manager import VaultIndexManager


class VaultFileHandler(FileSystemEventHandler):
    """
    File system event handler that monitors a vault directory
    and automatically encrypts new or modified files.
    """

    def __init__(
        self,
        vault_dir: Path,
        enc_service: EncryptionService,
        provider,
        index_manager: VaultIndexManager,
        provider_name: Optional[str] = None,
    ):
        """
        Initialize the vault file handler.

        Args:
            vault_dir: Path to the vault directory to watch
            enc_service: Encryption service instance
            provider: Storage provider instance
            index_manager: Index manager instance
            provider_name: Optional name of the provider for display
        """
        self.vault_dir = vault_dir.resolve()
        self.encrypted_dir = vault_dir / "encrypted"
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)
        self.enc_service = enc_service
        self.provider = provider
        self.provider_name = provider_name
        self.index_manager = index_manager
        self.observer = None
        self.processing_files = set()
        self.batch_timer = None
        self.batch_queue = []
        self.error_files = (
            set()
        )  # Track files that had errors to avoid repeated messages

        # Define excluded paths patterns
        excluded_paths_patterns = [
            str(vault_dir / "encrypted" / "**"),
            str(vault_dir / "keys" / "**"),
            "*.enc",
            "*.hmac",
            "*.tmp",
            ".*",  # Hidden files
        ]
        self.excluded_patterns = excluded_paths_patterns

        # Build excluded paths set
        self.excluded_paths = {
            str(vault_dir / "encrypted"),
            str(vault_dir / "keys"),
            str(vault_dir / "metadata.json"),
        }

    def start(self):
        """Start the file watcher."""
        try:
            print(f"[green]Starting watcher for directory: {self.vault_dir}[/green]")
            self.observer = Observer()
            self.observer.schedule(self, str(self.vault_dir), recursive=True)
            self.observer.start()
            print("[green]Watcher started successfully[/green]")
        except Exception as e:
            print(f"[red]Error starting watcher: {e}[/red]")
            raise

    def stop(self):
        """Stop the file watcher."""
        try:
            print("[yellow]Stopping watcher...[/yellow]")
            self.observer.stop()
            self.observer.join()
            print("[green]Watcher stopped successfully[/green]")
        except Exception as e:
            print(f"[red]Error stopping watcher: {e}[/red]")
            raise

    def on_created(self, event):
        print(f"[blue]File created detected: {event.src_path}[/blue]")
        if not event.is_directory:
            self._process_file(event.src_path)

    def on_modified(self, event):
        print(f"[blue]File modified detected: {event.src_path}[/blue]")
        if not event.is_directory:
            self._process_file(event.src_path)

    def _is_excluded(self, file_path: str) -> bool:
        """
        Check if a file path should be excluded from processing.

        Args:
            file_path: Path to check

        Returns:
            bool: True if the file should be excluded
        """
        import fnmatch

        # Check if path is in excluded set
        if file_path in self.excluded_paths:
            print(f"[yellow]File excluded (excluded_paths): {file_path}[/yellow]")
            return True

        # Check if file is in encrypted directory
        if str(self.vault_dir / "encrypted") in file_path:
            print(f"[yellow]File excluded (encrypted directory): {file_path}[/yellow]")
            return True

        # Check excluded patterns
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(file_path, pattern):
                print(
                    f"[yellow]File excluded (pattern {pattern}): {file_path}[/yellow]"
                )
                return True

        # Check if path is in error_files
        if file_path in self.error_files:
            print(f"[yellow]File excluded (error_files): {file_path}[/yellow]")
            return True

        return False

    def _process_file(self, file_path: str):
        """
        Process a file for encryption.

        Args:
            file_path: Path to the file to process
        """
        try:
            print(f"[blue]Processing file: {file_path}[/blue]")

            # Skip if file is being processed
            if file_path in self.processing_files:
                print(f"[yellow]File already being processed: {file_path}[/yellow]")
                return

            # Skip if file is excluded
            if self._is_excluded(file_path):
                print(f"[yellow]File excluded from processing: {file_path}[/yellow]")
                return

            # Add to processing set
            self.processing_files.add(file_path)

            try:
                # Check if file is readable
                if not os.access(file_path, os.R_OK):
                    print(f"[red]File not readable: {file_path}[/red]")
                    self.error_files.add(file_path)
                    return

                # Encrypt the file
                print(f"[green]Encrypting file: {file_path}[/green]")
                path_obj = Path(file_path)
                rel_path = path_obj.relative_to(self.vault_dir)
                encrypted_filename = encrypt_and_store_file(
                    path_obj,
                    rel_path,
                    self.enc_service,
                    self.encrypted_dir,
                    self.provider,
                    self.index_manager,
                )

                # Update index
                if encrypted_filename:
                    print(
                        f"[green]Updating index for file: {encrypted_filename}[/green]"
                    )
                    self.index_manager.add_file(
                        encrypted_filename,
                        {
                            "original_name": str(rel_path),
                            "added": time.time(),
                            "size": path_obj.stat().st_size,
                        },
                    )
                    self.index_manager.save_index()
                    print("[green]Index updated successfully[/green]")

                print(f"[green]File encrypted successfully: {file_path}[/green]")

            except Exception as e:
                print(f"[red]Error processing file {file_path}: {e}[/red]")
                self.error_files.add(file_path)

            finally:
                # Remove from processing set
                self.processing_files.remove(file_path)

        except Exception as e:
            print(f"[red]Unexpected error in _process_file: {e}[/red]")

    def _start_batch_timer(self):
        """Start or reset the batch timer."""
        if self.batch_timer:
            self.batch_timer.cancel()

        self.batch_timer = Timer(1.0, self._process_batch)
        self.batch_timer.start()

    def _process_batch(self):
        """Process all files in the batch queue."""
        try:
            print(
                f"[blue]Starting batch processing with {len(self.batch_queue)} files[/blue]"
            )

            # Make a copy of the batch queue to avoid modification during iteration
            queue_copy = list(self.batch_queue)
            self.batch_queue.clear()

            for file_path in queue_copy:
                try:
                    # Verify file exists before processing
                    path_obj = Path(file_path)
                    if not path_obj.exists():
                        print(f"[yellow]⚠️ File no longer exists: {file_path}[/yellow]")
                        self.error_files.add(file_path)
                        continue

                    # Convert file path to relative path
                    rel_path = path_obj.relative_to(self.vault_dir)

                    print(
                        f"[green]Encrypting: {rel_path} (format: {path_obj.suffix})[/green]"
                    )

                    # Try to encrypt the file
                    success = encrypt_and_store_file(
                        path_obj,
                        rel_path,
                        self.enc_service,
                        self.encrypted_dir,
                        self.provider,
                        self.index_manager,
                    )

                    if success:
                        print(f"[green]✓ Successfully encrypted: {rel_path}[/green]")
                    else:
                        print(f"[red]❌ Failed to encrypt: {rel_path}[/red]")

                except Exception as e:
                    self.error_files.add(file_path)
                    print(f"[red]❌ Error encrypting file {file_path}:[/red] {str(e)}")
                    import traceback

                    traceback.print_exc()

            print("[blue]Batch processing completed[/blue]")
        except Exception as e:
            print(f"[red]❌ Error processing batch:[/red] {str(e)}")
            import traceback

            traceback.print_exc()
        finally:
            self.batch_timer = None


def start_vault_watcher(vault_id: str, passphrase: str):
    """
    Start watching a vault for changes and automatically encrypt new files.
    """
    try:
        # Get vault path
        vault_dir = Path(".vaultic") / vault_id
        if not vault_dir.exists():
            raise ValueError(f"Vault {vault_id} not found")

        # Initialize encryption service
        meta_path = vault_dir / "keys" / "vault-meta.json"
        if not meta_path.exists():
            raise ValueError("Vault metadata not found")
        encryption_service = EncryptionService(passphrase, meta_path)

        # Create necessary directories
        content_dir = vault_dir / "encrypted" / "content"
        hmac_dir = vault_dir / "encrypted" / "hmac"
        index_dir = vault_dir / "encrypted" / "index"
        archive_dir = vault_dir / "encrypted" / "archive"

        # Create directories if they don't exist
        content_dir.mkdir(parents=True, exist_ok=True)
        hmac_dir.mkdir(parents=True, exist_ok=True)
        index_dir.mkdir(parents=True, exist_ok=True)
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Delete old archive files if they exist
        old_archive = vault_dir / "encrypted" / "vault.enc"
        old_hmac = vault_dir / "encrypted" / "vault.enc.hmac"
        if old_archive.exists():
            old_archive.unlink()
        if old_hmac.exists():
            old_hmac.unlink()

        # Decompress files if archive exists
        archive_path = archive_dir / ARCHIVE_FILENAME
        archive_hmac_path = archive_dir / ARCHIVE_HMAC_FILENAME
        if archive_path.exists() and archive_hmac_path.exists():
            print("[blue]Decompressing existing archive...[/blue]")
            try:
                # Extract files from archive
                files = encryption_service.extract_from_archive(archive_path)

                # Save extracted files
                for filename, content in files.items():
                    file_path = content_dir / filename
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    file_path.write_bytes(content)

                    # Create HMAC file
                    hmac_path = hmac_dir / f"{filename}.hmac"
                    hmac_path.parent.mkdir(parents=True, exist_ok=True)
                    hmac_value = encryption_service.create_file_hmac(file_path)
                    hmac_path.write_bytes(hmac_value)

                # Delete archive files
                archive_path.unlink()
                archive_hmac_path.unlink()

                # Delete archive directory if empty
                if not any(archive_dir.iterdir()):
                    archive_dir.rmdir()

                print(
                    f"[green]✓ Archive decompressed successfully with {len(files)} files[/green]"
                )
            except Exception as e:
                print(f"[red]❌ Error decompressing archive:[/red] {str(e)}")
                traceback.print_exc()

        # Initialize index manager
        index_manager = VaultIndexManager(encryption_service, vault_dir)

        # Initialize storage provider
        provider = get_provider(Config.PROVIDER)

        # Initialize file handler
        file_handler = VaultFileHandler(
            vault_dir,
            encryption_service,
            provider,
            index_manager,
            provider_name=Config.PROVIDER,
        )

        # Start watching
        print("[green]✓ Watcher started[/green]")
        print("[blue]Press Ctrl+C to stop[/blue]")

        try:
            file_handler.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[yellow]🛑 Stopping watcher...[/yellow]")
            file_handler.stop()

            # Create archive of all files
            print("[blue]Creating archive...[/blue]")
            try:
                # Create necessary directories
                archive_dir.mkdir(parents=True, exist_ok=True)
                archive_path = archive_dir / ARCHIVE_FILENAME
                archive_hmac_path = archive_dir / ARCHIVE_HMAC_FILENAME

                # Get all files from content directory
                files = {}
                for file_path in content_dir.glob("**/*"):
                    if file_path.is_file():
                        rel_path = file_path.relative_to(content_dir)
                        files[str(rel_path)] = file_path.read_bytes()

                # Create encrypted archive
                if files:
                    encryption_service.create_encrypted_archive(files, archive_path)
                    print(f"[green]✓ Archive created with {len(files)} files[/green]")
                else:
                    print("[yellow]No files to archive[/yellow]")

                # Delete all files in content and hmac directories after archiving
                for file_path in content_dir.glob("**/*"):
                    if file_path.is_file():
                        try:
                            file_path.unlink()
                        except Exception as e:
                            print(
                                f"[yellow]⚠️ Could not delete file {file_path}: {str(e)}[/yellow]"
                            )

                for file_path in hmac_dir.glob("**/*"):
                    if file_path.is_file():
                        try:
                            file_path.unlink()
                        except Exception as e:
                            print(
                                f"[yellow]⚠️ Could not delete file {file_path}: {str(e)}[/yellow]"
                            )

            except Exception as e:
                print(f"[red]❌ Error creating archive: {str(e)}[/red]")
                traceback.print_exc()

            # Delete empty directories
            try:
                if content_dir.exists():
                    # Check if directory is empty
                    is_empty = True
                    for _ in content_dir.iterdir():
                        is_empty = False
                        break

                    if is_empty:
                        content_dir.rmdir()
                        print(
                            f"[green]✓ Removed empty directory: {content_dir}[/green]"
                        )
                    else:
                        print(
                            f"[yellow]⚠️ Directory not empty, cannot delete: {content_dir}[/yellow]"
                        )

                if hmac_dir.exists():
                    # Check if directory is empty
                    is_empty = True
                    for _ in hmac_dir.iterdir():
                        is_empty = False
                        break

                    if is_empty:
                        hmac_dir.rmdir()
                        print(f"[green]✓ Removed empty directory: {hmac_dir}[/green]")
                    else:
                        print(
                            f"[yellow]⚠️ Directory not empty, cannot delete: {hmac_dir}[/yellow]"
                        )

                if index_dir.exists() and not any(index_dir.iterdir()):
                    index_dir.rmdir()
                    print(f"[green]✓ Removed empty directory: {index_dir}[/green]")
            except Exception as e:
                print(f"[yellow]⚠️ Error cleaning up directories: {str(e)}[/yellow]")

            print("[green]✓ Watcher stopped[/green]")
            exit(0)  # Use Python's exit instead of typer.Exit

    except KeyboardInterrupt:
        print("\n[yellow]🛑 Stopping watcher...[/yellow]")
        print("[green]✓ Watcher stopped[/green]")
        exit(0)  # Use Python's exit instead of typer.Exit
    except Exception as e:
        print(f"[red]❌ Error starting watcher:[/red] {str(e)}")
        traceback.print_exc()
        exit(1)  # Use Python's exit instead of typer.Exit
