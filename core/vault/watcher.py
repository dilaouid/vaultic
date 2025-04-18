"""
Vault Watcher - Monitors vault directories for changes and automatically processes files.
"""

import time
from pathlib import Path
from typing import Set
from rich import print

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

from core.encryption.service import EncryptionService
from core.config import Config
from core.utils.dos import can_process_file, register_file_processed, throttle
from core.storage.factory import get_provider
from core.vault.file_handler import encrypt_and_store_file
from core.vault.manager import select_vault
from core.vault.index_manager import VaultIndexManager


class VaultFileHandler(FileSystemEventHandler):
    """
    File system event handler that monitors a vault directory
    and automatically encrypts new or modified files.
    """

    def __init__(
        self, vault_dir: Path, encrypted_dir: Path, enc_service: EncryptionService
    ):
        """
        Initialize the vault file handler.

        Args:
            vault_dir: Path to the vault directory to watch
            encrypted_dir: Path to the directory where encrypted files are stored
            enc_service: Encryption service instance
        """
        self.vault_dir = vault_dir.resolve()
        self.encrypted_dir = encrypted_dir.resolve()
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)
        self.enc_service = enc_service
        self.provider = get_provider(Config.PROVIDER)

        # Create index manager - pass the vault directory, not its parent
        self.index_manager = VaultIndexManager(enc_service, self.vault_dir)

        # Load index to ensure it's initialized
        self.index_manager.load()

        # Flag to track if we're in a batch operation
        self.batch_mode = False
        self.batch_timer = None
        self.BATCH_TIMEOUT = 5  # seconds after last file before saving index
        self.last_file_processed = 0

        # Paths to exclude from monitoring
        self.excluded_paths: Set[str] = {
            str(encrypted_dir),
            str(vault_dir / "keys"),
        }

        # Common temporary files to ignore
        self.excluded_files: Set[str] = {
            ".DS_Store",
            "thumbs.db",
            "desktop.ini",
            ".gitkeep",
            ".vaultic.lock",
            ".meta-test",
            "README.md",
        }

        # List of files containing "index.json" that should be ignored
        # Since these are managed by the VaultIndexManager
        self.index_file_patterns = [
            "index.json",
            "index.json.enc",
            "index.json.enc.hmac",
            ".index_temp.json",
        ]

        # Set of files currently being processed
        self.processing: Set[str] = set()

    def dispatch(self, event):
        """
        Filter events before dispatching to specific handlers.
        """
        # Only process file creation and modification events
        if not isinstance(event, (FileCreatedEvent, FileModifiedEvent)):
            return

        # Ignore directory events
        if event.is_directory:
            return

        path = Path(event.src_path).resolve()
        path_str = str(path)

        # Ignore index files - these are managed separately
        if any(pattern in path.name for pattern in self.index_file_patterns):
            return

        # Ignore files in excluded directories
        for excluded in self.excluded_paths:
            if excluded in path_str:
                return

        # Ignore common temporary/system files
        if path.name in self.excluded_files:
            return

        # Ignore files already being processed
        if path_str in self.processing:
            return

        # Start batch mode if not already started
        self._start_batch()

        # Dispatch the event to the specific handler
        super().dispatch(event)

    def on_created(self, event):
        self._process_file(event.src_path)

    def on_modified(self, event):
        self._process_file(event.src_path)

    def _start_batch(self):
        """
        Enter batch mode to delay index encryption until processing is complete.
        """
        if not self.batch_mode:
            self.batch_mode = True
            print("[blue]🔄 Starting batch processing...[/blue]")

        # Reset the batch timer to delay index saving
        self._reset_batch_timer()

    def _reset_batch_timer(self):
        """
        Reset the timer that determines when to end batch mode.
        """
        self.batch_timer = time.time() + self.BATCH_TIMEOUT

    def _check_batch_end(self):
        """
        Check if it's time to end batch mode and save the index.
        """
        if not self.batch_mode or not self.batch_timer:
            return

        # If we've been idle for a while, end the batch
        if (
            time.time() > self.batch_timer
            and time.time() - self.last_file_processed > 2
        ):
            self._end_batch()

    def _end_batch(self):
        """
        End batch mode and save the encrypted index.
        """
        if not self.batch_mode:
            return

        print("[blue]🔄 Batch processing complete, saving encrypted index...[/blue]")
        self.batch_mode = False
        self.batch_timer = None

        # Encrypt and save the index
        saved = self.index_manager.save(force=True)
        if saved:
            print("[green]✅ Encrypted index saved.[/green]")
        else:
            print("[yellow]⚠️ No changes to index or save failed.[/yellow]")

    def _process_file(self, filepath: str):
        """
        Process a newly created or modified file.
        """
        # Resolve the file path
        path = Path(filepath).resolve()
        path_str = str(path)

        # Skip index files - these should be managed only by VaultIndexManager
        if any(pattern in path.name for pattern in self.index_file_patterns):
            return

        # Additional checks for reserved files
        forbidden_names = {".meta-test", ".vaultic.lock", ".index_temp.json"}
        if path.name in forbidden_names and path.parent == self.vault_dir:
            print(f"[grey]🚫 Ignored reserved Vaultic file: {path.name}[/grey]")
            return

        # Additional checks
        if path_str in self.processing:
            return

        # Double-check excluded paths
        if any(excluded in path_str for excluded in self.excluded_paths):
            return

        try:
            # Check if file still exists
            if not path.exists():
                print(f"[yellow]⚠ File no longer exists: {path}[/yellow]")
                return

            # Mark file as being processed
            self.processing.add(path_str)

            # Check rate limits
            if not can_process_file():
                print("[yellow]⏱ Rate limit reached, throttling…[/yellow]")
                return

            # Register file processing and apply throttle
            register_file_processed()
            throttle()

            # Calculate relative path
            try:
                rel_path = path.relative_to(self.vault_dir)
            except ValueError:
                print(f"[red]❌ File is outside vault directory: {path}[/red]")
                return

            # Reset batch timer since we're processing a file
            self._reset_batch_timer()
            self.last_file_processed = time.time()

            # Process the file using the index manager
            encrypt_and_store_file(
                path,
                rel_path,
                self.enc_service,
                self.encrypted_dir,
                self.provider,
                self.index_manager,
            )

        except Exception as e:
            print(f"[red]❌ Error processing file {path}: {str(e)}[/red]")
        finally:
            # Always remove the file from the processing set
            self.processing.discard(path_str)

            # Check if batch has timed out
            self._check_batch_end()


def start_vault_watcher(vault_id, passphrase, meta_path=None):
    """
    Start watching a vault directory for changes and encrypt files automatically.

    Args:
        vault_id: Optional ID of the vault to watch
        passphrase: Optional passphrase for the vault
        meta_path: Optional direct path to the vault metadata file
    """
    print(f"Starting watcher for vault: {vault_id}")
    if meta_path:
        print(f"Using provided metadata path: {meta_path}")

    # Select vault if not specified
    if meta_path is None:
        selected_vault_id, selected_meta_path = select_vault(vault_id)
        meta_path = selected_meta_path
        vault_id = selected_vault_id
    else:
        # Extract vault_id from meta_path parent directory if not provided
        if vault_id is None:
            vault_id = meta_path.parent.parent.name

    # Base paths
    vault_dir = Path(".vaultic") / vault_id
    encrypted_dir = vault_dir / "encrypted"

    print("[blue]Setting up vault with paths:[/blue]")
    print(f"[blue]  vault_dir: {vault_dir.resolve()}[/blue]")
    print(f"[blue]  encrypted_dir: {encrypted_dir.resolve()}[/blue]")

    # Initialize encryption service
    enc_service = EncryptionService(passphrase, meta_path)

    # Verify passphrase
    try:
        enc_service.verify_passphrase()
    except ValueError as e:
        print(f"[red]❌ {str(e)}[/red]")
        return

    # Create necessary directories
    encrypted_dir.mkdir(parents=True, exist_ok=True)

    # Create lock files for user guidance
    (vault_dir / ".vaultic.lock").write_text(
        "🔒 Managed by Vaultic. Do not modify manually.\n"
        f"Files placed in this directory (vault: {vault_id}) will be encrypted automatically.\n"
        "Do not place anything in /keys or /encrypted directories.",
        encoding="UTF-8",
    )

    # Initialize and ensure index is encrypted
    index_manager = VaultIndexManager(enc_service, vault_dir)

    # Load the index and ensure it's saved in encrypted form
    index_manager.load()
    index_manager.save(force=True)
    print("[green]✅ Initialized encrypted index.[/green]")

    # Set up and start the file watcher
    print(f"[blue]👀 Watching vault:[/blue] {vault_id}")
    print(f"[blue]📁 Path:[/blue] {vault_dir.resolve()}")

    # Create and configure the event handler
    event_handler = VaultFileHandler(vault_dir, encrypted_dir, enc_service)

    # Create and start the observer
    observer = Observer()
    observer.schedule(event_handler, str(vault_dir), recursive=True)
    observer.start()

    try:
        print("[green]✅ Watcher started. Press Ctrl+C to stop.[/green]")
        while True:
            time.sleep(1)

            # Periodically check if batch mode should end
            event_handler._check_batch_end()

    except KeyboardInterrupt:
        print("[yellow]🛑 Stopping watcher...[/yellow]")
        observer.stop()

        # Ensure index is saved when stopping
        if event_handler.batch_mode:
            event_handler._end_batch()

    observer.join()
    print("[green]✓ Watcher stopped.[/green]")
