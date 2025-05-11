"""
Vault Watcher - Monitors vault directories for changes and automatically processes files.
"""

import time
from pathlib import Path
from typing import Optional, Literal
from rich import print
import traceback
from threading import Timer, Lock
import os
import shutil
import configparser

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from core.encryption.service import (
    EncryptionService,
    ARCHIVE_FILENAME,
    ARCHIVE_HMAC_FILENAME,
)
from core.config import Config
from core.storage.factory import get_provider
from core.vault.file_handler import encrypt_and_store_file, OVERWRITE, RENAME, SKIP
from core.vault.index_manager import VaultIndexManager

DuplicateAction = Literal["overwrite", "rename", "skip", "ask"]

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
        duplicate_action: DuplicateAction = "ask",
    ):
        """
        Initialize the vault file handler.

        Args:
            vault_dir: Path to the vault directory to watch
            enc_service: Encryption service instance
            provider: Storage provider instance
            index_manager: Index manager instance
            provider_name: Optional name of the provider for display
            duplicate_action: How to handle duplicate files (overwrite, rename, skip, ask)
        """
        self.vault_dir = vault_dir.resolve()
        self.encrypted_dir = vault_dir / "encrypted"
        self.keys_dir = vault_dir / "keys"
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.enc_service = enc_service
        self.provider = provider
        self.provider_name = provider_name
        self.index_manager = index_manager
        self.observer = None
        self.duplicate_action = duplicate_action
        
        # Load user preferences if available
        config_path = vault_dir / "config.ini"
        if config_path.exists():
            self._load_config(config_path)
        
        # Event debouncing
        self.processing_files = set()
        self.processed_files = set()
        self.pending_events = {}
        self.event_lock = Lock()
        self.debounce_timer = None
        self.debounce_time = 0.5  # seconds to wait before processing events
        
        # Error tracking
        self.error_files = set()
        
        # Critical directories that must be protected
        self.critical_dirs = [
            str(self.encrypted_dir),
            str(self.keys_dir),
        ]
        
        # Patterns for files that should never be encrypted
        self.excluded_patterns = [
            "*.enc", "*.hmac", "*.tmp", 
            ".meta-test", "index.json*", 
            "config.ini", "vault-meta.json"
        ]

    def _load_config(self, config_path: Path) -> None:
        """
        Load user configuration from config file.
        
        Args:
            config_path: Path to the configuration file
        """
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            
            if 'Preferences' in config:
                if 'duplicate_action' in config['Preferences']:
                    action = config['Preferences']['duplicate_action'].lower()
                    if action in (OVERWRITE, RENAME, SKIP, "ask"):
                        self.duplicate_action = action
                        print(f"[blue]Using configured duplicate file handling: {action}[/blue]")
                    
                if 'debounce_time' in config['Preferences']:
                    try:
                        time_value = float(config['Preferences']['debounce_time'])
                        if 0.1 <= time_value <= 5.0:  # Reasonable limits
                            self.debounce_time = time_value
                    except ValueError:
                        pass
        except Exception as e:
            print(f"[yellow]⚠️ Error loading configuration: {e}[/yellow]")

    def _save_config(self) -> None:
        """Save current configuration to file."""
        try:
            config_path = self.vault_dir / "config.ini"
            config = configparser.ConfigParser()
            
            # Create Preferences section if it doesn't exist
            if not config.has_section('Preferences'):
                config.add_section('Preferences')
                
            config['Preferences']['duplicate_action'] = self.duplicate_action
            config['Preferences']['debounce_time'] = str(self.debounce_time)
            
            with open(config_path, 'w') as f:
                config.write(f)
                
            print(f"[green]✓ Configuration saved to {config_path}[/green]")
        except Exception as e:
            print(f"[yellow]⚠️ Error saving configuration: {e}[/yellow]")

    def start(self):
        """Start the file watcher."""
        try:
            print(f"[green]Starting watcher for directory: {self.vault_dir}[/green]")
            
            # Display current duplicate handling mode
            print(f"[blue]Duplicate file handling: {self.duplicate_action}[/blue]")
            
            # Ask if user wants to change duplicate handling mode
            if self.duplicate_action == "ask":
                from questionary import confirm, select
                
                should_change = confirm(
                    "Do you want to set a default action for duplicate files? (This will apply to all files)",
                    default=False
                ).ask()
                
                if should_change:
                    try:
                        action = select(
                            "Select default action for duplicate files:",
                            choices=[
                                {"name": "Always ask (prompt for each duplicate)", "value": "ask"},
                                {"name": "Always rename (create a new version)", "value": RENAME},
                                {"name": "Always overwrite (replace existing files)", "value": OVERWRITE},
                                {"name": "Always skip (ignore duplicate files)", "value": SKIP},
                            ]
                        ).ask()
                        
                        if action:
                            self.duplicate_action = action
                            self._save_config()
                            print(f"[green]✓ Default duplicate action set to: {action}[/green]")
                    except Exception as e:
                        print(f"[yellow]⚠️ Error setting duplicate action: {e}[/yellow]")
                        print("[blue]Continuing with default setting (ask for each file)[/blue]")
            
            # Process existing files
            self._process_existing_files()
            
            # Start watchdog observer
            self.observer = Observer()
            self.observer.schedule(self, str(self.vault_dir), recursive=True)
            self.observer.start()
            print("[green]Watcher started successfully[/green]")
        except Exception as e:
            print(f"[red]Error starting watcher: {e}[/red]")
            raise

    def _process_existing_files(self):
        """Process any existing unencrypted files in the vault directory."""
        try:
            print("[blue]Checking for existing files...[/blue]")
            count = 0
            
            # Get all files in the vault directory
            for file_path in self.vault_dir.glob("**/*"):
                if not file_path.is_file():
                    continue
                    
                # Skip if file is in a protected directory
                if self._is_protected_path(str(file_path)):
                    continue
                    
                # Process the file
                self._process_file(str(file_path))
                count += 1
                
            if count > 0:
                print(f"[green]Processed {count} existing files[/green]")
            else:
                print("[blue]No unencrypted files found in vault[/blue]")
                
        except Exception as e:
            print(f"[yellow]⚠️ Error processing existing files: {e}[/yellow]")

    def stop(self):
        """Stop the file watcher."""
        try:
            print("[yellow]Stopping watcher...[/yellow]")
            if self.debounce_timer:
                self.debounce_timer.cancel()
            self.observer.stop()
            self.observer.join()
            print("[green]Watcher stopped successfully[/green]")
        except Exception as e:
            print(f"[red]Error stopping watcher: {e}[/red]")
            raise
            
    def _is_protected_path(self, path: str) -> bool:
        """
        Check if a path is protected and should never be encrypted/deleted.
        
        Args:
            path: File path to check
            
        Returns:
            bool: True if path is protected
        """
        path_obj = Path(path)
        
        # First check if it's in a protected directory
        for critical_dir in self.critical_dirs:
            if path.startswith(critical_dir):
                return True
        
        # Check if the parent directory is 'keys'
        if path_obj.parent.name == "keys":
            return True
            
        # Check critical filenames regardless of location
        if path_obj.name == "vault-meta.json" or path_obj.name == ".meta-test":
            return True
            
        # Check excluded patterns
        import fnmatch
        for pattern in self.excluded_patterns:
            if fnmatch.fnmatch(path_obj.name, pattern):
                return True
                
        return False

    def _should_process_event(self, event: FileSystemEvent) -> bool:
        """
        Determine if an event should be processed.
        
        Args:
            event: The file system event
            
        Returns:
            bool: True if the event should be processed
        """
        if event.is_directory:
            return False
            
        path = event.src_path
        
        # Check if path is protected
        if self._is_protected_path(path):
            if Path(path).name == "vault-meta.json":
                # Extra visibility for this critical file - never process vault-meta.json
                print(f"[blue]Skipping critical file: {Path(path).name}[/blue]")
            return False
                
        # Check if already processed or had errors
        if path in self.processed_files or path in self.error_files:
            return False
            
        # Skip if file doesn't exist (might have been deleted)
        if not Path(path).exists():
            return False
            
        return True

    def on_created(self, event):
        """Handle file creation events."""
        self._handle_event(event)
        
    def on_modified(self, event):
        """Handle file modification events."""
        self._handle_event(event)
        
    def _handle_event(self, event):
        """Common event handling logic."""
        if not self._should_process_event(event):
            return
            
        with self.event_lock:
            # Store the event with a timestamp
            self.pending_events[event.src_path] = (time.time(), event)
            
            # Reset the debounce timer
            if self.debounce_timer:
                self.debounce_timer.cancel()
                
            self.debounce_timer = Timer(self.debounce_time, self._process_pending_events)
            self.debounce_timer.daemon = True
            self.debounce_timer.start()

    def _process_pending_events(self):
        """Process all pending events after debounce time has elapsed."""
        with self.event_lock:
            if not self.pending_events:
                return
                
            current_time = time.time()
            files_to_process = []
            
            # Filter events that have waited for at least debounce_time
            for path, (timestamp, event) in list(self.pending_events.items()):
                if current_time - timestamp >= self.debounce_time:
                    # Double check that the file isn't protected
                    if not self._is_protected_path(path) and path not in self.processing_files:
                        files_to_process.append(path)
                    del self.pending_events[path]
            
            # Process each file
            for path in files_to_process:
                self._process_file(path)
                
            # If there are still pending events, schedule another check
            if self.pending_events:
                self.debounce_timer = Timer(self.debounce_time, self._process_pending_events)
                self.debounce_timer.daemon = True
                self.debounce_timer.start()

    def _process_file(self, file_path: str):
        """
        Process a file for encryption.

        Args:
            file_path: Path to the file to process
        """
        try:
            # Skip if file is being processed
            if file_path in self.processing_files:
                return

            # Skip if file is protected (double-check)
            if self._is_protected_path(file_path):
                print(f"[blue]Skipping protected file: {Path(file_path).name}[/blue]")
                return

            # Track that we're processing this file
            self.processing_files.add(file_path)

            try:
                path_obj = Path(file_path)
                
                # Check if file still exists and is readable
                if not path_obj.exists() or not os.access(file_path, os.R_OK):
                    print(f"[yellow]File not accessible: {file_path}[/yellow]")
                    self.error_files.add(file_path)
                    return

                # Process file
                print(f"[blue]Processing file: {path_obj.name}[/blue]")
                rel_path = path_obj.relative_to(self.vault_dir)
                
                # Get duplicate action based on configuration
                duplicate_action = self.duplicate_action
                if duplicate_action == "ask":
                    duplicate_action = None  # Will prompt user
                
                # Encrypt the file
                result = encrypt_and_store_file(
                    path_obj,
                    rel_path,
                    self.enc_service,
                    self.encrypted_dir,
                    self.provider,
                    self.index_manager,
                    duplicate_action=duplicate_action
                )
                
                if result:
                    # Mark as processed to avoid reprocessing
                    self.processed_files.add(file_path)
                    
                    # Keep processed_files from growing too large
                    if len(self.processed_files) > 1000:
                        self.processed_files.clear()
                else:
                    print(f"[red]Failed to process file: {path_obj.name}[/red]")
                    self.error_files.add(file_path)

            except Exception as e:
                print(f"[red]Error processing file {Path(file_path).name}: {str(e)}[/red]")
                self.error_files.add(file_path)

            finally:
                # Remove from processing set
                if file_path in self.processing_files:
                    self.processing_files.remove(file_path)

        except Exception as e:
            print(f"[red]Unexpected error in _process_file: {e}[/red]")
            # Clean up processing state in case of error
            if file_path in self.processing_files:
                self.processing_files.remove(file_path)

def handle_corrupted_archive(archive_path: Path, archive_hmac_path: Path):
    """
    Safely handle corrupted archives by moving them to a backup location.
    
    Args:
        archive_path: Path to the corrupted archive
        archive_hmac_path: Path to the archive HMAC file
    """
    try:
        # Create a backup directory
        backup_dir = archive_path.parent / "corrupted_archives"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate timestamp for unique backup filenames
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        
        # Move archive and HMAC to backup
        if archive_path.exists():
            backup_archive = backup_dir / f"{archive_path.name}.{timestamp}.bak"
            shutil.move(str(archive_path), str(backup_archive))
            print(f"[yellow]⚠️ Corrupted archive moved to: {backup_archive}[/yellow]")
        
        if archive_hmac_path.exists():
            backup_hmac = backup_dir / f"{archive_hmac_path.name}.{timestamp}.bak"
            shutil.move(str(archive_hmac_path), str(backup_hmac))
            print(f"[yellow]⚠️ Corrupted HMAC moved to: {backup_hmac}[/yellow]")
            
        print("[blue]Archives have been backed up and can be manually recovered if needed.[/blue]")
        return True
        
    except Exception as e:
        print(f"[red]❌ Error handling corrupted archive: {e}[/red]")
        traceback.print_exc()
        return False

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
            
        # Try to initialize encryption service to verify passphrase
        try:
            encryption_service = EncryptionService(passphrase, meta_path)
            encryption_service.verify_passphrase()
        except Exception as e:
            print(f"[red]❌ Invalid passphrase or corrupted vault: {e}[/red]")
            exit(1)

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

                print(f"[green]✓ Archive decompressed successfully with {len(files)} files[/green]")
            except Exception as e:
                print(f"[red]❌ Error decompressing archive: {e}[/red]")
                
                # Ask user what to do
                from questionary import confirm
                
                try:
                    should_backup = confirm(
                        "Would you like to backup the corrupted archive and continue?",
                        default=True
                    ).ask()
                    
                    if should_backup:
                        if handle_corrupted_archive(archive_path, archive_hmac_path):
                            print("[yellow]Continuing without decompressing the archive...[/yellow]")
                        else:
                            print("[red]❌ Unable to handle the corrupted archive.[/red]")
                            print("[yellow]You can manually move or delete these files:[/yellow]")
                            print(f"  - {archive_path}")
                            print(f"  - {archive_hmac_path}")
                            
                            should_continue = confirm(
                                "Would you like to continue anyway?",
                                default=False
                            ).ask()
                            
                            if not should_continue:
                                print("[yellow]Exiting at user request.[/yellow]")
                                exit(1)
                    else:
                        print("[yellow]Exiting at user request.[/yellow]")
                        exit(1)
                except Exception as e:
                    print(f"[yellow]⚠️ Error in interactive prompt: {e}. Continuing without decompressing.[/yellow]")

        # Initialize index manager
        index_manager = VaultIndexManager(encryption_service, vault_dir)

        # Initialize storage provider
        provider = get_provider(Config.PROVIDER)

        # Determine default duplicate action from config
        config_path = vault_dir / "config.ini"
        duplicate_action: DuplicateAction = "ask"  # Default
        
        if config_path.exists():
            try:
                config = configparser.ConfigParser()
                config.read(config_path)
                
                if 'Preferences' in config and 'duplicate_action' in config['Preferences']:
                    action = config['Preferences']['duplicate_action'].lower()
                    if action in (OVERWRITE, RENAME, SKIP, "ask"):
                        duplicate_action = action
            except Exception:
                pass

        # Initialize file handler
        file_handler = VaultFileHandler(
            vault_dir,
            encryption_service,
            provider,
            index_manager,
            provider_name=Config.PROVIDER,
            duplicate_action=duplicate_action
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
                            print(f"[yellow]⚠️ Could not delete file {file_path}: {str(e)}[/yellow]")
                            
                for file_path in hmac_dir.glob("**/*"):
                    if file_path.is_file():
                        try:
                            file_path.unlink()
                        except Exception as e:
                            print(f"[yellow]⚠️ Could not delete file {file_path}: {str(e)}[/yellow]")
                
            except Exception as e:
                print(f"[red]❌ Error creating archive: {str(e)}[/red]")
                traceback.print_exc()
            
            # Clean up empty directories
            try:
                for dir_path in [content_dir, hmac_dir, index_dir]:
                    if dir_path.exists() and not any(dir_path.iterdir()):
                        dir_path.rmdir()
                        print(f"[green]✓ Removed empty directory: {dir_path}[/green]")
            except Exception as e:
                print(f"[yellow]⚠️ Error cleaning up directories: {str(e)}[/yellow]")
            
            print("[green]✓ Watcher stopped[/green]")
            exit(0)

    except KeyboardInterrupt:
        print("\n[yellow]🛑 Stopping watcher...[/yellow]")
        print("[green]✓ Watcher stopped[/green]")
        exit(0)
    except Exception as e:
        print(f"[red]❌ Error starting watcher:[/red] {str(e)}")
        traceback.print_exc()
        exit(1)