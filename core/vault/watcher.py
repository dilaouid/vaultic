import time
import hashlib

from pathlib import Path
from typing import Optional, Union

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.encryption.service import EncryptionService
from core.config import Config
from core.utils import console
from core.utils.dos import can_process_file, register_file_processed, throttle

from core.vault.file_handler import handle_file

from core.storage.factory import get_provider

class VaulticWatcher(FileSystemEventHandler):
    """
        VaulticWatcher monitors the .vaultic/ directory for new or modified files.
        When a file is added, it is encrypted, moved, and indexed in real-time.
        Internal Vaultic files (e.g., /encrypted, /keys, or index.json) are ignored.
    """
    def __init__(self, watch_dir: Path, encrypted_dir: Path, enc_service: EncryptionService):
        self.watch_dir = watch_dir.resolve()
        self.encrypted_dir = encrypted_dir.resolve()
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)

        self.enc_service = enc_service
        self.provider = get_provider(Config.PROVIDER)

    def on_created(self, event):
        if event.is_directory:
            return
        self._encrypt_and_upload(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._encrypt_and_upload(event.src_path)

    def _encrypt_and_upload(self, filepath):
        """
            Encrypts a given file and uploads it to the configured storage provider.
            Handles deduplication, throttling, HMAC generation, secure deletion, and index update.
        """
        if not can_process_file():
            console.print("[yellow]⏱ Too many files, throttling…[/yellow]")
            return
        
        index_path = self.encrypted_dir.parent / "index.json"
        if Path(filepath).resolve() == index_path.resolve():
            console.print(f"[grey]🔁 Skipping Vaultic internal index.json[/grey]")
            return

        register_file_processed()
        throttle()

        src_path = Path(filepath).resolve()

        if not src_path.exists():
            console.print(f"[yellow]⚠ File already deleted, skipping: {src_path}[/yellow]")
            return

        if self.encrypted_dir in src_path.parents:
            # 🛑 Total exclusion of everything inside .vaultic/encrypted/*
            return

        rel_path = src_path.relative_to(self.watch_dir)
        handle_file(src_path, rel_path, self.enc_service, self.encrypted_dir, self.provider)


def start_vaultic_watcher(passphrase: str, meta_path: Optional[Union[str, Path]] = None):
    vault_dir = Path(".vaultic")
    meta_path = Path(meta_path).expanduser() if meta_path else Path(".vaultic/keys/vaultic_meta.json")

    enc_service = EncryptionService(passphrase, meta_path)
    enc_service.verify_passphrase()

    salt = enc_service.salt
    subfolder = hashlib.sha256(salt.encode()).hexdigest()[:12]
    encrypted_dir = Path(".vaultic/encrypted") / subfolder

    # Ensure encrypted_dir exists before writing lock
    (encrypted_dir).mkdir(parents=True, exist_ok=True)

    # Create lock files
    (vault_dir / ".vaultic.lock").write_text(
        "🔒 Managed by Vaultic. Do not modify manually.\n"
        "Here, you can paste / write multiple files, and it will go in the appropriate encrypted folder.\n"
        "Do not paste anything inside /keys or /encrypted.\n\n"
        "--------\n\nFiles placed here will be auto-deleted and encrypted",
        encoding="UTF-8"
    )

    (encrypted_dir / ".vaultic.lock").write_text(
        "🔒 This encrypted area is managed by Vaultic.",
        encoding="UTF-8"
    )

    console.print(f"👀  [blue]Watching: {vault_dir.resolve()} for changes…[/blue]")
    event_handler = VaulticWatcher(vault_dir, encrypted_dir, enc_service)

    observer = Observer()
    observer.schedule(event_handler, str(vault_dir), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
