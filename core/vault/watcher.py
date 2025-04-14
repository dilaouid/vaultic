import json
import time
import hashlib

from pathlib import Path
from typing import Optional, Union

import typer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.encryption.service import EncryptionService
from core.config import Config
from core.utils import console
from core.utils.dos import can_process_file, register_file_processed, throttle, register_error
from core.utils.security import secure_delete, is_rotational
from core.storage.factory import get_provider

class VaulticWatcher(FileSystemEventHandler):
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

        try:
            rel_path = src_path.relative_to(self.watch_dir)
            hashed_name = hashlib.sha256(str(rel_path).encode()).hexdigest() + ".enc"
            content_dir = self.encrypted_dir / "content"
            hmac_dir = self.encrypted_dir / "hmac"

            content_dir.mkdir(parents=True, exist_ok=True)
            hmac_dir.mkdir(parents=True, exist_ok=True)

            encrypted_path = content_dir / hashed_name
            hmac_path = hmac_dir / (hashed_name + ".hmac")
        except ValueError:
            console.print(f"[yellow]⚠ Ignored file outside watch dir: {src_path}[/yellow]")
            return

        # Wait a bit to ensure the file is fully written (or in this case, not deleted yet)
        time.sleep(0.2)

        # Abort if file was deleted between events
        if not src_path.exists():
            console.print(f"[yellow]⚠ File no longer exists: {src_path}[/yellow]")
            return

        if src_path.stat().st_size == 0:
            console.print(f"[yellow]⚠ Skipping empty file:[/yellow] {rel_path}")
            return

        MAX_FILE_SIZE_MB = Config.VAULTIC_MAX_FILE_MB
        if src_path.stat().st_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            console.print(f"[red]🚫 Skipped too large:[/red] {src_path.name}")
            return

        encrypted_path.parent.mkdir(parents=True, exist_ok=True)

        console.print(f"[yellow]🔐 Encrypting:[/yellow] {rel_path}")
        if encrypted_path.exists():
            if Config.OVERWRITE_EXISTING == "no":
                console.print(f"[yellow]↪ Already encrypted: {hashed_name}, skipping.[/yellow]")
                return
            elif Config.OVERWRITE_EXISTING == "ask":
                confirm = typer.confirm(f"❓ Overwrite '{hashed_name}'?", default=False)
                if not confirm:
                    console.print(f"[blue]⏩ Skipped:[/blue] {rel_path}")
                    return
            # If "yes" or confirmed
            console.print(f"[red]⚠ Overwriting existing:[/red] {hashed_name}")

        file_size = src_path.stat().st_size
        self.enc_service.encrypt_file(str(src_path), str(encrypted_path), str(hmac_path))

        console.print(f"☁️  [yellow]Uploading to {Config.PROVIDER}:[/yellow] {rel_path}.enc")
        self.provider.upload_file(encrypted_path, str(rel_path) + ".enc")

        try:
            if is_rotational(src_path):
                secure_delete(src_path, passes=3)
            else:
                src_path.unlink()
            console.print(f"[grey]🧹 Deleted original: {rel_path}[/grey]")
        except Exception as e:
            console.print(f"[red]⚠️ Failed to delete original file: {e}[/red]")
            register_error()
        console.print('-------------------------------')
        index_data = {}

        if index_path.exists():
            index_data = json.loads(index_path.read_text())

        # Save or update entry
        index_data[str(rel_path)] = {
            "hash": hashed_name,
            "size": file_size,
            "timestamp": time.time()
        }

        index_path.write_text(json.dumps(index_data, indent=2))


def start_vaultic_watcher(passphrase: str, meta_path: Optional[Union[str, Path]] = None):
    vault_dir = Path(".vaultic")
    meta_path = Path(meta_path).expanduser() if meta_path else Path(".vaultic/keys/vaultic_meta.json")

    enc_service = EncryptionService(passphrase, meta_path)
    enc_service.verify_passphrase()

    salt = enc_service.salt
    subfolder = hashlib.sha256(salt.encode()).hexdigest()[:12]
    encrypted_dir = Path(".vaultic/encrypted") / subfolder
    (vault_dir / ".vaultic.lock").write_text("🔒 Managed by Vaultic. Do not modify manually.\nHere, you can paste / write multiple files, and it will go in the appropriate encrypted folder.\nDo not paste anything inside /keys or /encrypted.\n\n--------\n\nFiles placed here will be auto-deleted and encrypted", encoding="UTF-8")
    (encrypted_dir / ".vaultic.lock").write_text("🔒 This encrypted area is managed by Vaultic.", encoding="UTF-8")

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
