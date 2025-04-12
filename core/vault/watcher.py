import time
import hashlib

from pathlib import Path
from typing import Optional, Union
import uuid
import typer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.encryption.service import EncryptionService
from core.config import Config
from core.utils import console
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
        src_path = Path(filepath).resolve()

        if not src_path.exists():
            console.print(f"[yellow]⚠ File already deleted, skipping: {src_path}[/yellow]")
            return

        if self.encrypted_dir in src_path.parents:
            console.print(f"[yellow]↪ Ignored encrypted file: {src_path}[/yellow]")
            return

        try:
            rel_path = src_path.relative_to(self.watch_dir)
        except ValueError:
            console.print(f"[yellow]⚠ Ignored file outside watch dir: {src_path}[/yellow]")
            return

        # ✅ Wait for file to be fully written
        time.sleep(0.2)  # Adjust as needed

        if src_path.stat().st_size == 0:
            console.print(f"[yellow]⚠ Skipping empty file:[/yellow] {rel_path}")
            return

        encrypted_path = self.encrypted_dir / rel_path
        encrypted_path = encrypted_path.with_suffix(encrypted_path.suffix + ".enc")
        encrypted_path.parent.mkdir(parents=True, exist_ok=True)

        console.print(f"[yellow]🔐 Encrypting:[/yellow] {rel_path}")
        self.enc_service.encrypt_file(str(src_path), str(encrypted_path))

        console.print(f"☁️  [yellow]Uploading to {Config.PROVIDER}:[/yellow] {rel_path}.enc")
        self.provider.upload_file(encrypted_path, str(rel_path) + ".enc")

        try:
            src_path.unlink()
            console.print(f"[grey]🧹 Deleted original: {rel_path}[/grey]")
        except Exception as e:
            console.print(f"[red]⚠️ Failed to delete original file: {e}[/red]")
        console.print('-------------------------------')

def ensure_meta_test_valid(enc_service: EncryptionService, encrypted_dir: Path):
    test_path = encrypted_dir / ".meta-test"

    if not test_path.exists():
        if any(encrypted_dir.rglob("*.enc")):
            console.print("[red bold]❌ .meta-test is missing and encrypted files already exist. Aborting.[/red bold]")
            raise typer.Exit(1)

        # First-time generation
        token = f"vaultic-test-{uuid.uuid4().hex[:8]}"
        test_path.write_text(token)
        enc_service.encrypt_file(str(test_path), str(test_path) + ".enc")
        test_path.unlink()
        console.print("[green]✅ .meta-test generated and encrypted.[/green]")
        return

    encrypted_test = str(test_path) + ".enc"
    if not Path(encrypted_test).exists():
        console.print("[red]❌ .meta-test.enc missing while .meta-test exists. Aborting.[/red]")
        raise typer.Exit(1)

    try:
        decrypted = enc_service.fernet.decrypt(Path(encrypted_test).read_bytes()).decode()
        if not decrypted.startswith("vaultic-test"):
            raise ValueError("Wrong prefix")
    except Exception as e:
        console.print(f"[red bold]❌ Invalid passphrase for given salt! Decryption failed: {e}[/red bold]")
        raise typer.Exit(1)

    console.print("[green]🔐 Verified passphrase matches .meta-test file.[/green]")

def start_vaultic_watcher(passphrase: str, meta_path: Optional[Union[str, Path]] = None):
    vault_dir = Path(".vaultic")
    meta_path = Path(meta_path).expanduser() if meta_path else Path(".vaultic/keys/vaultic_meta.json")
    enc_service = EncryptionService(passphrase, meta_path)

    salt = enc_service.salt
    subfolder = hashlib.sha256(salt.encode()).hexdigest()[:12]
    encrypted_dir = Path(".vaultic/encrypted") / subfolder

    ensure_meta_test_valid(enc_service, encrypted_dir)

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
